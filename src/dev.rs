//! `rdev dev` — the one-command development loop for a ceapp.
//!
//! `rdev dev [dir]` reads the app's `ceapp.toml` and runs the whole edit loop with zero setup:
//! watch the sources -> rebuild -> restart the app -> stream its output, seconds per iteration.
//! `rdev dev --via <target>` runs the SAME loop with the heavy lifting on a remote node: the tree
//! is content-addressed-synced over the mesh, the build+run happen on the target host, and the
//! logs stream back live — the local machine never compiles.
//!
//! The manifest is the single source of truth (apps building on apps): with no config at all a
//! Rust ceapp gets `cargo build --bin <native.bin>` + run-with-`[daemon].args`. An optional
//! rdev-owned `[dev]` section overrides any part of it (ce-appmgr ignores unknown sections, so a
//! manifest with `[dev]` still installs everywhere):
//!
//! ```toml
//! [dev]
//! build       = "cargo build --bin myapp"   # custom build (sh -c). Requires `run` too.
//! run         = "./target/debug/myapp -v"   # custom run (sh -c)
//! args        = ["serve", "--dev"]          # args for the DEFAULT run (else [daemon].args)
//! web         = "npm run dev"               # optional frontend dev process (sh -c)
//! web_dir     = "web"                       # where to run it (default: web/ if it exists)
//! env         = { RUST_LOG = "debug" }      # extra env for the app process
//! debounce_ms = 400                         # rebuild debounce window
//! ```
//!
//! Loop semantics (both modes): a failing build never kills the running app — the previous
//! process keeps serving until a build succeeds; then the old process group is terminated and the
//! new build takes over. Ctrl-C tears everything down (including the remote job in --via mode).

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ce_rs::CeClient;
use notify::{RecursiveMode, Watcher};
use serde::Deserialize;

use rdev::walk;

use crate::{Config, Req, Resp, RunLogsResp, SyncdOpts, remote_root_of, resolve, syncd};
use rdev::conflict::Policy;

// ----- manifest -> plan -----

/// The rdev-owned `[dev]` section of `ceapp.toml`. Every field optional; ce-appmgr ignores the
/// whole section (no `deny_unknown_fields` in its manifest parser), so adding it never breaks
/// `ce app install`.
#[derive(Deserialize, Default, Debug, Clone)]
pub struct DevSection {
    #[serde(default)]
    pub build: Option<String>,
    #[serde(default)]
    pub run: Option<String>,
    #[serde(default)]
    pub args: Option<Vec<String>>,
    #[serde(default)]
    pub web: Option<String>,
    #[serde(default)]
    pub web_dir: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub debounce_ms: Option<u64>,
}

/// The slices of `ceapp.toml` the dev loop needs (tolerant: unknown sections/fields ignored).
#[derive(Deserialize, Default)]
struct ManifestLite {
    #[serde(default)]
    app: AppLite,
    #[serde(default)]
    native: Option<NativeLite>,
    #[serde(default)]
    daemon: Option<DaemonLite>,
    #[serde(default)]
    build: Option<BuildLite>,
    #[serde(default)]
    dev: DevSection,
}
#[derive(Deserialize, Default)]
struct AppLite {
    #[serde(default)]
    name: String,
}
#[derive(Deserialize, Default)]
struct NativeLite {
    #[serde(default)]
    bin: Option<String>,
}
#[derive(Deserialize, Default)]
struct DaemonLite {
    #[serde(default)]
    args: Vec<String>,
}
/// `[build] features = [...]` — the same section `ce-publish`/`tools/ce-app-publish` honor.
#[derive(Deserialize, Default)]
struct BuildLite {
    #[serde(default)]
    features: Vec<String>,
}

/// Everything the loop needs, derived once from the manifest + flags. Pure (unit-tested).
#[derive(Debug, Clone)]
pub struct DevPlan {
    pub name: String,
    /// `[native].bin` — required unless a custom `[dev].build`+`run` pair is given.
    pub bin: Option<String>,
    /// Custom build command (`sh -c`). `None` = the default cargo build.
    pub build: Option<String>,
    /// `[build].features` for the default cargo build.
    pub features: Vec<String>,
    /// Custom run command (`sh -c`). `None` = run the built executable with `args`.
    pub run: Option<String>,
    /// Args for the default run: `[dev].args`, else `[daemon].args`.
    pub args: Vec<String>,
    /// Optional frontend dev process: (command, directory).
    pub web: Option<(String, PathBuf)>,
    pub env: BTreeMap<String, String>,
    pub debounce_ms: u64,
    pub release: bool,
}

/// Derive the dev plan from a manifest string. `dir` only anchors defaults (name, web_dir).
pub fn plan(dir: &Path, manifest: &str, release: bool, no_web: bool) -> Result<DevPlan> {
    let m: ManifestLite = toml::from_str(manifest).context("parsing ceapp.toml")?;
    let name = if m.app.name.is_empty() {
        dir.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "app".into())
    } else {
        m.app.name.clone()
    };
    let bin = m.native.as_ref().and_then(|n| n.bin.clone());
    let dev = m.dev.clone();

    if dev.build.is_some() && dev.run.is_none() {
        bail!("[dev].build is custom but [dev].run is not set — rdev cannot guess what to launch");
    }
    if dev.build.is_none() && dev.run.is_none() && bin.is_none() {
        bail!("manifest has no [native].bin and no [dev] build/run — nothing to build or launch");
    }

    let args = dev
        .args
        .clone()
        .or_else(|| m.daemon.as_ref().map(|d| d.args.clone()))
        .unwrap_or_default();

    let web = if no_web {
        None
    } else {
        dev.web.clone().map(|cmd| {
            let wd = dev.web_dir.clone().unwrap_or_else(|| "web".into());
            (cmd, dir.join(wd))
        })
    };

    Ok(DevPlan {
        name,
        bin,
        build: dev.build.clone(),
        features: m.build.map(|b| b.features).unwrap_or_default(),
        run: dev.run.clone(),
        args,
        web,
        env: dev.env.clone(),
        debounce_ms: dev.debounce_ms.unwrap_or(500),
        release,
    })
}

/// The default cargo build invocation for the plan (used locally with JSON output, and remotely
/// as a plain shell command).
pub fn default_build_cmd(plan: &DevPlan) -> String {
    let bin = plan.bin.as_deref().unwrap_or_default();
    let mut cmd = format!("cargo build --bin {bin}");
    if plan.release {
        cmd.push_str(" --release");
    }
    if !plan.features.is_empty() {
        cmd.push_str(&format!(" --features {}", plan.features.join(",")));
    }
    cmd
}

/// The remote (`--via`) one-shot shell: build, then exec the app so the job IS the app process.
pub fn via_shell(plan: &DevPlan) -> String {
    let build = plan.build.clone().unwrap_or_else(|| default_build_cmd(plan));
    let run = plan.run.clone().unwrap_or_else(|| {
        let profile = if plan.release { "release" } else { "debug" };
        let bin = plan.bin.as_deref().unwrap_or_default();
        let mut r = format!("./target/{profile}/{bin}");
        for a in &plan.args {
            r.push(' ');
            r.push_str(&shell_quote(a));
        }
        r
    });
    let mut env = String::new();
    for (k, v) in &plan.env {
        env.push_str(&format!("export {k}={}; ", shell_quote(v)));
    }
    // `source cargo env` covers hosts where cargo is only on login shells' PATH.
    format!("source \"$HOME/.cargo/env\" 2>/dev/null || true; {env}{build} && exec {run}")
}

fn shell_quote(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

// ----- entry -----

/// `rdev dev`: read the manifest, derive the plan, and run the local or `--via` loop.
pub async fn dev(
    client: &CeClient,
    cfg: &Config,
    dir: &Path,
    via: Option<String>,
    cap: Option<String>,
    release: bool,
    no_web: bool,
) -> Result<()> {
    let dir = dir.canonicalize().with_context(|| format!("no such directory: {}", dir.display()))?;
    let mpath = dir.join("ceapp.toml");
    let raw = std::fs::read_to_string(&mpath)
        .with_context(|| format!("{} — `rdev dev` runs in a ceapp directory", mpath.display()))?;
    let plan = plan(&dir, &raw, release, no_web)?;
    match via {
        Some(target) => dev_via(client, cfg, &plan, &dir, &target, cap).await,
        None => dev_local(&plan, &dir).await,
    }
}

// ----- local loop -----

async fn dev_local(plan: &DevPlan, dir: &Path) -> Result<()> {
    println!("dev {}  (watch -> rebuild -> restart; Ctrl-C to stop)", plan.name);

    let mut web_child = match &plan.web {
        Some((cmd, wd)) => Some(spawn_shell(cmd, wd, &plan.env).context("starting [dev].web")?),
        None => None,
    };

    let mut app_child: Option<Child> = None;
    match build_local(plan, dir) {
        Ok(exe) => match spawn_app(plan, dir, exe.as_deref()) {
            Ok(c) => app_child = Some(c),
            Err(e) => eprintln!("dev: launch failed: {e}"),
        },
        Err(e) => eprintln!("dev: initial build failed: {e}\ndev: watching — fix and save to retry"),
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<notify::Event>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            let _ = tx.send(ev);
        }
    })?;
    watcher.watch(dir, RecursiveMode::Recursive)?;

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        let first = tokio::select! {
            ev = rx.recv() => match ev { Some(e) => e, None => break },
            _ = tick.tick() => {
                if let Some(c) = app_child.as_mut()
                    && let Ok(Some(status)) = c.try_wait() {
                    eprintln!("dev: app exited ({status}) — will relaunch on the next change");
                    app_child = None;
                }
                continue;
            }
            _ = tokio::signal::ctrl_c() => break,
        };
        let mut changed: HashSet<PathBuf> = first.paths.into_iter().collect();
        while let Ok(Some(ev)) =
            tokio::time::timeout(Duration::from_millis(plan.debounce_ms), rx.recv()).await
        {
            changed.extend(ev.paths);
        }
        if !any_relevant(dir, &changed) {
            continue;
        }
        println!("dev: change detected — rebuilding");
        match build_local(plan, dir) {
            Ok(exe) => {
                if let Some(c) = app_child.as_mut() {
                    kill_child(c);
                }
                match spawn_app(plan, dir, exe.as_deref()) {
                    Ok(c) => {
                        println!("dev: restarted {}", plan.name);
                        app_child = Some(c);
                    }
                    Err(e) => eprintln!("dev: launch failed: {e}"),
                }
            }
            // The old process (if any) keeps running: a broken edit never takes the app down.
            Err(e) => eprintln!("dev: build failed: {e}"),
        }
    }

    println!("\ndev: stopping");
    if let Some(c) = app_child.as_mut() {
        kill_child(c);
    }
    if let Some(c) = web_child.as_mut() {
        kill_child(c);
    }
    Ok(())
}

/// Did the debounced change set touch anything the loop cares about? (`.ceignore` + the default
/// skip set: target/, .git, node_modules, editor droppings.)
fn any_relevant(root: &Path, changed: &HashSet<PathBuf>) -> bool {
    let matcher = walk::load_matcher(root);
    changed.iter().any(|p| {
        let Some(rel) = walk::rel_of(root, p) else { return false };
        !matcher.is_ignored(&rel, p.is_dir()) && !crate::skip_any_component(&rel)
    })
}

/// Build once. Returns the built executable's path for the default cargo build (parsed from
/// cargo's JSON messages, so shared/target-dir-remapped workspaces resolve correctly); `None`
/// for a custom `[dev].build` (its `[dev].run` knows what to launch).
fn build_local(plan: &DevPlan, dir: &Path) -> Result<Option<PathBuf>> {
    match &plan.build {
        Some(custom) => {
            let status = Command::new("sh")
                .arg("-c")
                .arg(custom)
                .current_dir(dir)
                .envs(&plan.env)
                .status()
                .context("running [dev].build")?;
            if !status.success() {
                bail!("[dev].build exited with {status}");
            }
            Ok(None)
        }
        None => {
            let cmd = default_build_cmd(plan);
            // json-render-diagnostics: compiler errors/warnings render to stderr for the human;
            // stdout carries the JSON we parse for the executable path.
            let out = Command::new("sh")
                .arg("-c")
                .arg(format!("{cmd} --message-format=json-render-diagnostics"))
                .current_dir(dir)
                .stdout(Stdio::piped())
                .output()
                .context("running cargo build")?;
            if !out.status.success() {
                bail!("cargo build exited with {}", out.status);
            }
            let exe = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .filter_map(|v| v.get("executable").and_then(|e| e.as_str()).map(String::from))
                .next_back();
            let exe = exe.ok_or_else(|| anyhow!("cargo built nothing (no executable in output)"))?;
            Ok(Some(PathBuf::from(exe)))
        }
    }
}

fn spawn_app(plan: &DevPlan, dir: &Path, exe: Option<&Path>) -> Result<Child> {
    match (&plan.run, exe) {
        (Some(run), _) => spawn_shell(run, dir, &plan.env),
        (None, Some(exe)) => {
            let mut c = Command::new(exe);
            c.args(&plan.args).current_dir(dir).envs(&plan.env);
            spawn_grouped(c)
        }
        (None, None) => bail!("nothing to launch"),
    }
}

fn spawn_shell(cmd: &str, dir: &Path, env: &BTreeMap<String, String>) -> Result<Child> {
    let mut c = Command::new("sh");
    c.arg("-c").arg(cmd).current_dir(dir).envs(env);
    spawn_grouped(c)
}

/// Spawn in its own process group (unix) so a restart kills the whole tree (sh -c children,
/// cargo-run grandchildren), not just the immediate child.
fn spawn_grouped(mut c: Command) -> Result<Child> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.process_group(0);
    }
    c.spawn().context("spawning app process")
}

fn kill_child(c: &mut Child) {
    #[cfg(unix)]
    {
        let pid = c.id() as i32;
        unsafe {
            // Negative pid = the whole process group.
            libc::kill(-pid, libc::SIGTERM);
        }
        // Grace, then make sure.
        std::thread::sleep(Duration::from_millis(300));
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = c.kill();
    }
    let _ = c.wait();
}

// ----- --via loop (remote build+run over the mesh) -----

/// The remote loop: content-addressed-sync the tree, start ONE remote job (`build && exec run`),
/// stream its logs; on a local change kill it, resync the delta, restart. Same primitives as
/// `rdev build`/`rdev run` — no ssh, capability-authed, works through NAT.
async fn dev_via(
    client: &CeClient,
    cfg: &Config,
    plan: &DevPlan,
    dir: &Path,
    target: &str,
    cap: Option<String>,
) -> Result<()> {
    let (node_id, caps) = resolve(cfg, target, cap)?;
    let remote = format!("dev/{}", plan.name);
    let remote_root = remote_root_of(&remote);
    let shell = via_shell(plan);
    let dest = format!("{target}:{remote}");
    println!("dev {} --via {target}  (sync -> remote build+run -> live logs; Ctrl-C to stop)", plan.name);
    if plan.web.is_some() {
        eprintln!("dev: note — [dev].web runs locally even with --via");
    }
    let mut web_child = match &plan.web {
        Some((cmd, wd)) => Some(spawn_shell(cmd, wd, &plan.env).context("starting [dev].web")?),
        None => None,
    };

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<notify::Event>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            let _ = tx.send(ev);
        }
    })?;
    watcher.watch(dir, RecursiveMode::Recursive)?;

    'outer: loop {
        // 1) push the tree delta (content-addressed; unchanged files cost nothing).
        let opts = SyncdOpts {
            bidirectional: false,
            conflict: Policy::Lww,
            once: true,
            dry_run: false,
            debounce_ms: plan.debounce_ms,
        };
        syncd(client, cfg, dir, &dest, Some(caps.clone()), opts).await?;

        // 2) start the remote job: build, then exec the app.
        let start = Req {
            caps: caps.clone(),
            cmd: Some(vec!["bash".into(), "-lc".into(), shell.clone()]),
            cwd: Some(remote_root.clone()),
            ..Default::default()
        };
        let reply = client.request(&node_id, "rdev/run/start", &serde_json::to_vec(&start)?, 60_000).await?;
        let r: Resp = serde_json::from_slice(&reply)?;
        if !r.ok {
            return Err(anyhow!("remote start refused: {}", r.error.unwrap_or_default()));
        }
        let job_id = r.job_id.ok_or_else(|| anyhow!("server did not return a job_id"))?;
        println!("dev: remote job {job_id} started");

        // 3) stream logs until a local change (restart), remote exit (wait), or Ctrl-C (stop).
        let mut offset: u64 = 0;
        let mut running = true;
        loop {
            let poll = async {
                let req = Req {
                    caps: caps.clone(),
                    job_id: Some(job_id.clone()),
                    offset: Some(offset),
                    ..Default::default()
                };
                client.request(&node_id, "rdev/run/logs", &serde_json::to_vec(&req)?, 60_000).await
            };
            tokio::select! {
                ev = rx.recv() => {
                    let Some(first) = ev else { break 'outer };
                    let mut changed: HashSet<PathBuf> = first.paths.into_iter().collect();
                    while let Ok(Some(e)) =
                        tokio::time::timeout(Duration::from_millis(plan.debounce_ms), rx.recv()).await
                    {
                        changed.extend(e.paths);
                    }
                    if !any_relevant(dir, &changed) {
                        continue;
                    }
                    println!("dev: change detected — restarting remote job");
                    kill_remote(client, &node_id, &caps, &job_id).await;
                    continue 'outer;
                }
                reply = poll, if running => {
                    let lr: RunLogsResp = serde_json::from_slice(&reply?)?;
                    if !lr.ok {
                        return Err(anyhow!("run/logs failed: {}", lr.error.unwrap_or_default()));
                    }
                    if !lr.data_hex.is_empty() {
                        use std::io::Write;
                        let bytes = hex::decode(&lr.data_hex).context("log data hex")?;
                        let mut out = std::io::stdout();
                        out.write_all(&bytes)?;
                        out.flush()?;
                    }
                    offset = lr.next_offset;
                    if !lr.running {
                        eprintln!("dev: remote job exited ({:?}) — will restart on the next change",
                                  lr.exit_code);
                        running = false;
                        continue;
                    }
                    tokio::time::sleep(Duration::from_millis(700)).await;
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\ndev: stopping");
                    kill_remote(client, &node_id, &caps, &job_id).await;
                    break 'outer;
                }
            }
        }
    }

    if let Some(c) = web_child.as_mut() {
        kill_child(c);
    }
    Ok(())
}

async fn kill_remote(client: &CeClient, node_id: &str, caps: &str, job_id: &str) {
    let req = Req { caps: caps.to_string(), job_id: Some(job_id.to_string()), ..Default::default() };
    if let Ok(bytes) = serde_json::to_vec(&req) {
        let _ = client.request(node_id, "rdev/run/kill", &bytes, 30_000).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(manifest: &str) -> Result<DevPlan> {
        plan(Path::new("/tmp/myapp"), manifest, false, false)
    }

    #[test]
    fn defaults_from_native_and_daemon() {
        let plan = p(r#"
            [app]
            name = "clip"
            version = "0.2.0"
            runtime = "native"
            [native]
            bin = "clip"
            [daemon]
            enabled = true
            args = ["serve"]
        "#)
        .unwrap();
        assert_eq!(plan.name, "clip");
        assert_eq!(plan.bin.as_deref(), Some("clip"));
        assert!(plan.build.is_none());
        assert!(plan.run.is_none());
        assert_eq!(plan.args, vec!["serve"]);
        assert_eq!(default_build_cmd(&plan), "cargo build --bin clip");
        assert_eq!(plan.debounce_ms, 500);
    }

    #[test]
    fn dev_section_overrides() {
        let plan = p(r#"
            [app]
            name = "myapp"
            [native]
            bin = "myapp"
            [daemon]
            args = ["host"]
            [build]
            features = ["gateway"]
            [dev]
            args = ["host", "--dev"]
            web = "npm run dev"
            env = { RUST_LOG = "debug" }
            debounce_ms = 250
        "#)
        .unwrap();
        assert_eq!(plan.args, vec!["host", "--dev"]);
        assert_eq!(plan.web.as_ref().unwrap().0, "npm run dev");
        assert!(plan.web.as_ref().unwrap().1.ends_with("web"));
        assert_eq!(plan.env.get("RUST_LOG").map(String::as_str), Some("debug"));
        assert_eq!(plan.debounce_ms, 250);
        assert_eq!(default_build_cmd(&plan), "cargo build --bin myapp --features gateway");
    }

    #[test]
    fn custom_build_requires_run() {
        let err = p(r#"
            [app]
            name = "x"
            [native]
            bin = "x"
            [dev]
            build = "make"
        "#)
        .unwrap_err();
        assert!(err.to_string().contains("[dev].run"));
    }

    #[test]
    fn no_bin_no_dev_is_an_error() {
        assert!(p("[app]\nname = \"x\"\n").is_err());
    }

    #[test]
    fn custom_pair_without_native_ok() {
        let plan = p(r#"
            [app]
            name = "site"
            [dev]
            build = "npm run build"
            run = "npm run preview"
        "#)
        .unwrap();
        assert!(plan.bin.is_none());
        assert_eq!(plan.run.as_deref(), Some("npm run preview"));
    }

    #[test]
    fn no_web_flag_suppresses_web() {
        let plan = plan(
            Path::new("/tmp/a"),
            "[native]\nbin = \"a\"\n[dev]\nweb = \"npm run dev\"\n",
            false,
            true,
        )
        .unwrap();
        assert!(plan.web.is_none());
    }

    #[test]
    fn via_shell_builds_and_execs() {
        let plan = p(r#"
            [native]
            bin = "trana"
            [daemon]
            args = ["serve", "--ns", "a b"]
        "#)
        .unwrap();
        let sh = via_shell(&plan);
        assert!(sh.contains("cargo build --bin trana"));
        assert!(sh.contains("exec ./target/debug/trana serve --ns 'a b'"));
    }

    #[test]
    fn via_shell_release_and_env() {
        let mut plan = p("[native]\nbin = \"x\"\n").unwrap();
        plan.release = true;
        plan.env.insert("RUST_LOG".into(), "info".into());
        let sh = via_shell(&plan);
        assert!(sh.contains("--release"));
        assert!(sh.contains("export RUST_LOG=info;"));
        assert!(sh.contains("./target/release/x"));
    }
}
