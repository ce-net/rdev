//! rdev — remote-dev services on CE, as an **application** (not part of the node).
//!
//! The reference for CE's primitives-vs-apps boundary: device-to-device features that mutate host
//! resources (run processes, write files) are apps built on CE's primitives — NOT node RPCs. rdev
//! provides remote exec + file sync/mirror over the mesh, authorized by capabilities, using only:
//!   - `ce-rs`        — mesh transport: directed request/response (`AppRequest`/`reply`) + `/status`.
//!   - `ce-cap`       — the capability verifier (does a signed, attenuating chain authorize an action?).
//!   - `ce-container` — the run-a-container primitive (bollard/gVisor), composed for `exec`.
//! CE moves the bytes and verifies signatures; rdev is the policy. No node code, no consensus tx.
//!
//! ## Protocol (over CE `AppRequest`, topic `rdev/<action>`)
//!   - `rdev/sync`   `{caps, path, data_hex}`     — write a file under the target's home.
//!   - `rdev/delete` `{caps, path}`               — delete a file (idempotent).
//!   - `rdev/exec`   `{caps, image, cmd, cwd}`    — run a command in a sandboxed container.
//!   - `rdev/spawn`  `{caps, cmd, cwd}`           — start a HOST process (cwd confined to home).
//!     DANGEROUS: spawns native code on the host, not sandboxed. Gated by the `spawn` ability,
//!     which a cap must explicitly carry. This is what lets a node bring up a new CE node +
//!     `rdev serve` on a target — the basis for self-replicating fleets (see the `replicator` app).
//!
//! ## Commands
//!   - `rdev serve`                       — run the server (handles the actions above).
//!   - `rdev exec <target> -- <cmd…>`     — run a command on a peer.
//!   - `rdev push <file> <target:path>`   — push one file.
//!   - `rdev rm <target:path>`            — delete one file.
//!   - `rdev watch <dir> <target:dir>`    — continuous 1:1 folder mirror (replaces the old `mirror`).
//!
//! A `target` is a config alias or a 64-hex node id; the capability comes from the alias's `cap`
//! (or `--cap`). `rdev serve` consults the node's on-chain revoked set (refreshed periodically) and
//! denies revoked chains; `spawn` is gated by a `$RDEV_SPAWN_ALLOW` allowlist (default-deny) with a
//! scrubbed environment. The inbox is polled.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use ce_cap::{SignedCapability, authorize, decode_chain};
use ce_container::{ExecSpec, exec_in_container};
use ce_rs::CeClient;
use clap::{Parser, Subcommand};
use notify::{RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

const SKIP: &[&str] = &["target", ".git", "node_modules", ".DS_Store"];

#[derive(Parser)]
#[command(name = "rdev", version, about = "Remote-dev exec + file sync over the CE mesh (an app on CE)")]
struct Cli {
    /// Local CE node API URL (else config's node.url, else http://127.0.0.1:8844).
    #[arg(long, global = true)]
    node: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server: accept rdev requests addressed to this node and perform them.
    Serve,
    /// Run a command in a sandboxed container on a peer: `rdev exec <target> --image rust -- cargo build`.
    Exec {
        target: String,
        #[arg(long, short = 'i')]
        image: String,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        cap: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Push a single file: `rdev push <file> <target>:<remote-path>`.
    Push {
        file: PathBuf,
        dest: String,
        #[arg(long)]
        cap: Option<String>,
    },
    /// Delete a file on a peer: `rdev rm <target>:<remote-path>`.
    Rm {
        dest: String,
        #[arg(long)]
        cap: Option<String>,
    },
    /// Continuous 1:1 folder mirror: `rdev watch <local-dir> <target>:<remote-dir>` (replaces `mirror`).
    Watch {
        dir: PathBuf,
        dest: String,
        #[arg(long)]
        cap: Option<String>,
    },
    /// Write an example config to the config path.
    Init,
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    node: NodeCfg,
    #[serde(default)]
    alias: BTreeMap<String, Alias>,
}

#[derive(Deserialize)]
struct NodeCfg {
    url: String,
}
impl Default for NodeCfg {
    fn default() -> Self {
        NodeCfg { url: "http://127.0.0.1:8844".into() }
    }
}

#[derive(Deserialize, Clone)]
struct Alias {
    node_id: String,
    #[serde(default)]
    cap: Option<String>,
}

/// Wire request payload (fields used per action).
#[derive(Debug, Serialize, Deserialize, Default)]
struct Req {
    caps: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    data_hex: Option<String>,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    cmd: Option<Vec<String>>,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Resp {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    stdout: Option<String>,
    #[serde(default)]
    stderr: Option<String>,
    #[serde(default)]
    exit_code: Option<i64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Cmd::Init = cli.cmd {
        return write_example_config();
    }
    let cfg = load_config();
    let url = cli.node.clone().unwrap_or_else(|| cfg.node.url.clone());
    let client = CeClient::new(url.clone());
    if !client.health().await.unwrap_or(false) {
        return Err(anyhow!("local CE node not reachable at {url} — is `ce start` running?"));
    }
    match cli.cmd {
        Cmd::Serve => serve(&client).await,
        Cmd::Exec { target, image, cwd, cap, command } => {
            exec(&client, &cfg, &target, image, cwd, cap, command).await
        }
        Cmd::Push { file, dest, cap } => push(&client, &cfg, &file, &dest, cap).await,
        Cmd::Rm { dest, cap } => rm(&client, &cfg, &dest, cap).await,
        Cmd::Watch { dir, dest, cap } => watch(&client, &cfg, &dir, &dest, cap).await,
        Cmd::Init => unreachable!(),
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ----- config / resolution -----

fn config_path() -> PathBuf {
    dirs_next::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("rdev").join("config.toml")
}
fn load_config() -> Config {
    std::fs::read_to_string(config_path()).ok().and_then(|s| toml::from_str(&s).ok()).unwrap_or_default()
}
fn write_example_config() -> Result<()> {
    let path = config_path();
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    if path.exists() {
        println!("config already exists: {}", path.display());
        return Ok(());
    }
    std::fs::write(&path, EXAMPLE_CONFIG)?;
    println!("wrote {}", path.display());
    Ok(())
}

/// Resolve `target` (alias or 64-hex node id) + optional `--cap` to (node_id, cap_token).
fn resolve(cfg: &Config, target: &str, cli_cap: Option<String>) -> Result<(String, String)> {
    let (node_id, cap) = if is_hex64(target) {
        (target.to_string(), cli_cap)
    } else if let Some(a) = cfg.alias.get(target) {
        (a.node_id.clone(), cli_cap.or_else(|| a.cap.clone()))
    } else {
        return Err(anyhow!("unknown target '{target}' (not 64-hex, not a config alias)"));
    };
    let cap = cap.ok_or_else(|| anyhow!("no capability for '{target}' — set `cap` in the alias or pass --cap"))?;
    Ok((node_id, cap))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ----- client commands -----

async fn exec(
    client: &CeClient,
    cfg: &Config,
    target: &str,
    image: String,
    cwd: Option<String>,
    cap: Option<String>,
    command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        return Err(anyhow!("specify a command, e.g. rdev exec desktop --image rust -- cargo build"));
    }
    let (node_id, caps) = resolve(cfg, target, cap)?;
    let req = Req { caps, image: Some(image), cmd: Some(command), cwd, ..Default::default() };
    let reply = client.request(&node_id, "rdev/exec", &serde_json::to_vec(&req)?, 600_000).await?;
    let r: Resp = serde_json::from_slice(&reply)?;
    if !r.ok {
        return Err(anyhow!("exec refused: {}", r.error.unwrap_or_default()));
    }
    if let Some(o) = &r.stdout {
        print!("{o}");
    }
    if let Some(e) = &r.stderr {
        eprint!("{e}");
    }
    if r.exit_code.unwrap_or(0) != 0 {
        std::process::exit(r.exit_code.unwrap_or(1) as i32);
    }
    Ok(())
}

async fn push(client: &CeClient, cfg: &Config, file: &Path, dest: &str, cap: Option<String>) -> Result<()> {
    let (target, path) = split_dest(dest)?;
    let (node_id, caps) = resolve(cfg, target, cap)?;
    let data = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    let req = Req { caps, path: path.into(), data_hex: Some(hex::encode(&data)), ..Default::default() };
    ok_reply(client.request(&node_id, "rdev/sync", &serde_json::to_vec(&req)?, 60_000).await?, &format!("pushed {}", file.display()))
}

async fn rm(client: &CeClient, cfg: &Config, dest: &str, cap: Option<String>) -> Result<()> {
    let (target, path) = split_dest(dest)?;
    let (node_id, caps) = resolve(cfg, target, cap)?;
    let req = Req { caps, path: path.into(), ..Default::default() };
    ok_reply(client.request(&node_id, "rdev/delete", &serde_json::to_vec(&req)?, 60_000).await?, &format!("deleted {path}"))
}

fn split_dest(dest: &str) -> Result<(&str, &str)> {
    dest.split_once(':').ok_or_else(|| anyhow!("dest must be <target>:<remote-path>"))
}

fn ok_reply(reply: Vec<u8>, msg: &str) -> Result<()> {
    let r: Resp = serde_json::from_slice(&reply)?;
    if r.ok {
        println!("{msg}");
        Ok(())
    } else {
        Err(anyhow!("remote refused: {}", r.error.unwrap_or_default()))
    }
}

// ----- watch (1:1 folder mirror; replaces the old `mirror` app) -----

async fn watch(client: &CeClient, cfg: &Config, dir: &Path, dest: &str, cap: Option<String>) -> Result<()> {
    let (target, remote_dir) = split_dest(dest)?;
    let (node_id, caps) = resolve(cfg, target, cap)?;
    let root = dir.canonicalize().with_context(|| format!("no such directory: {}", dir.display()))?;
    let remote_root = remote_dir.trim_start_matches("~/").trim_start_matches('~').trim_start_matches('/').trim_end_matches('/').to_string();

    // Initial full sync.
    let mut sent = 0usize;
    for e in WalkDir::new(&root).follow_links(false).into_iter().filter_entry(|e| e.depth() == 0 || !skip(e.file_name().to_str().unwrap_or(""))) {
        let e = match e { Ok(e) => e, Err(_) => continue };
        if !e.file_type().is_file() {
            continue;
        }
        let rel = e.path().strip_prefix(&root).unwrap_or(e.path());
        if push_file(client, &node_id, &caps, &remote_root, rel, e.path()).await.is_ok() {
            sent += 1;
        }
    }
    println!("initial sync: {sent} files. watching {} -> {target}:{remote_root} (Ctrl-C to stop)", root.display());

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<notify::Event>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            let _ = tx.send(ev);
        }
    })?;
    watcher.watch(&root, RecursiveMode::Recursive)?;

    loop {
        let first = tokio::select! {
            ev = rx.recv() => match ev { Some(e) => e, None => break },
            _ = tokio::signal::ctrl_c() => { println!("\nstopped"); break; }
        };
        let mut paths: HashSet<PathBuf> = first.paths.into_iter().collect();
        loop {
            match tokio::time::timeout(Duration::from_millis(250), rx.recv()).await {
                Ok(Some(ev)) => paths.extend(ev.paths),
                _ => break,
            }
        }
        for p in paths {
            let rel = match p.strip_prefix(&root) { Ok(r) => r, Err(_) => continue };
            if rel.as_os_str().is_empty() || rel.components().any(|c| skip(&c.as_os_str().to_string_lossy())) {
                continue;
            }
            if p.is_file() {
                match push_file(client, &node_id, &caps, &remote_root, rel, &p).await {
                    Ok(()) => println!("  synced {}", rel.display()),
                    Err(e) => eprintln!("  WARN {}: {e}", rel.display()),
                }
            } else if !p.exists() {
                let remote = remote_path(&remote_root, rel);
                let req = Req { caps: caps.clone(), path: remote, ..Default::default() };
                match client.request(&node_id, "rdev/delete", &serde_json::to_vec(&req)?, 30_000).await {
                    Ok(_) => println!("  deleted {}", rel.display()),
                    Err(e) => eprintln!("  WARN delete {}: {e}", rel.display()),
                }
            }
        }
    }
    Ok(())
}

async fn push_file(client: &CeClient, node_id: &str, caps: &str, remote_root: &str, rel: &Path, abs: &Path) -> Result<()> {
    let data = std::fs::read(abs)?;
    let req = Req { caps: caps.to_string(), path: remote_path(remote_root, rel), data_hex: Some(hex::encode(&data)), ..Default::default() };
    let reply = client.request(node_id, "rdev/sync", &serde_json::to_vec(&req)?, 60_000).await?;
    let r: Resp = serde_json::from_slice(&reply)?;
    if r.ok { Ok(()) } else { Err(anyhow!("{}", r.error.unwrap_or_default())) }
}

fn remote_path(remote_root: &str, rel: &Path) -> String {
    let rel = rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
    if remote_root.is_empty() { rel } else { format!("{remote_root}/{rel}") }
}

fn skip(name: &str) -> bool {
    SKIP.contains(&name) || name.ends_with('~') || name.ends_with(".swp") || name.ends_with(".tmp") || name.starts_with(".#")
}

// ----- server -----

async fn serve(client: &CeClient) -> Result<()> {
    let host_hex = client.status().await?.node_id;
    let host_id: [u8; 32] = hex::decode(&host_hex).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("bad node id"))?;
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    // Accepted capability roots: chains rooted at any of these (or at this host's own key) are
    // honored. Empty by default (only self-issued caps). An org/fleet sets a shared root here so
    // a seed can delegate attenuated caps down a replication tree that every node accepts.
    let roots = load_roots();
    println!(
        "rdev serving as {}… (rdev/sync, rdev/delete, rdev/exec, rdev/spawn) — {} configured root(s)",
        &host_hex[..16],
        roots.len()
    );

    let mut seen: HashSet<u64> = HashSet::new();
    // On-chain revoked (issuer, nonce) set, refreshed from the node every ~10s. A request whose
    // capability chain names a revoked link is denied even before its expiry.
    let mut revoked: HashSet<([u8; 32], u64)> = HashSet::new();
    let mut tick: u32 = 0;
    loop {
        if tick % 20 == 0 {
            if let Ok(pairs) = client.revoked().await {
                revoked = pairs
                    .into_iter()
                    .filter_map(|(issuer, nonce)| {
                        hex::decode(&issuer)
                            .ok()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .map(|i| (i, nonce))
                    })
                    .collect();
            }
        }
        tick = tick.wrapping_add(1);
        for m in client.messages().await.unwrap_or_default() {
            let Some(token) = m.reply_token else { continue };
            if !m.topic.starts_with("rdev/") || !seen.insert(token) {
                continue;
            }
            let resp = handle(&m.topic, &m.from, &m.payload_hex, &host_id, &roots, &revoked, &home).await;
            let _ = client.reply(token, &serde_json::to_vec(&resp).unwrap_or_default()).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Load accepted capability root keys (64-hex node ids, one per line, `#` comments). Looked up at
/// `$RDEV_ROOTS`, else `$CE_DATA_DIR/roots`, else `~/.local/share/ce/roots` — mirrors the node's
/// `<data_dir>/roots`. A node opts into an org/fleet by listing that org's root key here.
fn load_roots() -> Vec<[u8; 32]> {
    let path = std::env::var_os("RDEV_ROOTS")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CE_DATA_DIR").map(|d| PathBuf::from(d).join("roots")))
        .unwrap_or_else(|| dirs_next::home_dir().unwrap_or_default().join(".local/share/ce/roots"));
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .filter_map(|h| hex::decode(h).ok().and_then(|b| b.try_into().ok()))
        .collect()
}

async fn handle(topic: &str, from_hex: &str, payload_hex: &str, host_id: &[u8; 32], roots: &[[u8; 32]], revoked: &HashSet<([u8; 32], u64)>, home: &Path) -> Resp {
    match handle_inner(topic, from_hex, payload_hex, host_id, roots, revoked, home).await {
        Ok(r) => r,
        Err(e) => Resp { ok: false, error: Some(e.to_string()), ..Default::default() },
    }
}

/// Verify the capability and dispatch the action.
async fn handle_inner(topic: &str, from_hex: &str, payload_hex: &str, host_id: &[u8; 32], roots: &[[u8; 32]], revoked: &HashSet<([u8; 32], u64)>, home: &Path) -> Result<Resp> {
    let action = topic.strip_prefix("rdev/").unwrap_or(topic);
    let req: Req = serde_json::from_slice(&hex::decode(payload_hex).context("payload hex")?).context("payload json")?;
    let from: [u8; 32] = hex::decode(from_hex).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("bad sender id"))?;

    // Authorize with the capability primitive. Chains rooted at this host or any configured root
    // are honored; a link named in the on-chain revoked set is rejected (consulted via the node).
    let chain: Vec<SignedCapability> = decode_chain(&req.caps).map_err(|_| anyhow!("bad capability"))?;
    let is_revoked = |issuer: &[u8; 32], nonce: u64| revoked.contains(&(*issuer, nonce));
    authorize(host_id, roots, &[], now(), &from, action, &chain, &is_revoked).map_err(|e| anyhow!("denied: {e}"))?;

    match action {
        "exec" => exec_action(&req, home).await,
        "spawn" => spawn_action(&req, &chain, home),
        "sync" | "delete" => fs_action(action, &req, &chain, home),
        other => Err(anyhow!("unknown rdev action '{other}'")),
    }
}

/// Allowed program basenames for `rdev/spawn`, from `$RDEV_SPAWN_ALLOW` (comma-separated).
/// EMPTY/unset ⇒ spawn is DENIED entirely (default-deny). The operator opts in explicitly, e.g.
/// `RDEV_SPAWN_ALLOW=ce,rdev,replicator,sh`. This bounds the blast radius of the (unsandboxed)
/// spawn ability: even a holder of a valid `spawn` cap can only launch programs on this list.
fn spawn_allowlist() -> Vec<String> {
    std::env::var("RDEV_SPAWN_ALLOW")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Start a HOST process (NOT sandboxed). Reached only with the `spawn` ability, AND only for a
/// program whose basename is on `$RDEV_SPAWN_ALLOW` (default-deny). `cwd` is confined to the
/// target's home + any `path_prefix` caveat; the environment is scrubbed; the child is detached
/// (stdio null) so long-running processes like `ce start` survive. Returns the spawned pid.
fn spawn_action(req: &Req, chain: &[SignedCapability], home: &Path) -> Result<Resp> {
    let cmd = req.cmd.clone().unwrap_or_default();
    if cmd.is_empty() {
        return Err(anyhow!("spawn needs a command"));
    }
    // Default-deny allowlist on the program basename.
    let allow = spawn_allowlist();
    let prog_base = std::path::Path::new(&cmd[0])
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| cmd[0].clone());
    if allow.is_empty() {
        return Err(anyhow!(
            "spawn denied: no programs allow-listed (set RDEV_SPAWN_ALLOW=<basenames>)"
        ));
    }
    if !allow.contains(&prog_base) {
        return Err(anyhow!("spawn denied: '{prog_base}' not in RDEV_SPAWN_ALLOW {allow:?}"));
    }
    let cwd = match &req.cwd {
        Some(c) => {
            if c.contains("..") {
                return Err(anyhow!("path traversal not allowed"));
            }
            if let Some(prefix) = chain.last().and_then(|c| c.cap.caveats.path_prefix.as_ref()) {
                if !c.starts_with(prefix.as_str()) {
                    return Err(anyhow!("cwd outside capability prefix '{prefix}'"));
                }
            }
            home.join(c)
        }
        None => home.to_path_buf(),
    };
    std::fs::create_dir_all(&cwd).ok();
    // Scrub the environment so the child can't inherit the server's secrets (tokens, keys, etc.).
    // Provide only a minimal, safe set.
    let path_env = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    let child = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(&cwd)
        .env_clear()
        .env("PATH", path_env)
        .env("HOME", &cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawn '{}'", cmd[0]))?;
    Ok(Resp { ok: true, stdout: Some(format!("spawned pid {}", child.id())), ..Default::default() })
}

async fn exec_action(req: &Req, home: &Path) -> Result<Resp> {
    let image = req.image.clone().ok_or_else(|| anyhow!("exec needs image"))?;
    let cmd = req.cmd.clone().unwrap_or_default();
    if cmd.is_empty() {
        return Err(anyhow!("exec needs a command"));
    }
    let docker = bollard::Docker::connect_with_local_defaults().context("Docker unavailable")?;
    let spec = ExecSpec { image, cmd, cwd: req.cwd.clone() };
    let (stdout, stderr, exit_code) = exec_in_container(&docker, &spec, home).await?;
    Ok(Resp { ok: true, stdout: Some(stdout), stderr: Some(stderr), exit_code: Some(exit_code as i64), ..Default::default() })
}

fn fs_action(action: &str, req: &Req, chain: &[SignedCapability], home: &Path) -> Result<Resp> {
    let home_canon = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    if req.path.contains("..") {
        return Err(anyhow!("path traversal not allowed"));
    }
    if let Some(prefix) = chain.last().and_then(|c| c.cap.caveats.path_prefix.as_ref()) {
        if !req.path.starts_with(prefix.as_str()) {
            return Err(anyhow!("path outside capability prefix '{prefix}'"));
        }
    }
    let target = home.join(&req.path);
    match action {
        "sync" => {
            let data = hex::decode(req.data_hex.clone().unwrap_or_default()).context("data hex")?;
            if let Some(p) = target.parent() {
                std::fs::create_dir_all(p).ok();
                let canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
                if !canon.starts_with(&home_canon) {
                    return Err(anyhow!("path traversal not allowed"));
                }
            }
            std::fs::write(&target, &data).with_context(|| format!("write {}", target.display()))?;
            Ok(Resp { ok: true, ..Default::default() })
        }
        "delete" => match std::fs::remove_file(&target) {
            Ok(()) => Ok(Resp { ok: true, ..Default::default() }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Resp { ok: true, ..Default::default() }),
            Err(e) => Err(anyhow!("delete failed: {e}")),
        },
        _ => unreachable!(),
    }
}

const EXAMPLE_CONFIG: &str = r#"# rdev config

[node]
url = "http://127.0.0.1:8844"

# alias -> target node + the capability the target issued you (ce grant <your-id> --can exec,sync,delete)
[alias.desktop]
node_id = "25df8f15853855c4cd2c5769cbc9789bf156534356ffead3b67c2c395f6d8ac1"
# cap = "<token from ce grant>"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use ce_cap::{Caveats, Resource, SignedCapability, encode_chain};
    use ce_identity::Identity;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn id(tag: &str) -> Identity {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rdev-test-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn tmp_home(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rdev-home-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Issue a self-cap from `host` to `aud` for `actions`, with optional path_prefix/expiry.
    fn cap(host: &Identity, aud: [u8; 32], actions: &[&str], path_prefix: Option<&str>, not_after: u64) -> String {
        let caveats = Caveats { not_after, path_prefix: path_prefix.map(|s| s.to_string()), ..Default::default() };
        let c = SignedCapability::issue(host, aud, actions.iter().map(|s| s.to_string()).collect(), Resource::Any, caveats, 1, None);
        encode_chain(&[c])
    }

    fn payload(req: &Req) -> String {
        hex::encode(serde_json::to_vec(req).unwrap())
    }

    // ----- pure helpers -----

    #[test]
    fn req_resp_roundtrip() {
        let r = Req { caps: "ab".into(), path: "a/b.txt".into(), data_hex: Some("00ff".into()), ..Default::default() };
        let back: Req = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(back.path, "a/b.txt");
        assert_eq!(back.data_hex.as_deref(), Some("00ff"));
        let resp = Resp { ok: false, error: Some("x".into()), ..Default::default() };
        let rb: Resp = serde_json::from_slice(&serde_json::to_vec(&resp).unwrap()).unwrap();
        assert!(!rb.ok);
        assert_eq!(rb.error.as_deref(), Some("x"));
    }

    #[test]
    fn is_hex64_rules() {
        assert!(is_hex64(&"a".repeat(64)));
        assert!(!is_hex64(&"a".repeat(63)));
        assert!(!is_hex64(&"g".repeat(64)));
    }

    #[test]
    fn remote_path_joins() {
        assert_eq!(remote_path("code", Path::new("a/b.rs")), "code/a/b.rs");
        assert_eq!(remote_path("", Path::new("a.rs")), "a.rs");
    }

    #[test]
    fn skip_rules() {
        assert!(skip("target"));
        assert!(skip(".git"));
        assert!(skip("foo~"));
        assert!(skip("x.swp"));
        assert!(!skip("main.rs"));
    }

    #[test]
    fn resolve_alias_hex_and_errors() {
        let mut cfg = Config::default();
        cfg.alias.insert("desktop".into(), Alias { node_id: "d".repeat(64), cap: Some("tok".into()) });
        // alias
        let (n, c) = resolve(&cfg, "desktop", None).unwrap();
        assert_eq!(n, "d".repeat(64));
        assert_eq!(c, "tok");
        // --cap overrides alias cap
        let (_, c) = resolve(&cfg, "desktop", Some("override".into())).unwrap();
        assert_eq!(c, "override");
        // raw hex node id needs --cap
        assert!(resolve(&cfg, &"a".repeat(64), None).is_err());
        let (n, c) = resolve(&cfg, &"a".repeat(64), Some("t".into())).unwrap();
        assert_eq!(n, "a".repeat(64));
        assert_eq!(c, "t");
        // unknown target
        assert!(resolve(&cfg, "nope", None).is_err());
    }

    // ----- fs_action (capability already checked upstream; here we test path safety) -----

    #[test]
    fn fs_sync_writes_then_delete_idempotent() {
        let home = tmp_home("fs-sync");
        let chain: Vec<SignedCapability> = vec![];
        let req = Req { path: "sub/a.txt".into(), data_hex: Some(hex::encode(b"hello")), ..Default::default() };
        let r = fs_action("sync", &req, &chain, &home).unwrap();
        assert!(r.ok);
        assert_eq!(std::fs::read(home.join("sub/a.txt")).unwrap(), b"hello");
        // delete it, then delete again (idempotent)
        let del = Req { path: "sub/a.txt".into(), ..Default::default() };
        assert!(fs_action("delete", &del, &chain, &home).unwrap().ok);
        assert!(!home.join("sub/a.txt").exists());
        assert!(fs_action("delete", &del, &chain, &home).unwrap().ok, "delete is idempotent");
    }

    #[test]
    fn fs_rejects_path_traversal() {
        let home = tmp_home("fs-trav");
        let chain: Vec<SignedCapability> = vec![];
        let req = Req { path: "../escape.txt".into(), data_hex: Some(hex::encode(b"x")), ..Default::default() };
        assert!(fs_action("sync", &req, &chain, &home).is_err());
    }

    #[test]
    fn fs_enforces_path_prefix_caveat() {
        let home = tmp_home("fs-prefix");
        let host = id("prefix-host");
        let aud = id("prefix-aud");
        // cap confined to "code/"
        let token = cap(&host, aud.node_id(), &["sync"], Some("code/"), 0);
        let chain = decode_chain(&token).unwrap();
        // inside prefix → ok
        let inside = Req { caps: token.clone(), path: "code/a.txt".into(), data_hex: Some(hex::encode(b"y")), ..Default::default() };
        assert!(fs_action("sync", &inside, &chain, &home).unwrap().ok);
        // outside prefix → denied
        let outside = Req { caps: token, path: "secrets.txt".into(), data_hex: Some(hex::encode(b"y")), ..Default::default() };
        assert!(fs_action("sync", &outside, &chain, &home).is_err());
    }

    // ----- handle_inner: full path incl. capability authorization -----

    #[tokio::test]
    async fn handle_authorizes_self_issued_cap_and_writes() {
        let home = tmp_home("h-ok");
        let host = id("h-ok-host");
        let sender = id("h-ok-sender");
        let token = cap(&host, sender.node_id(), &["sync"], None, 0);
        let req = Req { caps: token, path: "f.txt".into(), data_hex: Some(hex::encode(b"data")), ..Default::default() };
        let resp = handle_inner("rdev/sync", &hex::encode(sender.node_id()), &payload(&req), &host.node_id(), &[], &std::collections::HashSet::new(), &home).await.unwrap();
        assert!(resp.ok);
        assert_eq!(std::fs::read(home.join("f.txt")).unwrap(), b"data");
    }

    #[tokio::test]
    async fn handle_denies_action_not_granted() {
        let home = tmp_home("h-deny");
        let host = id("h-deny-host");
        let sender = id("h-deny-sender");
        // cap grants only "sync"; request "delete"
        let token = cap(&host, sender.node_id(), &["sync"], None, 0);
        let req = Req { caps: token, path: "f.txt".into(), ..Default::default() };
        let err = handle_inner("rdev/delete", &hex::encode(sender.node_id()), &payload(&req), &host.node_id(), &[], &std::collections::HashSet::new(), &home).await.unwrap_err();
        assert!(err.to_string().contains("denied"));
    }

    #[tokio::test]
    async fn handle_denies_expired_cap() {
        let home = tmp_home("h-exp");
        let host = id("h-exp-host");
        let sender = id("h-exp-sender");
        let token = cap(&host, sender.node_id(), &["sync"], None, 1); // not_after = 1 (long past)
        let req = Req { caps: token, path: "f.txt".into(), data_hex: Some(hex::encode(b"z")), ..Default::default() };
        let err = handle_inner("rdev/sync", &hex::encode(sender.node_id()), &payload(&req), &host.node_id(), &[], &std::collections::HashSet::new(), &home).await.unwrap_err();
        assert!(err.to_string().contains("denied"));
    }

    #[tokio::test]
    async fn handle_denies_cap_for_other_audience() {
        let home = tmp_home("h-aud");
        let host = id("h-aud-host");
        let sender = id("h-aud-sender");
        let other = id("h-aud-other");
        // cap issued to `other`, presented by `sender`
        let token = cap(&host, other.node_id(), &["sync"], None, 0);
        let req = Req { caps: token, path: "f.txt".into(), data_hex: Some(hex::encode(b"z")), ..Default::default() };
        let err = handle_inner("rdev/sync", &hex::encode(sender.node_id()), &payload(&req), &host.node_id(), &[], &std::collections::HashSet::new(), &home).await.unwrap_err();
        assert!(err.to_string().contains("denied"));
    }

    #[tokio::test]
    async fn handle_denies_cap_not_rooted_at_host() {
        let home = tmp_home("h-root");
        let host = id("h-root-host");
        let stranger = id("h-root-stranger"); // not the host, not a configured root
        let sender = id("h-root-sender");
        let token = cap(&stranger, sender.node_id(), &["sync"], None, 0);
        let req = Req { caps: token, path: "f.txt".into(), data_hex: Some(hex::encode(b"z")), ..Default::default() };
        let err = handle_inner("rdev/sync", &hex::encode(sender.node_id()), &payload(&req), &host.node_id(), &[], &std::collections::HashSet::new(), &home).await.unwrap_err();
        assert!(err.to_string().contains("denied"));
    }

    // ----- spawn: HOST process execution, gated by the `spawn` ability -----

    /// Allow the programs the spawn tests launch (default-deny otherwise). Idempotent value so
    /// concurrent tests setting the same env var don't disagree.
    fn allow_spawn() {
        unsafe { std::env::set_var("RDEV_SPAWN_ALLOW", "sh,true") };
    }

    #[tokio::test]
    async fn spawn_authorized_runs_host_process() {
        allow_spawn();
        let home = tmp_home("spawn-ok");
        let _ = std::fs::remove_file(home.join("spawned_marker"));
        let host = id("spawn-ok-host");
        let sender = id("spawn-ok-sender");
        let token = cap(&host, sender.node_id(), &["spawn"], None, 0);
        let req = Req { caps: token, cmd: Some(vec!["sh".into(), "-c".into(), "echo hi > spawned_marker".into()]), ..Default::default() };
        let resp = handle_inner("rdev/spawn", &hex::encode(sender.node_id()), &payload(&req), &host.node_id(), &[], &std::collections::HashSet::new(), &home).await.unwrap();
        assert!(resp.ok);
        assert!(resp.stdout.unwrap_or_default().contains("spawned pid"));
        let marker = home.join("spawned_marker");
        let mut ran = false;
        for _ in 0..30 {
            if marker.exists() { ran = true; break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(ran, "spawned host process did not create its marker");
    }

    #[tokio::test]
    async fn spawn_denied_without_spawn_ability() {
        let home = tmp_home("spawn-deny");
        let host = id("spawn-deny-host");
        let sender = id("spawn-deny-sender");
        let token = cap(&host, sender.node_id(), &["sync"], None, 0); // no "spawn"
        let req = Req { caps: token, cmd: Some(vec!["sh".into(), "-c".into(), "echo pwned > pwned".into()]), ..Default::default() };
        let err = handle_inner("rdev/spawn", &hex::encode(sender.node_id()), &payload(&req), &host.node_id(), &[], &std::collections::HashSet::new(), &home).await.unwrap_err();
        assert!(err.to_string().contains("denied"));
        assert!(!home.join("pwned").exists());
    }

    #[tokio::test]
    async fn spawn_cwd_rejects_traversal() {
        allow_spawn();
        let home = tmp_home("spawn-trav");
        let host = id("spawn-trav-host");
        let sender = id("spawn-trav-sender");
        let token = cap(&host, sender.node_id(), &["spawn"], None, 0);
        let req = Req { caps: token, cmd: Some(vec!["true".into()]), cwd: Some("../evil".into()), ..Default::default() };
        let err = handle_inner("rdev/spawn", &hex::encode(sender.node_id()), &payload(&req), &host.node_id(), &[], &std::collections::HashSet::new(), &home).await.unwrap_err();
        assert!(err.to_string().contains("traversal"));
    }

    #[tokio::test]
    async fn spawn_denied_for_non_allowlisted_program() {
        allow_spawn(); // allows sh,true — but NOT `echo`
        let home = tmp_home("spawn-allow");
        let host = id("spawn-allow-host");
        let sender = id("spawn-allow-sender");
        let token = cap(&host, sender.node_id(), &["spawn"], None, 0);
        let req = Req { caps: token, cmd: Some(vec!["echo".into(), "hi".into()]), ..Default::default() };
        let err = handle_inner("rdev/spawn", &hex::encode(sender.node_id()), &payload(&req), &host.node_id(), &[], &std::collections::HashSet::new(), &home).await.unwrap_err();
        assert!(err.to_string().contains("not in RDEV_SPAWN_ALLOW"), "got: {err}");
    }

    // ----- delegation rooted at a configured org root: the recursion spine -----

    #[tokio::test]
    async fn delegated_chain_rooted_at_org_root_authorizes() {
        allow_spawn();
        let home = tmp_home("deleg");
        let _ = std::fs::remove_file(home.join("deleg_marker"));
        let root = id("deleg-root"); // shared org root R, listed in the host's accepted roots
        let seed = id("deleg-seed"); // A holds [R->A]
        let mid = id("deleg-mid"); // B holds [R->A, A->B] (A delegated to B)
        let host = id("deleg-host"); // C: serving host, accepts R as a root

        let c0 = SignedCapability::issue(&root, seed.node_id(), vec!["sync".into(), "spawn".into()], Resource::Any, Caveats::default(), 1, None);
        let c1 = SignedCapability::issue(&seed, mid.node_id(), vec!["spawn".into()], Resource::Any, Caveats::default(), 2, Some(c0.id()));
        let token = encode_chain(&[c0, c1]);

        // B presents the delegated chain to host C; requester = B. C honors it (rooted at R).
        let req = Req { caps: token, cmd: Some(vec!["sh".into(), "-c".into(), "echo ok > deleg_marker".into()]), ..Default::default() };
        let resp = handle_inner("rdev/spawn", &hex::encode(mid.node_id()), &payload(&req), &host.node_id(), &[root.node_id()], &std::collections::HashSet::new(), &home).await.unwrap();
        assert!(resp.ok);
        let marker = home.join("deleg_marker");
        let mut ran = false;
        for _ in 0..30 {
            if marker.exists() { ran = true; break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(ran, "delegated spawn did not run");
    }

    #[tokio::test]
    async fn delegation_cannot_escalate_beyond_parent() {
        let home = tmp_home("deleg-esc");
        let root = id("esc-root");
        let seed = id("esc-seed");
        let mid = id("esc-mid");
        let host = id("esc-host");
        // R -> A grants ONLY sync; A tries to delegate `spawn` to B — privilege escalation.
        let c0 = SignedCapability::issue(&root, seed.node_id(), vec!["sync".into()], Resource::Any, Caveats::default(), 1, None);
        let c1 = SignedCapability::issue(&seed, mid.node_id(), vec!["spawn".into()], Resource::Any, Caveats::default(), 2, Some(c0.id()));
        let token = encode_chain(&[c0, c1]);
        let req = Req { caps: token, cmd: Some(vec!["sh".into(), "-c".into(), "echo pwn > pwn".into()]), ..Default::default() };
        let err = handle_inner("rdev/spawn", &hex::encode(mid.node_id()), &payload(&req), &host.node_id(), &[root.node_id()], &std::collections::HashSet::new(), &home).await.unwrap_err();
        assert!(err.to_string().contains("denied"));
        assert!(!home.join("pwn").exists());
    }
}
