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
//!
//! ## Commands
//!   - `rdev serve`                       — run the server (handles the actions above).
//!   - `rdev exec <target> -- <cmd…>`     — run a command on a peer.
//!   - `rdev push <file> <target:path>`   — push one file.
//!   - `rdev rm <target:path>`            — delete one file.
//!   - `rdev watch <dir> <target:dir>`    — continuous 1:1 folder mirror (replaces the old `mirror`).
//!
//! A `target` is a config alias or a 64-hex node id; the capability comes from the alias's `cap`
//! (or `--cap`). v0: revocation not consulted (relies on expiry); inbox is polled.

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
#[derive(Serialize, Deserialize, Default)]
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

#[derive(Serialize, Deserialize, Default)]
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
    println!("rdev serving as {}… (rdev/sync, rdev/delete, rdev/exec)", &host_hex[..16]);

    let mut seen: HashSet<u64> = HashSet::new();
    loop {
        for m in client.messages().await.unwrap_or_default() {
            let Some(token) = m.reply_token else { continue };
            if !m.topic.starts_with("rdev/") || !seen.insert(token) {
                continue;
            }
            let resp = handle(&m.topic, &m.from, &m.payload_hex, &host_id).await;
            let _ = client.reply(token, &serde_json::to_vec(&resp).unwrap_or_default()).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn handle(topic: &str, from_hex: &str, payload_hex: &str, host_id: &[u8; 32]) -> Resp {
    match handle_inner(topic, from_hex, payload_hex, host_id).await {
        Ok(r) => r,
        Err(e) => Resp { ok: false, error: Some(e.to_string()), ..Default::default() },
    }
}

async fn handle_inner(topic: &str, from_hex: &str, payload_hex: &str, host_id: &[u8; 32]) -> Result<Resp> {
    let action = topic.strip_prefix("rdev/").unwrap_or(topic);
    let req: Req = serde_json::from_slice(&hex::decode(payload_hex).context("payload hex")?).context("payload json")?;
    let from: [u8; 32] = hex::decode(from_hex).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("bad sender id"))?;

    // Authorize with the capability primitive. accepted_roots empty → self-issued caps honored;
    // revocation not consulted in v0 (rely on expiry).
    let chain: Vec<SignedCapability> = decode_chain(&req.caps).map_err(|_| anyhow!("bad capability"))?;
    authorize(host_id, &[], &[], now(), &from, action, &chain, &|_, _| false).map_err(|e| anyhow!("denied: {e}"))?;

    match action {
        "exec" => exec_action(&req).await,
        "sync" | "delete" => fs_action(action, &req, &chain),
        other => Err(anyhow!("unknown rdev action '{other}'")),
    }
}

async fn exec_action(req: &Req) -> Result<Resp> {
    let image = req.image.clone().ok_or_else(|| anyhow!("exec needs image"))?;
    let cmd = req.cmd.clone().unwrap_or_default();
    if cmd.is_empty() {
        return Err(anyhow!("exec needs a command"));
    }
    let docker = bollard::Docker::connect_with_local_defaults().context("Docker unavailable")?;
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let spec = ExecSpec { image, cmd, cwd: req.cwd.clone() };
    let (stdout, stderr, exit_code) = exec_in_container(&docker, &spec, &home).await?;
    Ok(Resp { ok: true, stdout: Some(stdout), stderr: Some(stderr), exit_code: Some(exit_code as i64), ..Default::default() })
}

fn fs_action(action: &str, req: &Req, chain: &[SignedCapability]) -> Result<Resp> {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let home_canon = home.canonicalize().unwrap_or_else(|_| home.clone());
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
