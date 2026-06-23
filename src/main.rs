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
//! ## Auto-Sync v2 protocol (continuous, content-addressed; topic `rdev/sync2/<verb>`)
//!   - `rdev/sync2/have`   `{caps, chunks}`            — which chunk CIDs does the receiver lack?
//!   - `rdev/sync2/commit` `{caps, path, file_cid, manifest, base_cid, mode, mtime_ms}` — apply a
//!     file by manifest (bytes travel via the blob store, NOT in the RPC).
//!   - `rdev/sync2/delete` `{caps, path, base_cid}`    — tombstone a path (idempotent, conflict-aware).
//!   - `rdev/sync2/list`   `{caps, prefix}`            — receiver returns its subtree index (bidir).
//!   The reusable chunk/CID/delta/index/ignore/conflict engine lives in this crate's **library**
//!   half (`src/lib.rs` → `rdev::{chunk,delta,index,ceignore,conflict,syncproto,walk}`), the shared
//!   substrate `ce-pin` and Notes depend on. See `PLAN/05-autosync.md`.
//!
//! ## Commands
//!   - `rdev serve`                       — run the server (handles the actions above + sync2/*).
//!   - `rdev exec <target> -- <cmd…>`     — run a command on a peer.
//!   - `rdev push <file> <target:path>`   — push one file (whole-file, one-shot).
//!   - `rdev rm <target:path>`            — delete one file.
//!   - `rdev syncd <dir> <target:dir>`    — continuous, content-addressed, resumable folder sync.
//!   - `rdev watch <dir> <target:dir>`    — DEPRECATED alias for `rdev syncd --conflict lww`.
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

// The Auto-Sync v2 substrate (this crate's library half): chunking, delta, index, ignore, conflict
// resolution, and the rdev/sync2/* wire types. The daemon below wires it to ce-rs transport.
use rdev::chunk::chunk_bytes;
use rdev::conflict::{ConflictInput, Policy, Resolution, resolve as resolve_conflict};
use rdev::delta::{apply_commit_verified, plan_transfer, upload_missing};
use rdev::index::{Index, IndexEntry};
use rdev::syncproto::{
    CommitReq, CommitResp, DeleteReq, DeleteResp, HaveReq, HaveResp, ListEntry, ListReq, ListResp,
    ManifestReq, ManifestResp, action_for, verb,
};
use rdev::walk;

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
    /// Continuous 1:1 folder mirror (DEPRECATED alias for `syncd --conflict lww`).
    Watch {
        dir: PathBuf,
        dest: String,
        #[arg(long)]
        cap: Option<String>,
    },
    /// Continuous, content-addressed, resumable folder sync (Auto-Sync v2).
    ///
    /// `rdev syncd <local-dir> <target>:<remote-dir>`. Chunks files client-side, transfers only the
    /// chunks the receiver lacks (via the blob store), commits manifests over `rdev/sync2/*`, and
    /// keeps a crash-safe index for fast-skip + resume. `.ceignore` is honored.
    Syncd {
        dir: PathBuf,
        dest: String,
        #[arg(long)]
        cap: Option<String>,
        /// Bidirectional sync (pull remote changes too). Default: push-only.
        #[arg(long)]
        bidirectional: bool,
        /// Conflict policy: lww | copy | crdt. Default: lww.
        #[arg(long, default_value = "lww")]
        conflict: String,
        /// Reconcile once and exit (no watch) — for scripts/CI.
        #[arg(long)]
        once: bool,
        /// Print the planned commits/deletes; transfer nothing.
        #[arg(long)]
        dry_run: bool,
        /// Debounce window for batching filesystem events, in ms.
        #[arg(long, default_value_t = 500)]
        debounce_ms: u64,
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
        Cmd::Watch { dir, dest, cap } => {
            // Back-compat shim: `watch` == `syncd --conflict lww` (push-only, watch).
            eprintln!("note: `rdev watch` is deprecated; use `rdev syncd`");
            let opts = SyncdOpts {
                bidirectional: false,
                conflict: Policy::Lww,
                once: false,
                dry_run: false,
                debounce_ms: 500,
            };
            syncd(&client, &cfg, &dir, &dest, cap, opts).await
        }
        Cmd::Syncd { dir, dest, cap, bidirectional, conflict, once, dry_run, debounce_ms } => {
            let conflict: Policy = conflict.parse()?;
            let opts = SyncdOpts { bidirectional, conflict, once, dry_run, debounce_ms };
            syncd(&client, &cfg, &dir, &dest, cap, opts).await
        }
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

// ----- legacy mirror helpers (the old whole-file `watch` is superseded by `syncd`; these small
// pure helpers remain, exercised by unit tests and documenting the historic skip list) -----

/// Legacy hard-coded skip predicate (superseded by `.ceignore` via `rdev::ceignore`). Retained for
/// the `skip_rules` unit test and as documentation of the historic default ignore set.
#[allow(dead_code)]
fn skip(name: &str) -> bool {
    SKIP.contains(&name) || name.ends_with('~') || name.ends_with(".swp") || name.ends_with(".tmp") || name.starts_with(".#")
}

/// Legacy remote-path join (superseded by `remote_join`). Retained for its unit test.
#[allow(dead_code)]
fn remote_path(remote_root: &str, rel: &Path) -> String {
    let rel = rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
    if remote_root.is_empty() { rel } else { format!("{remote_root}/{rel}") }
}

// ----- syncd (Auto-Sync v2: content-addressed, resumable, delta folder sync) -----

/// Options controlling a `syncd` session.
struct SyncdOpts {
    bidirectional: bool,
    conflict: Policy,
    once: bool,
    dry_run: bool,
    debounce_ms: u64,
}

/// The wire string for a conflict [`Policy`] (matches `Policy::from_str`). Sent on `commit` so the
/// receiver can honor the initiator's chosen policy.
fn policy_str(p: Policy) -> &'static str {
    match p {
        Policy::Lww => "lww",
        Policy::Copy => "copy",
        Policy::Crdt => "crdt",
    }
}

/// Normalize a `<target>:<remote-dir>` into the remote root (trim `~/`, leading/trailing slashes).
fn remote_root_of(remote_dir: &str) -> String {
    remote_dir
        .trim_start_matches("~/")
        .trim_start_matches('~')
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

/// Continuous content-addressed sync: reconcile from a crash-safe index, transfer only missing
/// chunks via the blob store, commit manifests over `rdev/sync2/*`, then (unless `--once`) watch.
async fn syncd(
    client: &CeClient,
    cfg: &Config,
    dir: &Path,
    dest: &str,
    cap: Option<String>,
    opts: SyncdOpts,
) -> Result<()> {
    let (target, remote_dir) = split_dest(dest)?;
    let (node_id, caps) = resolve(cfg, target, cap)?;
    let root = dir.canonicalize().with_context(|| format!("no such directory: {}", dir.display()))?;
    let remote_root = remote_root_of(remote_dir);
    let root_str = root.to_string_lossy().to_string();

    let idx_dir = Index::default_dir();
    let mut index = Index::load(&idx_dir, &root_str, &node_id, &remote_root);

    // Reconcile: rebuild a fresh index (reusing cached chunk CIDs for unchanged files) and push the
    // delta. This replaces the old unconditional full re-push.
    println!("reconcile  {target}:{remote_root}");
    let fresh = walk::build_index(&root, &index)?;
    reconcile(client, &node_id, &caps, &remote_root, &root, &mut index, &fresh, &opts).await?;
    if !opts.dry_run {
        index.save(&idx_dir).ok();
    }

    if opts.once {
        return Ok(());
    }

    println!(
        "watching {} -> {target}:{remote_root}   conflict={:?}  (Ctrl-C to stop)",
        root.display(),
        opts.conflict
    );

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
        let mut changed: HashSet<PathBuf> = first.paths.into_iter().collect();
        // Coalesce a debounce window of events.
        while let Ok(Some(ev)) =
            tokio::time::timeout(Duration::from_millis(opts.debounce_ms), rx.recv()).await
        {
            changed.extend(ev.paths);
        }
        // A change to .ceignore triggers a full reconcile (the matcher changed).
        let ceignore_changed = changed.iter().any(|p| p.file_name().is_some_and(|n| n == ".ceignore"));
        if ceignore_changed {
            let fresh = walk::build_index(&root, &index)?;
            reconcile(client, &node_id, &caps, &remote_root, &root, &mut index, &fresh, &opts).await?;
            index.save(&idx_dir).ok();
            continue;
        }
        let matcher = walk::load_matcher(&root);
        for p in changed {
            let Some(rel) = walk::rel_of(&root, &p) else { continue };
            let is_dir = p.is_dir();
            if matcher.is_ignored(&rel, is_dir) {
                continue;
            }
            if p.is_file() {
                match push_delta(client, &node_id, &caps, &remote_root, &root, &rel, &mut index, &opts).await {
                    Ok(Some(n)) => println!("  up {rel}  ({n} new chunks)"),
                    Ok(None) => {} // unchanged / dry-run skip
                    Err(e) => eprintln!("  WARN {rel}: {e}"),
                }
            } else if !p.exists() {
                match delete_remote(client, &node_id, &caps, &remote_root, &rel, &mut index, &opts).await {
                    Ok(true) => println!("  deleted {rel}"),
                    Ok(false) => {}
                    Err(e) => eprintln!("  WARN delete {rel}: {e}"),
                }
            }
        }
        if !opts.dry_run {
            index.save(&idx_dir).ok();
        }
    }
    Ok(())
}

/// Reconcile the fresh local index against the last-saved index (and, if bidirectional, the
/// remote's `list`), pushing the minimal set of changed files and propagating deletes.
#[allow(clippy::too_many_arguments)]
async fn reconcile(
    client: &CeClient,
    node_id: &str,
    caps: &str,
    remote_root: &str,
    root: &Path,
    index: &mut Index,
    fresh: &Index,
    opts: &SyncdOpts,
) -> Result<()> {
    // Files present (or changed) locally -> push delta.
    let mut pushed = 0usize;
    for (rel, entry) in &fresh.entries {
        let changed = match index.entries.get(rel) {
            Some(prev) => prev.file_cid != entry.file_cid,
            None => true,
        };
        // Adopt the fresh entry into the working index first (so push_delta sees current chunks).
        index.upsert(entry.clone());
        if !changed {
            continue;
        }
        match push_delta(client, node_id, caps, remote_root, root, rel, index, opts).await {
            Ok(Some(n)) => {
                println!("  push   {rel}  ({n} new chunks)");
                pushed += 1;
            }
            Ok(None) => {}
            Err(e) => eprintln!("  WARN {rel}: {e}"),
        }
    }
    // Files that vanished locally (in index but not in fresh) -> propagate delete.
    let gone: Vec<String> =
        index.entries.keys().filter(|k| !fresh.entries.contains_key(*k)).cloned().collect();
    for rel in gone {
        match delete_remote(client, node_id, caps, remote_root, &rel, index, opts).await {
            Ok(true) => println!("  delete {rel}"),
            Ok(false) => {}
            Err(e) => eprintln!("  WARN delete {rel}: {e}"),
        }
    }
    if opts.bidirectional {
        pull_remote(client, node_id, caps, remote_root, root, index, opts).await?;
    }
    println!("  reconciled ({pushed} pushed)");
    Ok(())
}

/// Chunk a file, ask the receiver which chunks it lacks, upload only those, then commit the
/// manifest. Returns `Some(n_new_chunks)` when a commit was sent (or planned, in dry-run), `None`
/// if the file was unchanged versus the index.
#[allow(clippy::too_many_arguments)]
async fn push_delta(
    client: &CeClient,
    node_id: &str,
    caps: &str,
    remote_root: &str,
    root: &Path,
    rel: &str,
    index: &mut Index,
    opts: &SyncdOpts,
) -> Result<Option<usize>> {
    let abs = root.join(rel);
    let bytes = std::fs::read(&abs).with_context(|| format!("read {}", abs.display()))?;
    let (cf, chunks) = chunk_bytes(&bytes);
    let meta = std::fs::metadata(&abs).ok();
    let mtime_ms = meta.as_ref().map(walk::mtime_ms).unwrap_or(0);
    let mode = meta.as_ref().map(walk::mode_of).unwrap_or(0);

    let remote = remote_join(remote_root, rel);
    let base_cid = index.base_cid(rel);

    if opts.dry_run {
        println!("  (dry-run) would commit {rel} ({} chunks)", cf.chunk_cids().len());
        return Ok(Some(cf.chunk_cids().len()));
    }

    // 1) have: which chunks does the receiver lack?
    let have_req = HaveReq { caps: caps.to_string(), chunks: cf.manifest.chunks.clone() };
    let reply = client
        .request(node_id, verb::HAVE, &serde_json::to_vec(&have_req)?, 60_000)
        .await?;
    let have: HaveResp = serde_json::from_slice(&reply)?;
    if !have.ok {
        return Err(anyhow!("have refused: {}", have.error.unwrap_or_default()));
    }
    let missing = plan_transfer(&cf.manifest.chunks, &have.missing);

    // 2) upload missing chunks BEFORE committing (blob-retention caveat: chunks must be present and
    //    DHT-announced before the receiver pulls them).
    let n_new = upload_missing(client, &chunks, &missing).await?;

    // 3) commit the manifest.
    let commit = CommitReq {
        caps: caps.to_string(),
        path: remote,
        file_cid: cf.file_cid.clone(),
        manifest: cf.manifest.clone(),
        base_cid: base_cid.clone(),
        mode,
        mtime_ms,
        policy: Some(policy_str(opts.conflict).to_string()),
    };
    let reply = client
        .request(node_id, verb::COMMIT, &serde_json::to_vec(&commit)?, 120_000)
        .await?;
    let resp: CommitResp = serde_json::from_slice(&reply)?;
    if !resp.ok {
        return Err(anyhow!("commit refused: {}", resp.error.unwrap_or_default()));
    }

    // Update the local index + the last-acked remote state.
    index.upsert(IndexEntry {
        rel_path: rel.to_string(),
        file_cid: cf.file_cid.clone(),
        size: cf.size(),
        mtime_ms,
        mode,
        chunks: cf.manifest.chunks.clone(),
    });
    if resp.conflict {
        // Receiver kept its own version (or LWW chose it); record the remote's winning cid as base.
        if let Some(rc) = &resp.remote_cid {
            index.set_remote_seen(rel, rc, resp.remote_mtime_ms);
        }
        if let Some(copy) = &resp.conflict_copy {
            println!("  ! conflict {rel} -> receiver kept its copy; wrote {copy}");
        } else {
            println!("  ! conflict {rel}");
        }
    } else {
        index.set_remote_seen(rel, &cf.file_cid, mtime_ms);
    }
    Ok(Some(n_new))
}

/// Send a `sync2/delete` for a path and drop it from the index.
async fn delete_remote(
    client: &CeClient,
    node_id: &str,
    caps: &str,
    remote_root: &str,
    rel: &str,
    index: &mut Index,
    opts: &SyncdOpts,
) -> Result<bool> {
    if opts.dry_run {
        println!("  (dry-run) would delete {rel}");
        return Ok(true);
    }
    let req = DeleteReq {
        caps: caps.to_string(),
        path: remote_join(remote_root, rel),
        base_cid: index.base_cid(rel),
    };
    let reply = client
        .request(node_id, verb::DELETE, &serde_json::to_vec(&req)?, 60_000)
        .await?;
    let resp: DeleteResp = serde_json::from_slice(&reply)?;
    if !resp.ok {
        return Err(anyhow!("delete refused: {}", resp.error.unwrap_or_default()));
    }
    index.remove(rel);
    index.remote_seen.remove(rel);
    Ok(resp.deleted)
}

/// Pull remote-only / remote-changed files (bidirectional), chunk-level. Lists the remote subtree,
/// and for each entry whose CID differs from our local file, fetches the remote *manifest* (the
/// `sync2/manifest` verb), then reassembles the file fetching ONLY the chunks we do not already
/// hold (via the content-addressed blob store) — a one-chunk-different remote file costs one chunk,
/// not a whole-file transfer. The reassembled bytes are verified against the remote `file_cid` and
/// written atomically.
async fn pull_remote(
    client: &CeClient,
    node_id: &str,
    caps: &str,
    remote_root: &str,
    root: &Path,
    index: &mut Index,
    _opts: &SyncdOpts,
) -> Result<()> {
    let req = ListReq { caps: caps.to_string(), prefix: remote_root.to_string() };
    let reply = client.request(node_id, verb::LIST, &serde_json::to_vec(&req)?, 60_000).await?;
    let resp: ListResp = serde_json::from_slice(&reply)?;
    if !resp.ok {
        return Err(anyhow!("list refused: {}", resp.error.unwrap_or_default()));
    }
    for entry in resp.entries {
        let Some(rel) = strip_remote_root(remote_root, &entry.path) else { continue };
        let have_local = index.entries.get(rel).map(|e| e.file_cid.as_str());
        if have_local == Some(entry.file_cid.as_str()) {
            continue; // already in sync
        }
        match pull_one(client, node_id, caps, remote_root, root, rel, index).await {
            Ok(true) => println!("  down   {rel}  (chunked)"),
            Ok(false) => {}
            Err(e) => eprintln!("  WARN pull {rel}: {e}"),
        }
    }
    Ok(())
}

/// Chunk-level pull of one remote file at `rel`. Fetches the remote manifest, reassembles fetching
/// only chunks not already in the local blob store (the chunk CIDs the local index records as held
/// from prior pushes/pulls), verifies against the remote file CID, and writes atomically. Returns
/// `true` if a file was written, `false` if the remote no longer has the file (treated as a no-op;
/// deletes are reconciled separately).
async fn pull_one(
    client: &CeClient,
    node_id: &str,
    caps: &str,
    remote_root: &str,
    root: &Path,
    rel: &str,
    index: &mut Index,
) -> Result<bool> {
    let req = ManifestReq { caps: caps.to_string(), path: remote_join(remote_root, rel) };
    let reply = client.request(node_id, verb::MANIFEST, &serde_json::to_vec(&req)?, 60_000).await?;
    let resp: ManifestResp = serde_json::from_slice(&reply)?;
    if !resp.ok {
        return Err(anyhow!("manifest refused: {}", resp.error.unwrap_or_default()));
    }
    let Some(manifest) = resp.manifest.filter(|_| resp.found) else {
        return Ok(false); // remote no longer has the file
    };
    // Chunks we already hold locally (recorded in the index from earlier transfers): these resolve
    // local-first and never re-transfer. Everything else is a genuine fetch.
    let held: HashSet<String> = index.entries.get(rel).map(|e| e.chunks.iter().cloned().collect()).unwrap_or_default();
    let (bytes, _n_fetched) =
        rdev::delta::pull_file_verified(client, &manifest, &resp.file_cid, &held).await?;

    let abs = root.join(rel);
    if let Some(p) = abs.parent() {
        std::fs::create_dir_all(p).ok();
    }
    atomic_write(&abs, &bytes)?;
    index.upsert(IndexEntry {
        rel_path: rel.to_string(),
        file_cid: resp.file_cid.clone(),
        size: bytes.len() as u64,
        mtime_ms: resp.mtime_ms,
        mode: resp.mode,
        chunks: manifest.chunks.clone(),
    });
    index.set_remote_seen(rel, &resp.file_cid, resp.mtime_ms);
    Ok(true)
}

fn strip_remote_root<'a>(remote_root: &str, path: &'a str) -> Option<&'a str> {
    if remote_root.is_empty() {
        return Some(path);
    }
    path.strip_prefix(remote_root).map(|s| s.trim_start_matches('/'))
}

fn remote_join(remote_root: &str, rel: &str) -> String {
    if remote_root.is_empty() {
        rel.to_string()
    } else {
        format!("{remote_root}/{rel}")
    }
}

/// Write bytes to `path` atomically: temp file + fsync + rename.
///
/// Cross-platform note: `std::fs::rename` replaces the destination on every supported OS — on
/// Windows it maps to `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`, so the rename-over-existing is
/// atomic there too. The one Windows-specific caveat is that the rename fails with a sharing
/// violation if another process holds an open handle to `path` (e.g. an editor mid-write or an
/// antivirus scanner). That surfaces here as a normal `Err` (reported as `WARN <rel>` by the caller
/// and retried on the next sync pass) rather than silent corruption, which is the safe outcome.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("rdev-tmp");
    {
        let mut f = std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

// ----- server -----

async fn serve(client: &CeClient) -> Result<()> {
    let host_hex = client.status().await?.node_id;
    let host_id: [u8; 32] = hex::decode(&host_hex).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("bad node id"))?;
    let home = dirs_next::home_dir().unwrap_or_else(std::env::temp_dir);
    // Accepted capability roots: chains rooted at any of these (or at this host's own key) are
    // honored. Empty by default (only self-issued caps). An org/fleet sets a shared root here so
    // a seed can delegate attenuated caps down a replication tree that every node accepts.
    let roots = load_roots();
    let host_short = host_hex[..16].to_string();
    println!(
        "rdev serving as {}… (rdev/sync, rdev/delete, rdev/exec, rdev/spawn, rdev/sync2/*) — {} configured root(s)",
        host_short,
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
            // Auto-Sync v2 verbs return their own JSON shapes (not the generic `Resp`) and need the
            // node client (blob store) + the home tree state, so they are dispatched separately.
            let reply_bytes = if m.topic.starts_with(rdev::syncproto::TOPIC_PREFIX) {
                handle_sync2(client, &m.topic, &m.from, &m.payload_hex, &host_id, &roots, &revoked, &home, &host_short).await
            } else {
                let resp = handle(&m.topic, &m.from, &m.payload_hex, &host_id, &roots, &revoked, &home).await;
                serde_json::to_vec(&resp).unwrap_or_default()
            };
            let _ = client.reply(token, &reply_bytes).await;
        }
        // TODO(M5): switch from polling `messages()` to SSE `GET /mesh/messages/stream`. The node
        // already exposes that endpoint, but `ce-rs` does not yet wrap it as a `messages_stream()`
        // method (confirmed against the pinned ce-rs: only `messages()` exists — see ce-rs Cargo
        // lock rev). When ce-rs grows `messages_stream()`, replace this 500ms poll with a stream
        // consumer to remove the latency ceiling and the best-effort-ring drop risk. Idempotent
        // verbs + reconcile-on-start already recover any message the poll misses, so polling is
        // correct (only higher-latency) for v1.
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
        .unwrap_or_else(|| {
            // Join components individually so the path renders with the platform separator
            // (a literal ".local/share/ce/roots" in one `join` keeps forward slashes on Windows).
            dirs_next::home_dir()
                .unwrap_or_default()
                .join(".local")
                .join("share")
                .join("ce")
                .join("roots")
        });
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

// ----- Auto-Sync v2 server-side verb handlers (rdev/sync2/*) -----

/// Authorize a sync2 request's `caps` chain for the topic's action, returning the decoded chain so
/// the caller can enforce the `path_prefix` caveat. `have`/`list` map to the `sync-read` ability;
/// `commit`/`delete` to `sync`/`delete` (the abilities rdev already grants).
fn authorize_sync2(
    topic: &str,
    caps: &str,
    from_hex: &str,
    host_id: &[u8; 32],
    roots: &[[u8; 32]],
    revoked: &HashSet<([u8; 32], u64)>,
) -> Result<Vec<SignedCapability>> {
    let action = action_for(topic).ok_or_else(|| anyhow!("unknown sync2 verb"))?;
    let from: [u8; 32] = hex::decode(from_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("bad sender id"))?;
    let chain: Vec<SignedCapability> = decode_chain(caps).map_err(|_| anyhow!("bad capability"))?;
    let is_revoked = |issuer: &[u8; 32], nonce: u64| revoked.contains(&(*issuer, nonce));
    authorize(host_id, roots, &[], now(), &from, action, &chain, &is_revoked)
        .map_err(|e| anyhow!("denied: {e}"))?;
    Ok(chain)
}

/// Boundary-aware `path_prefix` caveat check. A raw `starts_with` admits sibling paths that merely
/// share a textual prefix (scope `proj` would admit `project-secret/x`). Match on a path component
/// boundary instead: the prefix admits `path` iff the prefix is empty, equals `path`, or `path`
/// begins with `prefix` followed by a `/`. Trailing slashes on the prefix are normalized away first
/// (a `code/` caveat and a `code` caveat are equivalent). Defense-in-depth only — the `..`-reject and
/// canonicalize-under-`home` checks are the real containment — but this layer should be tight too.
fn prefix_admits(prefix: &str, path: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    prefix.is_empty()
        || path == prefix
        || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

/// Enforce path safety for a sync2 `path`: reject `..` traversal and require the `path_prefix`
/// caveat (if present on the cap) to be a prefix. Returns the absolute target under `home`.
fn safe_target(path: &str, chain: &[SignedCapability], home: &Path) -> Result<PathBuf> {
    if path.contains("..") {
        return Err(anyhow!("path traversal not allowed"));
    }
    // Wire paths are forward-slash and relative. Reject anything that would make `home.join(path)`
    // absolute and escape `home`: a leading '/', a backslash (Windows separator), or a drive prefix
    // like `C:`. On unix `home.join("/etc/x")` discards `home`; on Windows `home.join("C:\\x")` or a
    // backslash component does the same — this guard closes both before the join.
    if is_unsafe_wire_path(path) {
        return Err(anyhow!("absolute or non-forward-slash path not allowed"));
    }
    if let Some(prefix) = chain.last().and_then(|c| c.cap.caveats.path_prefix.as_ref()) {
        if !prefix_admits(prefix, path) {
            return Err(anyhow!("path outside capability prefix '{prefix}'"));
        }
    }
    let home_canon = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let target = home.join(path);
    if let Some(p) = target.parent() {
        std::fs::create_dir_all(p).ok();
        let canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        if !canon.starts_with(&home_canon) {
            return Err(anyhow!("path traversal not allowed"));
        }
    }
    Ok(target)
}

/// True if a wire `path` is unsafe to join under `home`: absolute (leading '/'), containing a
/// backslash (the Windows separator — wire paths are always forward-slash), or carrying a Windows
/// drive/UNC prefix (`C:`, `\\`). Forward-slash relative paths pass unchanged on every platform.
fn is_unsafe_wire_path(path: &str) -> bool {
    if path.starts_with('/') || path.contains('\\') {
        return true;
    }
    // A `<letter>:` drive prefix (e.g. "C:foo", "C:/foo") would escape the join on Windows.
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Dispatch a `rdev/sync2/*` verb, returning the raw JSON reply bytes (each verb has its own shape).
#[allow(clippy::too_many_arguments)]
async fn handle_sync2(
    client: &CeClient,
    topic: &str,
    from_hex: &str,
    payload_hex: &str,
    host_id: &[u8; 32],
    roots: &[[u8; 32]],
    revoked: &HashSet<([u8; 32], u64)>,
    home: &Path,
    host_short: &str,
) -> Vec<u8> {
    let res = handle_sync2_inner(client, topic, from_hex, payload_hex, host_id, roots, revoked, home, host_short).await;
    match res {
        Ok(bytes) => bytes,
        Err(e) => {
            // Best-effort generic error reply (the client decodes per-verb; all share ok/error).
            serde_json::to_vec(&serde_json::json!({ "ok": false, "error": e.to_string() }))
                .unwrap_or_default()
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_sync2_inner(
    client: &CeClient,
    topic: &str,
    from_hex: &str,
    payload_hex: &str,
    host_id: &[u8; 32],
    roots: &[[u8; 32]],
    revoked: &HashSet<([u8; 32], u64)>,
    home: &Path,
    host_short: &str,
) -> Result<Vec<u8>> {
    let raw = hex::decode(payload_hex).context("payload hex")?;
    match topic {
        verb::HAVE => {
            let req: HaveReq = serde_json::from_slice(&raw).context("have json")?;
            authorize_sync2(topic, &req.caps, from_hex, host_id, roots, revoked)?;
            // A chunk is "held" if the local blob store returns it. (get_blob is local-first.)
            let mut missing = Vec::new();
            let mut checked: HashSet<&String> = HashSet::new();
            for c in &req.chunks {
                if !checked.insert(c) {
                    continue;
                }
                if client.get_blob(c).await.is_err() {
                    missing.push(c.clone());
                }
            }
            Ok(serde_json::to_vec(&HaveResp { ok: true, error: None, missing })?)
        }
        verb::COMMIT => {
            let req: CommitReq = serde_json::from_slice(&raw).context("commit json")?;
            let chain = authorize_sync2(topic, &req.caps, from_hex, host_id, roots, revoked)?;
            let target = safe_target(&req.path, &chain, home)?;

            // Reassemble + verify from the blob store (local hit else mesh fetch-by-hash).
            let bytes = apply_commit_verified(client, &req.manifest, &req.file_cid).await?;

            // Conflict detection against the receiver's current file.
            let local_bytes = std::fs::read(&target).ok();
            let local_cid = local_bytes.as_ref().map(|b| rdev::chunk::content_id(b));
            let local_mtime = std::fs::metadata(&target).ok().map(|m| walk::mtime_ms(&m)).unwrap_or(0);
            let input = ConflictInput {
                rel_path: &req.path,
                local_cid: local_cid.as_deref(),
                local_mtime_ms: local_mtime,
                incoming_cid: &req.file_cid,
                incoming_mtime_ms: req.mtime_ms,
                base_cid: req.base_cid.as_deref(),
                initiator_short: host_short,
            };
            // Honor the initiator's chosen conflict policy (default LWW when absent / unparseable).
            // Every policy preserves the loser as a conflict copy, so the receiver never silently
            // loses data regardless of what the initiator requested.
            let policy = req
                .policy
                .as_deref()
                .and_then(|s| s.parse::<Policy>().ok())
                .unwrap_or(Policy::Lww);
            let resolution = resolve_conflict(policy, &input);
            // Make the committed bytes fetchable by file_cid too (so bidir pull can `get_blob` it).
            let _ = client.put_blob(bytes.clone()).await;

            let resp = apply_resolution(&target, &req.path, &bytes, &local_bytes, resolution, local_cid.as_deref(), local_mtime)?;
            Ok(serde_json::to_vec(&resp)?)
        }
        verb::DELETE => {
            let req: DeleteReq = serde_json::from_slice(&raw).context("delete json")?;
            let chain = authorize_sync2(topic, &req.caps, from_hex, host_id, roots, revoked)?;
            let target = safe_target(&req.path, &chain, home)?;
            // Conflict: receiver's current file differs from the base the initiator assumed.
            let local_cid = std::fs::read(&target).ok().map(|b| rdev::chunk::content_id(&b));
            let conflict = match (&local_cid, &req.base_cid) {
                (Some(l), Some(b)) if !b.is_empty() => l != b,
                _ => false,
            };
            if conflict {
                return Ok(serde_json::to_vec(&DeleteResp {
                    ok: true,
                    error: None,
                    deleted: false,
                    conflict: true,
                    remote_cid: local_cid,
                })?);
            }
            match std::fs::remove_file(&target) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(anyhow!("delete failed: {e}")),
            }
            Ok(serde_json::to_vec(&DeleteResp { ok: true, error: None, deleted: true, conflict: false, remote_cid: None })?)
        }
        verb::LIST => {
            let req: ListReq = serde_json::from_slice(&raw).context("list json")?;
            let chain = authorize_sync2(topic, &req.caps, from_hex, host_id, roots, revoked)?;
            // The list is scoped to the prefix; enforce the path_prefix caveat on the prefix too.
            if req.prefix.contains("..") {
                return Err(anyhow!("path traversal not allowed"));
            }
            if let Some(p) = chain.last().and_then(|c| c.cap.caveats.path_prefix.as_ref()) {
                if !prefix_admits(p, &req.prefix) && !prefix_admits(&req.prefix, p) {
                    return Err(anyhow!("prefix outside capability"));
                }
            }
            let base = home.join(&req.prefix);
            let entries = list_subtree(&base, &req.prefix);
            Ok(serde_json::to_vec(&ListResp { ok: true, error: None, entries })?)
        }
        verb::MANIFEST => {
            let req: ManifestReq = serde_json::from_slice(&raw).context("manifest json")?;
            let chain = authorize_sync2(topic, &req.caps, from_hex, host_id, roots, revoked)?;
            let target = safe_target(&req.path, &chain, home)?;
            // Read + chunk the file. Absent file -> found:false (the puller treats it as a delete).
            let bytes = match std::fs::read(&target) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(serde_json::to_vec(&ManifestResp { ok: true, found: false, ..Default::default() })?);
                }
                Err(e) => return Err(anyhow!("read failed: {e}")),
            };
            let (cf, chunks) = chunk_bytes(&bytes);
            // Publish each chunk to the blob store so the puller can fetch the missing ones by CID
            // (the puller skips chunks it already holds; only genuinely-missing chunks transfer).
            for (cid, chunk) in &chunks {
                let got = client.put_blob(chunk.clone()).await?;
                if &got != cid {
                    return Err(anyhow!("blob store returned cid {got}, expected {cid}"));
                }
            }
            let meta = std::fs::metadata(&target).ok();
            let mode = meta.as_ref().map(walk::mode_of).unwrap_or(0);
            let mtime_ms = meta.as_ref().map(walk::mtime_ms).unwrap_or(0);
            Ok(serde_json::to_vec(&ManifestResp {
                ok: true,
                error: None,
                found: true,
                file_cid: cf.file_cid,
                manifest: Some(cf.manifest),
                mode,
                mtime_ms,
            })?)
        }
        other => Err(anyhow!("unknown sync2 verb '{other}'")),
    }
}

/// Apply a conflict resolution to disk and build the `commit` reply.
fn apply_resolution(
    target: &Path,
    rel_path: &str,
    incoming: &[u8],
    local_bytes: &Option<Vec<u8>>,
    resolution: Resolution,
    local_cid: Option<&str>,
    local_mtime: u64,
) -> Result<CommitResp> {
    match resolution {
        Resolution::TakeIncoming { conflict_copy } => {
            // Preserve the loser (previous local bytes) as a conflict copy, if any.
            let copy_rel = if let (Some(copy), Some(prev)) = (&conflict_copy, local_bytes) {
                let copy_abs = sibling(target, rel_path, copy);
                atomic_write(&copy_abs, prev)?;
                Some(copy.clone())
            } else {
                None
            };
            atomic_write(target, incoming)?;
            Ok(CommitResp {
                ok: true,
                applied: true,
                conflict: conflict_copy.is_some(),
                conflict_copy: copy_rel,
                remote_cid: None,
                remote_mtime_ms: 0,
                error: None,
            })
        }
        Resolution::KeepLocal { conflict_copy } => {
            // Keep local; the incoming loser lands as a conflict copy.
            let copy_abs = sibling(target, rel_path, &conflict_copy);
            atomic_write(&copy_abs, incoming)?;
            Ok(CommitResp {
                ok: true,
                applied: false,
                conflict: true,
                conflict_copy: Some(conflict_copy),
                remote_cid: local_cid.map(|s| s.to_string()),
                remote_mtime_ms: local_mtime,
                error: None,
            })
        }
        Resolution::Merged { merged } => {
            atomic_write(target, &merged)?;
            Ok(CommitResp { ok: true, applied: true, ..Default::default() })
        }
    }
}

/// Given a `target` absolute path and its `rel_path`, plus a `copy_rel` (relative to the same root),
/// compute the conflict-copy absolute path (same root as target).
fn sibling(target: &Path, rel_path: &str, copy_rel: &str) -> PathBuf {
    // target = root/rel_path  =>  root = target with rel_path stripped.
    let comps = rel_path.matches('/').count() + 1;
    let mut root = target.to_path_buf();
    for _ in 0..comps {
        root = root.parent().map(|p| p.to_path_buf()).unwrap_or(root);
    }
    root.join(copy_rel)
}

/// Walk a subtree under `base` and return [`ListEntry`] for every regular file, with `path` made
/// relative to `home` (i.e. prefixed by `prefix`). Used by `rdev/sync2/list` for bidir reconcile.
fn list_subtree(base: &Path, prefix: &str) -> Vec<ListEntry> {
    let mut out = Vec::new();
    for entry in WalkDir::new(base).follow_links(false).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else { continue };
        let rel = entry.path().strip_prefix(base).ok().map(|r| {
            r.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/")
        });
        let Some(rel) = rel else { continue };
        let path = if prefix.is_empty() { rel.clone() } else { format!("{}/{}", prefix.trim_end_matches('/'), rel) };
        let meta = entry.metadata().ok();
        out.push(ListEntry {
            path,
            file_cid: rdev::chunk::content_id(&bytes),
            mtime_ms: meta.as_ref().map(walk::mtime_ms).unwrap_or(0),
            mode: meta.as_ref().map(walk::mode_of).unwrap_or(0),
        });
    }
    out
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
                if !prefix_admits(prefix, c) {
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
    #[cfg(unix)]
    let default_path = "/usr/bin:/bin";
    #[cfg(windows)]
    // On Windows the program loader needs the System32 directory on PATH to resolve core DLLs and
    // built-in commands; a bare `/usr/bin:/bin` would render most allow-listed programs unspawnable.
    let default_path = "C:\\Windows\\System32;C:\\Windows";
    let path_env = std::env::var("PATH").unwrap_or_else(|_| default_path.to_string());
    let mut command = std::process::Command::new(&cmd[0]);
    command
        .args(&cmd[1..])
        .current_dir(&cwd)
        .env_clear()
        .env("PATH", path_env)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // Home is `HOME` on unix, `USERPROFILE` on Windows. Set both so the child's tooling resolves the
    // confined home regardless of platform (the unscrubbed counterpart would otherwise be missing).
    #[cfg(unix)]
    command.env("HOME", &cwd);
    #[cfg(windows)]
    command.env("USERPROFILE", &cwd);
    let child = command.spawn().with_context(|| format!("spawn '{}'", cmd[0]))?;
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
    if is_unsafe_wire_path(&req.path) {
        return Err(anyhow!("absolute or non-forward-slash path not allowed"));
    }
    if let Some(prefix) = chain.last().and_then(|c| c.cap.caveats.path_prefix.as_ref()) {
        if !prefix_admits(prefix, &req.path) {
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

    // ----- syncd helpers (Auto-Sync v2) -----

    #[test]
    fn remote_root_normalizes() {
        assert_eq!(remote_root_of("~/proj/"), "proj");
        assert_eq!(remote_root_of("/abs/dir"), "abs/dir");
        assert_eq!(remote_root_of("~"), "");
        assert_eq!(remote_root_of("plain"), "plain");
    }

    #[test]
    fn remote_join_and_strip_roundtrip() {
        assert_eq!(remote_join("proj", "src/a.rs"), "proj/src/a.rs");
        assert_eq!(remote_join("", "a.rs"), "a.rs");
        assert_eq!(strip_remote_root("proj", "proj/src/a.rs"), Some("src/a.rs"));
        assert_eq!(strip_remote_root("", "a.rs"), Some("a.rs"));
        assert_eq!(strip_remote_root("proj", "other/a.rs"), None);
    }

    #[test]
    fn sibling_computes_conflict_copy_path() {
        // target = /home/proj/src/a.rs ; rel = proj/src/a.rs ; copy rel = proj/src/a.conflict.rs
        let target = Path::new("/home/proj/src/a.rs");
        let s = sibling(target, "proj/src/a.rs", "proj/src/a.conflict.rs");
        assert_eq!(s, Path::new("/home/proj/src/a.conflict.rs"));
    }

    #[test]
    fn list_subtree_reports_files_with_cids() {
        let base = tmp_home("list-sub");
        std::fs::create_dir_all(base.join("d")).unwrap();
        std::fs::write(base.join("a.txt"), b"hello").unwrap();
        std::fs::write(base.join("d/b.txt"), b"world").unwrap();
        let entries = list_subtree(&base, "proj");
        let mut paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths, vec!["proj/a.txt", "proj/d/b.txt"]);
        // file_cid matches sha256.
        let a = entries.iter().find(|e| e.path == "proj/a.txt").unwrap();
        assert_eq!(a.file_cid, rdev::chunk::content_id(b"hello"));
    }

    #[test]
    fn unsafe_wire_path_rejects_absolute_backslash_and_drive() {
        // Legitimate forward-slash relative paths are accepted on every platform.
        assert!(!is_unsafe_wire_path("src/main.rs"));
        assert!(!is_unsafe_wire_path("a.txt"));
        // Absolute, backslash, and drive-prefixed paths are rejected (Windows-escape hardening).
        assert!(is_unsafe_wire_path("/etc/passwd"));
        assert!(is_unsafe_wire_path("..\\evil"));
        assert!(is_unsafe_wire_path("sub\\file.txt"));
        assert!(is_unsafe_wire_path("C:\\Windows\\System32"));
        assert!(is_unsafe_wire_path("C:/Windows"));
        assert!(is_unsafe_wire_path("d:rel"));
    }

    #[test]
    fn safe_target_rejects_traversal_and_enforces_prefix() {
        let home = tmp_home("safe-tgt");
        let chain: Vec<SignedCapability> = vec![];
        assert!(safe_target("../escape", &chain, &home).is_err());
        // with a path_prefix caveat
        let host = id("safe-host");
        let aud = id("safe-aud");
        let token = cap(&host, aud.node_id(), &["sync"], Some("code/"), 0);
        let chain = decode_chain(&token).unwrap();
        assert!(safe_target("code/a.rs", &chain, &home).is_ok());
        assert!(safe_target("secrets.txt", &chain, &home).is_err());
    }

    #[test]
    fn prefix_admits_respects_component_boundary() {
        // Empty prefix admits everything.
        assert!(prefix_admits("", "anything/x"));
        // Exact match and proper descendants are admitted.
        assert!(prefix_admits("proj", "proj"));
        assert!(prefix_admits("proj", "proj/a"));
        assert!(prefix_admits("proj/", "proj/a")); // trailing slash normalized
        // Sibling sharing a textual prefix is NOT admitted (the boundary bug).
        assert!(!prefix_admits("proj", "project-secret/x"));
        assert!(!prefix_admits("proj", "projx"));
    }

    #[test]
    fn safe_target_prefix_denies_sibling_prefix() {
        // Regression for Theme A: scope `proj` must NOT admit `project-secret/x` (raw starts_with
        // would), while still allowing the legitimate `proj/a`.
        let home = tmp_home("safe-tgt-boundary");
        let host = id("safe-boundary-host");
        let aud = id("safe-boundary-aud");
        let token = cap(&host, aud.node_id(), &["sync"], Some("proj"), 0);
        let chain = decode_chain(&token).unwrap();
        assert!(safe_target("proj/a", &chain, &home).is_ok());
        assert!(safe_target("project-secret/x", &chain, &home).is_err());
    }

    // ----- sync2 verb handlers (capability + path safety, no live node needed) -----

    fn empty_revoked() -> std::collections::HashSet<([u8; 32], u64)> {
        std::collections::HashSet::new()
    }

    #[tokio::test]
    async fn sync2_have_denies_without_capability() {
        // A have request with a cap that only grants `sync` (not `sync-read`) is denied for the
        // read verb. (We don't need a live node: authorization fails before any blob call.)
        let host = id("s2-have-host");
        let sender = id("s2-have-sender");
        let token = cap(&host, sender.node_id(), &["sync"], None, 0); // no sync-read
        let chain = decode_chain(&token).unwrap();
        let _ = chain;
        let res = authorize_sync2(
            verb::HAVE,
            &token,
            &hex::encode(sender.node_id()),
            &host.node_id(),
            &[],
            &empty_revoked(),
        );
        assert!(res.is_err(), "have requires sync-read");
    }

    #[tokio::test]
    async fn sync2_commit_authorizes_with_sync_ability() {
        let host = id("s2-commit-host");
        let sender = id("s2-commit-sender");
        let token = cap(&host, sender.node_id(), &["sync"], None, 0);
        let chain = authorize_sync2(
            verb::COMMIT,
            &token,
            &hex::encode(sender.node_id()),
            &host.node_id(),
            &[],
            &empty_revoked(),
        )
        .unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn apply_resolution_take_incoming_writes_and_preserves_loser() {
        let home = tmp_home("apply-take");
        let rel = "x.md";
        let target = home.join(rel);
        std::fs::write(&target, b"old-local").unwrap();
        let local = Some(b"old-local".to_vec());
        let res = Resolution::TakeIncoming { conflict_copy: Some("x.conflict-n-1.md".into()) };
        let resp = apply_resolution(&target, rel, b"new-incoming", &local, res, Some("oldcid"), 5).unwrap();
        assert!(resp.applied);
        assert_eq!(std::fs::read(&target).unwrap(), b"new-incoming");
        // loser preserved as conflict copy
        assert_eq!(std::fs::read(home.join("x.conflict-n-1.md")).unwrap(), b"old-local");
    }

    #[test]
    fn apply_resolution_keep_local_writes_incoming_as_copy() {
        let home = tmp_home("apply-keep");
        let rel = "y.md";
        let target = home.join(rel);
        std::fs::write(&target, b"my-local").unwrap();
        let local = Some(b"my-local".to_vec());
        let res = Resolution::KeepLocal { conflict_copy: "y.conflict-n-2.md".into() };
        let resp = apply_resolution(&target, rel, b"their-incoming", &local, res, Some("localcid"), 7).unwrap();
        assert!(!resp.applied);
        assert!(resp.conflict);
        assert_eq!(std::fs::read(&target).unwrap(), b"my-local", "local preserved");
        assert_eq!(std::fs::read(home.join("y.conflict-n-2.md")).unwrap(), b"their-incoming");
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_tmp() {
        let home = tmp_home("atomic-w");
        let p = home.join("f.bin");
        atomic_write(&p, b"first").unwrap();
        atomic_write(&p, b"second").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"second");
        assert!(!p.with_extension("rdev-tmp").exists());
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

    #[test]
    fn fs_prefix_denies_sibling_prefix() {
        // Regression for Theme A at the fs_action call site: a cap scoped to "proj" must NOT admit
        // the sibling "project-secret/x" (a raw starts_with would), while still allowing "proj/a".
        let home = tmp_home("fs-sibling-prefix");
        let host = id("fs-sib-host");
        let aud = id("fs-sib-aud");
        let token = cap(&host, aud.node_id(), &["sync"], Some("proj"), 0);
        let chain = decode_chain(&token).unwrap();
        let inside = Req { caps: token.clone(), path: "proj/a.txt".into(), data_hex: Some(hex::encode(b"y")), ..Default::default() };
        assert!(fs_action("sync", &inside, &chain, &home).unwrap().ok);
        let sibling = Req { caps: token, path: "project-secret/x".into(), data_hex: Some(hex::encode(b"y")), ..Default::default() };
        assert!(fs_action("sync", &sibling, &chain, &home).is_err(), "sibling prefix must be denied");
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
    /// concurrent tests setting the same env var don't disagree. The shell differs per OS (`sh` on
    /// unix, `cmd` on Windows) so the spawn tests run identically on every platform.
    fn allow_spawn() {
        #[cfg(unix)]
        let allow = "sh,true";
        #[cfg(windows)]
        let allow = "cmd,true";
        unsafe { std::env::set_var("RDEV_SPAWN_ALLOW", allow) };
    }

    /// Build a `cmd` vector that writes `text` into the file `rel` (under the spawn cwd), using the
    /// platform shell. Unix: `sh -c "echo text > rel"`. Windows: `cmd /C "echo text> rel"`.
    fn shell_write(text: &str, rel: &str) -> Vec<String> {
        #[cfg(unix)]
        {
            vec!["sh".into(), "-c".into(), format!("echo {text} > {rel}")]
        }
        #[cfg(windows)]
        {
            // No space before `>` on Windows: `echo foo > f` writes a trailing space; `echo foo> f`
            // does not. The marker-existence assertions only check the file is created, but keep it
            // tidy regardless.
            vec!["cmd".into(), "/C".into(), format!("echo {text}> {rel}")]
        }
    }

    #[tokio::test]
    async fn spawn_authorized_runs_host_process() {
        allow_spawn();
        let home = tmp_home("spawn-ok");
        let _ = std::fs::remove_file(home.join("spawned_marker"));
        let host = id("spawn-ok-host");
        let sender = id("spawn-ok-sender");
        let token = cap(&host, sender.node_id(), &["spawn"], None, 0);
        let req = Req { caps: token, cmd: Some(shell_write("hi", "spawned_marker")), ..Default::default() };
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
        let req = Req { caps: token, cmd: Some(shell_write("pwned", "pwned")), ..Default::default() };
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
        allow_spawn(); // allows the platform shell + `true` — but NOT `echo`
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
        let req = Req { caps: token, cmd: Some(shell_write("ok", "deleg_marker")), ..Default::default() };
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
        let req = Req { caps: token, cmd: Some(shell_write("pwn", "pwn")), ..Default::default() };
        let err = handle_inner("rdev/spawn", &hex::encode(mid.node_id()), &payload(&req), &host.node_id(), &[root.node_id()], &std::collections::HashSet::new(), &home).await.unwrap_err();
        assert!(err.to_string().contains("denied"));
        assert!(!home.join("pwn").exists());
    }
}
