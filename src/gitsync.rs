//! ce-gitsync (native): real-time git sync over the CE mesh. Event-driven via `notify`
//! (fsevents/inotify) so it's instant and scales to the whole workspace without polling. A single
//! static binary — no python interpreter, no launchd fsevents sandbox issues.
//!
//! Per repo under `root` (the nesting `root` repo itself is skipped): on a file change we auto-commit
//! and push a delta git bundle INLINE over the reliable mesh message path; the peer fetches + merges.
//! Multi-peer: every linked device (from ce-link) is a peer; we push to and receive from all of them.

use anyhow::{Context, Result};
use ce_rs::CeClient;
use notify::{RecursiveMode, Watcher};
use rdev::conflict::{is_mergeable_text, merge3, Merge3};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const IGNORE: &[&str] = &[
    "/.git/", "/target/", "/target-", "/node_modules/", "/.cargo-shared/", "/.cargo/", "/dist/",
    "/build/", "/.next/", "/.svelte-kit/", "/.worktrees/", "/__pycache__/",
];
// Loose content (files not in any git repo) is synced as plain files with our own 3-way merge — NOT
// by making folders into repos. These path fragments are never synced (build output, caches, temps).
const LOOSE_IGNORE: &[&str] = &[
    "/.git", "/target", "/node_modules/", "/.cargo-shared/", "/.cargo/", "/dist/", "/build/",
    "/.next/", "/.svelte-kit/", "/.worktrees/", "/__pycache__/", "/.ce-gitsync/", "/tmp/", "/trash/",
    "/.cache/", "/.claude_tmp/", "/scratchpad/", "/.DS_Store",
];
const INLINE_MAX: usize = 2 * 1024 * 1024; // hex-inline bundles up to this; skip larger (initial
                                           // bulk is done via `git clone` from origin, see setup).

#[derive(Serialize, Deserialize)]
struct FileMsg {
    rel: String,
    content: String, // hex of the raw bytes
}

#[derive(Serialize, Deserialize)]
struct Announce {
    repo: String,
    branch: String,
    head: String,
    bundle: String, // hex of the git bundle
}
#[derive(Serialize, Deserialize)]
struct Ack {
    repo: String,
    head: String,
}

struct Peer {
    name: String,
    node_id: String,
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let o = Command::new("git").arg("-C").arg(repo).args(args).output()
        .with_context(|| format!("spawn git {args:?}"))?;
    if !o.status.success() {
        anyhow::bail!("git {args:?}: {}", String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}
fn git_try(repo: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new("git").arg("-C").arg(repo).args(args).output().ok()?;
    if o.status.success() { Some(String::from_utf8_lossy(&o.stdout).trim().to_string()) } else { None }
}

/// Real git repos directly under `root` (excluding `root` itself, which nests them). We NEVER create
/// repos — folders that aren't already git repos are loose content and sync via the file-merge layer.
fn discover_repos(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && p.join(".git").exists() {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn repo_of(root: &Path, path: &Path) -> Option<PathBuf> {
    let mut p = path.to_path_buf();
    while p.starts_with(root) && p != *root {
        if p.join(".git").is_dir() {
            return Some(p);
        }
        p = p.parent()?.to_path_buf();
    }
    None
}

fn load_peers() -> Vec<Peer> {
    let path = dirs_next::home_dir().map(|h| h.join(".config/ce-link/links.json"));
    let Some(path) = path else { return vec![] };
    let Ok(data) = std::fs::read_to_string(path) else { return vec![] };
    let Ok(v): Result<serde_json::Value, _> = serde_json::from_str(&data) else { return vec![] };
    v.as_array().map(|a| a.iter().filter_map(|l| {
        Some(Peer { name: l.get("peer")?.as_str()?.to_string(), node_id: l.get("peerNodeId")?.as_str()?.to_string() })
    }).collect()).unwrap_or_default()
}

fn cur_branch(repo: &Path) -> Option<String> {
    git_try(repo, &["symbolic-ref", "--quiet", "--short", "HEAD"]).filter(|s| !s.is_empty())
}
fn head(repo: &Path) -> Option<String> {
    git_try(repo, &["rev-parse", "--verify", "--quiet", "HEAD"]).filter(|s| !s.is_empty())
}
fn is_dirty(repo: &Path) -> bool {
    git_try(repo, &["status", "--porcelain"]).map(|s| !s.is_empty()).unwrap_or(false)
}
fn peer_ref(name: &str) -> String { format!("refs/ce-gitsync/{name}") }
fn get_ref(repo: &Path, r: &str) -> Option<String> {
    git_try(repo, &["rev-parse", "--verify", "--quiet", r]).filter(|s| !s.is_empty())
}
fn set_ref(repo: &Path, r: &str, sha: &str) { let _ = git(repo, &["update-ref", r, sha]); }

fn auto_commit(repo: &Path, host: &str) -> bool {
    if !is_dirty(repo) { return false; }
    if git(repo, &["add", "-A"]).is_err() { return false; }
    let msg = format!("live: {host} {}", now_str());
    git(repo, &["-c", "user.name=ce-gitsync", "-c", "user.email=gitsync@ce-net",
        "commit", "--no-verify", "-q", "-m", &msg]).is_ok()
}

fn now_str() -> String {
    // seconds since epoch is enough to make the commit unique + ordered.
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs().to_string()).unwrap_or_default()
}

async fn push_repo(client: &CeClient, peer: &Peer, repo: &Path, root: &Path) -> Result<()> {
    let Some(branch) = cur_branch(repo) else { return Ok(()) };
    let Some(h) = head(repo) else { return Ok(()) };
    let rel = repo.strip_prefix(root).unwrap_or(repo).to_string_lossy().to_string();
    let base = get_ref(repo, &peer_ref(&peer.name));
    let tmp = std::env::temp_dir().join(format!("ce-gitsync-{}-{}.bundle", peer.name, h));
    let tmp_s = tmp.to_string_lossy().to_string();
    // Delta when we know an ancestor the peer has; else full branch (first contact).
    let made = if let Some(b) = base.as_deref() {
        if b == h { return Ok(()); } // peer already has our head
        if git(repo, &["merge-base", "--is-ancestor", b, "HEAD"]).is_ok() {
            git(repo, &["bundle", "create", &tmp_s, &format!("^{b}"), &branch]).is_ok()
        } else {
            git(repo, &["bundle", "create", &tmp_s, &branch]).is_ok()
        }
    } else {
        git(repo, &["bundle", "create", &tmp_s, &branch]).is_ok()
    };
    if !made { return Ok(()); }
    let bytes = std::fs::read(&tmp).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);
    if bytes.is_empty() || bytes.len() > INLINE_MAX {
        if bytes.len() > INLINE_MAX {
            eprintln!("gitsync: {rel} bundle {}B exceeds inline cap; clone it from origin on the peer", bytes.len());
        }
        return Ok(());
    }
    let ann = Announce { repo: rel.clone(), branch, head: h.clone(), bundle: hex::encode(&bytes) };
    client.send_message(&peer.node_id, "gitsync/announce", &serde_json::to_vec(&ann)?).await?;
    eprintln!("{}  push {rel} -> {}: {} ({}B)", now_str(), peer.name, &h[..8.min(h.len())], bytes.len());
    Ok(())
}

async fn recv_announce(client: &CeClient, peer: &Peer, payload_hex: &str, root: &Path, host: &str) -> Result<()> {
    let raw = hex::decode(payload_hex)?;
    let ann: Announce = serde_json::from_slice(&raw)?;
    let repo = root.join(&ann.repo);
    if !repo.join(".git").is_dir() {
        std::fs::create_dir_all(&repo).ok();
        git(&repo, &["init", "-q"])?; // full-clone: init, the fetch+checkout below populates it
    }
    let bytes = hex::decode(&ann.bundle)?;
    let tmp = std::env::temp_dir().join(format!("ce-gitsync-in-{}.bundle", &ann.head));
    std::fs::write(&tmp, &bytes)?;
    let incoming = format!("refs/ce-gitsync/incoming/{}", peer.name);
    let res = (|| -> Result<()> {
        git(&repo, &["fetch", "-q", &tmp.to_string_lossy(), &format!("{}:{}", ann.branch, incoming)])?;
        set_ref(&repo, &peer_ref(&peer.name), &ann.head);
        match head(&repo) {
            None => { // unborn -> adopt the peer's branch
                git(&repo, &["checkout", "-B", &ann.branch, &incoming])?;
                eprintln!("{}  pull {} <- {}: initialized {}", now_str(), ann.repo, peer.name, &ann.head[..8.min(ann.head.len())]);
            }
            Some(lh) if lh == ann.head => {}
            Some(_) => {
                if cur_branch(&repo).as_deref() != Some(ann.branch.as_str()) { return Ok(()); }
                if git(&repo, &["merge-base", "--is-ancestor", "HEAD", &incoming]).is_ok() {
                    git(&repo, &["merge", "--ff-only", &incoming])?;
                    eprintln!("{}  pull {} <- {}: ff {}", now_str(), ann.repo, peer.name, &ann.head[..8.min(ann.head.len())]);
                } else {
                    // Diverged. Real line-by-line 3-way merge (git): non-overlapping edits to the
                    // same OR different files combine cleanly — nothing is dropped.
                    let m = git(&repo, &["-c", "user.name=ce-gitsync", "-c", "user.email=gitsync@ce-net",
                        "merge", "--no-edit", "--allow-unrelated-histories", "-m",
                        &format!("merge {} into {host}", peer.name), &incoming]);
                    if m.is_ok() {
                        eprintln!("{}  pull {} <- {}: merged", now_str(), ann.repo, peer.name);
                    } else {
                        // Genuine conflict (same lines changed on both, or two files independently
                        // created at the same path). PRESERVE BOTH: commit the conflict markers so
                        // NOTHING leaves the working tree — your editor shows both versions to
                        // resolve. Peer's pure version also kept on a branch. Never deletes.
                        let cb = format!("ce-gitsync/conflict-{}-{}", peer.name, now_str());
                        let _ = git(&repo, &["branch", "-f", &cb, &incoming]);
                        let _ = git(&repo, &["add", "-A"]);
                        let _ = git(&repo, &["-c", "user.name=ce-gitsync", "-c", "user.email=gitsync@ce-net",
                            "commit", "--no-verify", "-q", "-m",
                            &format!("CONFLICT {} vs {host}: both versions kept inline — resolve <<< markers (peer on {cb})", peer.name)]);
                        eprintln!("{}  CONFLICT {} <- {}: BOTH kept inline (<<< markers) + branch {cb} — nothing dropped", now_str(), ann.repo, peer.name);
                    }
                }
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&tmp);
    res?;
    if let Some(nh) = head(&repo) {
        let ack = Ack { repo: ann.repo, head: nh };
        let _ = client.send_message(&peer.node_id, "gitsync/ack", &serde_json::to_vec(&ack)?).await;
    }
    Ok(())
}

fn recv_ack(peer: &Peer, payload_hex: &str, root: &Path) {
    let Ok(raw) = hex::decode(payload_hex) else { return };
    let Ok(ack): Result<Ack, _> = serde_json::from_slice(&raw) else { return };
    let repo = root.join(&ack.repo);
    if repo.join(".git").is_dir() {
        set_ref(&repo, &peer_ref(&peer.name), &ack.head);
    }
}

// ---- Loose content: files NOT inside any git repo (notes/, AGENTS.md, …). Synced as plain files
// with our own line-by-line 3-way merge. Each file's last-agreed bytes are kept as a "base" under
// <root>/.ce-gitsync/base/<rel>; concurrent non-overlapping edits merge cleanly, same-region or binary
// conflicts keep BOTH (a `.conflict-<peer>` copy) — never dropped. Temp/build/cache paths are excluded.

fn is_loose_path(root: &Path, p: &Path) -> bool {
    let s = p.to_string_lossy();
    if LOOSE_IGNORE.iter().any(|seg| s.contains(seg)) { return false; }
    p.starts_with(root) && p != root && repo_of(root, p).is_none()
}

fn loose_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let walker = walkdir::WalkDir::new(root).min_depth(1).into_iter().filter_entry(|e| {
        let s = e.path().to_string_lossy();
        if LOOSE_IGNORE.iter().any(|seg| s.contains(seg)) { return false; }
        // prune sub-repo directories — their files sync via git, not here.
        !(e.file_type().is_dir() && e.path().join(".git").exists())
    });
    for e in walker.flatten() {
        if e.file_type().is_file() { out.push(e.path().to_path_buf()); }
    }
    out
}

fn rel_of(root: &Path, p: &Path) -> Option<String> {
    p.strip_prefix(root).ok().map(|r| r.to_string_lossy().replace('\\', "/"))
}
fn base_for(root: &Path, rel: &str) -> PathBuf { root.join(".ce-gitsync/base").join(rel) }
fn write_base(root: &Path, rel: &str, bytes: &[u8]) {
    let bp = base_for(root, rel);
    if let Some(d) = bp.parent() { let _ = std::fs::create_dir_all(d); }
    let _ = std::fs::write(bp, bytes);
}

async fn push_file(client: &CeClient, peer: &Peer, root: &Path, rel: &str) {
    let abs = root.join(rel);
    let Ok(content) = std::fs::read(&abs) else { return };
    if content.len() > INLINE_MAX { return; }
    let msg = FileMsg { rel: rel.to_string(), content: hex::encode(&content) };
    if let Ok(p) = serde_json::to_vec(&msg) {
        let _ = client.send_message(&peer.node_id, "gitsync/file", &p).await;
    }
}

/// Apply an incoming loose file. Returns Some(rel) when our copy changed (so we re-broadcast the
/// merged result and every device converges); None when nothing changed or it was a kept-both conflict.
fn apply_file(root: &Path, peer_name: &str, payload_hex: &str) -> Option<String> {
    let raw = hex::decode(payload_hex).ok()?;
    let msg: FileMsg = serde_json::from_slice(&raw).ok()?;
    if msg.rel.contains("..") || msg.rel.starts_with('/') { return None; }
    let abs = root.join(&msg.rel);
    if !is_loose_path(root, &abs) { return None; }
    let incoming = hex::decode(&msg.content).ok()?;
    let local = std::fs::read(&abs).unwrap_or_default();
    if local == incoming { write_base(root, &msg.rel, &incoming); return None; }
    if !abs.exists() {
        if let Some(d) = abs.parent() { let _ = std::fs::create_dir_all(d); }
        let _ = std::fs::write(&abs, &incoming);
        write_base(root, &msg.rel, &incoming);
        eprintln!("{}  file {} <- {}: new", now_str(), msg.rel, peer_name);
        return Some(msg.rel);
    }
    let base = std::fs::read(base_for(root, &msg.rel)).unwrap_or_default();
    if is_mergeable_text(&msg.rel) {
        if let Merge3::Clean(m) = merge3(&base, &local, &incoming) {
            let _ = std::fs::write(&abs, &m);
            write_base(root, &msg.rel, &m);
            eprintln!("{}  file {} <- {}: merged (line-level)", now_str(), msg.rel, peer_name);
            return Some(msg.rel);
        }
    }
    // unmergeable (same region, or binary): keep BOTH — never overwrite local.
    let copy = format!("{}.conflict-{}", msg.rel, peer_name);
    let cabs = root.join(&copy);
    if let Some(d) = cabs.parent() { let _ = std::fs::create_dir_all(d); }
    let _ = std::fs::write(&cabs, &incoming);
    eprintln!("{}  file {} <- {}: CONFLICT — kept both (peer's copy at {})", now_str(), msg.rel, peer_name, copy);
    None
}

pub async fn serve(client: CeClient, root: PathBuf, host: String) -> Result<()> {
    let peers = load_peers();
    let repos = discover_repos(&root);
    eprintln!("{}  ce-gitsync(native) as {host}; root={}; repos={}; peers={:?}",
        now_str(), root.display(), repos.len(), peers.iter().map(|p| &p.name).collect::<Vec<_>>());

    // Event-driven file watcher -> dirty repos + dirty loose files.
    let dirty: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));
    let dirty_files: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));
    let (root2, dirty2, df2) = (root.clone(), dirty.clone(), dirty_files.clone());
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            for p in ev.paths {
                if let Some(repo) = repo_of(&root2, &p) {
                    let s = p.to_string_lossy();
                    if IGNORE.iter().any(|seg| s.contains(seg)) { continue; }
                    dirty2.lock().unwrap().insert(repo);
                } else if is_loose_path(&root2, &p) {
                    df2.lock().unwrap().insert(p);
                }
            }
        }
    })?;
    watcher.watch(&root, RecursiveMode::Recursive)?;

    // Initial reconcile: push each repo's committed head, and every loose file, once.
    for repo in &repos {
        let _ = git(repo, &["config", "core.fileMode", "false"]); // mode noise isn't a "change"
        auto_commit(repo, &host); // commit real (non-mode) WIP so it syncs
        for peer in &peers { let _ = push_repo(&client, peer, repo, &root).await; }
    }
    for f in loose_files(&root) {
        if let Some(rel) = rel_of(&root, &f) {
            for peer in &peers { push_file(&client, peer, &root, &rel).await; }
        }
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut last_hb = Instant::now();
    loop {
        // 1) INSTANT: push repos + loose files the watcher flagged.
        let flagged: Vec<PathBuf> = { let mut d = dirty.lock().unwrap(); d.drain().collect() };
        for repo in flagged {
            if cur_branch(&repo).is_some() && auto_commit(&repo, &host) {
                for peer in &peers { let _ = push_repo(&client, peer, &repo, &root).await; }
            }
        }
        let ff: Vec<PathBuf> = { let mut d = dirty_files.lock().unwrap(); d.drain().collect() };
        for f in ff {
            if let Some(rel) = rel_of(&root, &f) {
                for peer in &peers { push_file(&client, peer, &root, &rel).await; }
            }
        }
        // 2) receive announces/acks/files from any peer.
        if let Ok(msgs) = client.messages().await {
            let allowed: HashSet<&str> = peers.iter().map(|p| p.node_id.as_str()).collect();
            for m in msgs {
                if !m.topic.starts_with("gitsync/") || !allowed.contains(m.from.as_str()) { continue; }
                let id = format!("{}|{}|{}", m.from, m.topic, &m.payload_hex[..m.payload_hex.len().min(48)]);
                if !seen.insert(id) { continue; }
                let Some(peer) = peers.iter().find(|p| p.node_id == m.from) else { continue };
                if m.topic == "gitsync/announce" {
                    if let Err(e) = recv_announce(&client, peer, &m.payload_hex, &root, &host).await {
                        eprintln!("{}  recv error: {e}", now_str());
                    }
                } else if m.topic == "gitsync/ack" {
                    recv_ack(peer, &m.payload_hex, &root);
                } else if m.topic == "gitsync/file" {
                    if let Some(rel) = apply_file(&root, &peer.name, &m.payload_hex) {
                        for pe in &peers { push_file(&client, pe, &root, &rel).await; }
                    }
                }
            }
            if seen.len() > 4000 { seen.clear(); }
        }
        // 3) heartbeat ~10s: re-push repo heads + loose files (no-op when already equal) — self-heals
        //    dropped messages and discovers new repos/files.
        if last_hb.elapsed() > Duration::from_secs(10) {
            last_hb = Instant::now();
            for repo in discover_repos(&root) {
                for peer in &peers { let _ = push_repo(&client, peer, &repo, &root).await; }
            }
            for f in loose_files(&root) {
                if let Some(rel) = rel_of(&root, &f) {
                    for peer in &peers { push_file(&client, peer, &root, &rel).await; }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}
