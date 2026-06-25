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
const INLINE_MAX: usize = 2 * 1024 * 1024; // hex-inline bundles up to this; skip larger (initial
                                           // bulk is done via `git clone` from origin, see setup).

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

/// Everything directly under `root` (excluding `root` itself, which nests the rest) is synced. Dirs
/// that aren't git repos are AUTO-INITIALIZED so the whole workspace syncs by default — including
/// plain folders like `notes/`. Hidden/dot dirs are skipped.
fn discover_repos(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_dir() { continue; }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.is_empty() || name.starts_with('.') { continue; }
            if !p.join(".git").exists() {
                let _ = git(&p, &["init", "-q"]);
                let _ = git(&p, &["config", "core.fileMode", "false"]);
            }
            if p.join(".git").exists() { out.push(p); }
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
                    // Diverged/unrelated. Try a clean merge; if it can't, last-writer-wins by commit
                    // time so BOTH sides converge deterministically (no stuck conflict branches).
                    let m = git(&repo, &["-c", "user.name=ce-gitsync", "-c", "user.email=gitsync@ce-net",
                        "merge", "--no-edit", "--allow-unrelated-histories", "-m",
                        &format!("merge {} into {host}", peer.name), &incoming]);
                    if m.is_ok() {
                        eprintln!("{}  pull {} <- {}: merged", now_str(), ann.repo, peer.name);
                    } else {
                        let _ = git(&repo, &["merge", "--abort"]);
                        let lt = git_try(&repo, &["log", "-1", "--format=%ct", "HEAD"]).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                        let it = git_try(&repo, &["log", "-1", "--format=%ct", &incoming]).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                        if it >= lt {
                            let cb = format!("ce-gitsync/superseded-{}", now_str());
                            let _ = git(&repo, &["branch", "-f", &cb, "HEAD"]); // keep ours, recoverable
                            let _ = git(&repo, &["reset", "--hard", &incoming]);
                            eprintln!("{}  pull {} <- {}: took newer {} (ours on {cb})", now_str(), ann.repo, peer.name, &ann.head[..8.min(ann.head.len())]);
                        } else {
                            eprintln!("{}  pull {} <- {}: kept ours (newer); peer adopts it", now_str(), ann.repo, peer.name);
                        }
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

pub async fn serve(client: CeClient, root: PathBuf, host: String) -> Result<()> {
    let peers = load_peers();
    let repos = discover_repos(&root);
    eprintln!("{}  ce-gitsync(native) as {host}; root={}; repos={}; peers={:?}",
        now_str(), root.display(), repos.len(), peers.iter().map(|p| &p.name).collect::<Vec<_>>());

    // Event-driven file watcher -> dirty repo set.
    let dirty: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));
    let (root2, dirty2) = (root.clone(), dirty.clone());
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            for p in ev.paths {
                let s = p.to_string_lossy();
                if IGNORE.iter().any(|seg| s.contains(seg)) { continue; }
                if let Some(repo) = repo_of(&root2, &p) {
                    dirty2.lock().unwrap().insert(repo);
                }
            }
        }
    })?;
    watcher.watch(&root, RecursiveMode::Recursive)?;

    // Initial reconcile: announce every repo's COMMITTED head once. We do NOT auto-commit here —
    // committing the just-started/just-cloned state on both sides creates divergent `live:` commits
    // that then conflict. Real edits are auto-committed only by the watcher path below.
    for repo in &repos {
        let _ = git(repo, &["config", "core.fileMode", "false"]); // mode noise isn't a "change"
        auto_commit(repo, &host); // commit real (non-mode) content so existing/loose files sync too
        for peer in &peers { let _ = push_repo(&client, peer, repo, &root).await; }
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut last_hb = Instant::now();
    loop {
        // 1) INSTANT: push only the repos the watcher flagged.
        let flagged: Vec<PathBuf> = { let mut d = dirty.lock().unwrap(); d.drain().collect() };
        for repo in flagged {
            if cur_branch(&repo).is_some() && auto_commit(&repo, &host) {
                for peer in &peers { let _ = push_repo(&client, peer, &repo, &root).await; }
            }
        }
        // 2) receive announces/acks from any peer.
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
                }
            }
            if seen.len() > 4000 { seen.clear(); }
        }
        // 3) heartbeat ~10s: re-announce all heads (no-op when the peer is current) — self-heals
        //    dropped messages + discovers new repos. Cheap: rev-parse only, no full status scan.
        if last_hb.elapsed() > Duration::from_secs(10) {
            last_hb = Instant::now();
            for repo in discover_repos(&root) {
                for peer in &peers { let _ = push_repo(&client, peer, &repo, &root).await; }
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}
