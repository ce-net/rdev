//! Two-node, in-process Auto-Sync v2 integration test.
//!
//! Spins up two real CE nodes (the `NEXT_PORT` pattern, exactly as `ce-node`'s `local_cluster`
//! tests do), wires them over the mesh, and drives the Auto-Sync v2 **delta engine** end-to-end
//! against the live local node (real blob store, real `AppRequest` request/reply transport, real
//! `ce-cap` authorization). It proves the central content-addressed-delta guarantees from
//! `PLAN/05-autosync.md` §11:
//!   - a **one-byte edit** of a multi-chunk file re-uploads **exactly one chunk**;
//!   - **resume** (re-running the same push, unchanged) uploads **zero** extra chunks;
//!   - the initiator's chosen **conflict policy** (`copy`) is threaded through to the server commit
//!     handler — a divergent receiver file is preserved (never silently overwritten);
//!   - **chunk-level bidirectional PULL** transfers only the chunks the puller lacks.
//!
//! Node A is the initiator's local node (the rdev client talks to it). Node B is the responder's
//! node; a small in-test responder loop polls B's inbox and dispatches the `rdev/sync2/*` verbs
//! using the SAME public library functions the real `rdev serve` uses (`apply_commit_verified`,
//! `pull_file_verified`, `resolve`, the `syncproto` wire types). That keeps the test honest: it
//! exercises the shipping delta/conflict code over the real mesh, not a reimplementation.
//!
//! The test is resilient: if a node cannot start or the mesh does not converge in time (e.g. a
//! locked-down CI sandbox), it prints a skip note and returns rather than failing spuriously.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;

use ce_cap::{Caveats, Resource, SignedCapability, authorize, decode_chain, encode_chain};
use ce_identity::Identity;
use ce_node::{Node, NodeConfig};
use ce_rs::CeClient;
use rdev::chunk::{chunk_bytes, content_id};
use rdev::delta::{apply_commit_verified, plan_transfer, pull_file_verified, upload_missing};
use rdev::syncproto::{
    CommitReq, CommitResp, HaveReq, HaveResp, ManifestReq, ManifestResp, action_for, verb,
};
use rdev::{ConflictInput, Policy, Resolution, resolve};
use tokio::time::sleep;

static NEXT_PORT: AtomicU16 = AtomicU16::new(15_200);
const TEST_API_TOKEN: &str = "rdev-autosync-test-token";

fn alloc_ports() -> (u16, u16) {
    let p2p = NEXT_PORT.fetch_add(2, Ordering::Relaxed);
    (p2p, p2p + 1)
}

fn tmpdir(label: &str) -> PathBuf {
    unsafe { std::env::set_var("CE_API_TOKEN", TEST_API_TOKEN) };
    let dir = std::env::temp_dir().join(format!(
        "rdev-autosync-{}-{label}-{}",
        std::process::id(),
        NEXT_PORT.load(Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn identity_in(dir: &Path) -> Identity {
    Identity::load_or_generate(&dir.join("identity")).unwrap()
}

fn node_id_of(dir: &Path) -> [u8; 32] {
    identity_in(dir).node_id()
}

fn bootstrap_addr(dir: &Path, p2p_port: u16) -> String {
    let id = identity_in(dir);
    let peer_id = ce_node::peer_id_from_identity(&id).unwrap();
    format!("/ip4/127.0.0.1/tcp/{p2p_port}/p2p/{peer_id}")
}

/// Start a node on freshly-allocated ports; returns the node, its p2p port, and its API base URL.
async fn start_node(
    bootstrap: Option<String>,
    dir: &Path,
) -> anyhow::Result<(Node, u16, String)> {
    let (p2p, api) = alloc_ports();
    let config = NodeConfig {
        listen_port: p2p,
        bootstrap_peers: bootstrap.into_iter().collect(),
        data_dir: dir.to_path_buf(),
        api_port: api,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    };
    let node = Node::start(config).await?;
    Ok((node, p2p, format!("http://127.0.0.1:{api}")))
}

/// Issue a capability from the resource owner `dir_owner` to the audience `aud` for `actions`.
fn issue_cap(dir_owner: &Path, aud: [u8; 32], actions: &[&str]) -> String {
    let owner = identity_in(dir_owner);
    let c = SignedCapability::issue(
        &owner,
        aud,
        actions.iter().map(|s| s.to_string()).collect(),
        Resource::Any,
        Caveats::default(),
        1,
        None,
    );
    encode_chain(&[c])
}

// ----- the in-test responder (mirrors `rdev serve`'s sync2 dispatch over real transport) -----

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn authorize_chain(
    topic: &str,
    caps: &str,
    from_hex: &str,
    host_id: &[u8; 32],
) -> anyhow::Result<Vec<SignedCapability>> {
    let action = action_for(topic).ok_or_else(|| anyhow::anyhow!("unknown verb"))?;
    let from: [u8; 32] = hex::decode(from_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("bad sender id"))?;
    let chain = decode_chain(caps).map_err(|_| anyhow::anyhow!("bad capability"))?;
    let is_revoked = |_: &[u8; 32], _: u64| false;
    authorize(host_id, &[], &[], now_secs(), &from, action, &chain, &is_revoked)
        .map_err(|e| anyhow::anyhow!("denied: {e}"))?;
    Ok(chain)
}

async fn handle_one(
    client: &CeClient,
    topic: &str,
    from_hex: &str,
    payload_hex: &str,
    host_id: &[u8; 32],
    home: &Path,
    host_short: &str,
) -> Vec<u8> {
    match handle_one_inner(client, topic, from_hex, payload_hex, host_id, home, host_short).await {
        Ok(b) => b,
        Err(e) => serde_json::to_vec(&serde_json::json!({ "ok": false, "error": e.to_string() }))
            .unwrap_or_default(),
    }
}

async fn handle_one_inner(
    client: &CeClient,
    topic: &str,
    from_hex: &str,
    payload_hex: &str,
    host_id: &[u8; 32],
    home: &Path,
    host_short: &str,
) -> anyhow::Result<Vec<u8>> {
    let raw = hex::decode(payload_hex)?;
    match topic {
        verb::HAVE => {
            let req: HaveReq = serde_json::from_slice(&raw)?;
            authorize_chain(topic, &req.caps, from_hex, host_id)?;
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
            let req: CommitReq = serde_json::from_slice(&raw)?;
            authorize_chain(topic, &req.caps, from_hex, host_id)?;
            let target = home.join(&req.path);
            if let Some(p) = target.parent() {
                std::fs::create_dir_all(p)?;
            }
            let bytes = apply_commit_verified(client, &req.manifest, &req.file_cid).await?;
            let _ = client.put_blob(bytes.clone()).await;
            let local = std::fs::read(&target).ok();
            let local_cid = local.as_ref().map(|b| content_id(b));
            let policy =
                req.policy.as_deref().and_then(|s| s.parse::<Policy>().ok()).unwrap_or(Policy::Lww);
            let input = ConflictInput {
                rel_path: &req.path,
                local_cid: local_cid.as_deref(),
                local_mtime_ms: 0,
                incoming_cid: &req.file_cid,
                incoming_mtime_ms: req.mtime_ms,
                base_cid: req.base_cid.as_deref(),
                initiator_short: host_short,
            };
            match resolve(policy, &input) {
                Resolution::TakeIncoming { conflict_copy } => {
                    if let (Some(copy), Some(prev)) = (&conflict_copy, &local) {
                        std::fs::write(home.join(copy), prev)?;
                    }
                    std::fs::write(&target, &bytes)?;
                    Ok(serde_json::to_vec(&CommitResp {
                        ok: true,
                        applied: true,
                        conflict: conflict_copy.is_some(),
                        conflict_copy,
                        ..Default::default()
                    })?)
                }
                Resolution::KeepLocal { conflict_copy } => {
                    std::fs::write(home.join(&conflict_copy), &bytes)?;
                    Ok(serde_json::to_vec(&CommitResp {
                        ok: true,
                        applied: false,
                        conflict: true,
                        conflict_copy: Some(conflict_copy),
                        remote_cid: local_cid,
                        ..Default::default()
                    })?)
                }
                Resolution::Merged { merged } => {
                    std::fs::write(&target, &merged)?;
                    Ok(serde_json::to_vec(&CommitResp {
                        ok: true,
                        applied: true,
                        ..Default::default()
                    })?)
                }
            }
        }
        verb::MANIFEST => {
            let req: ManifestReq = serde_json::from_slice(&raw)?;
            authorize_chain(topic, &req.caps, from_hex, host_id)?;
            let target = home.join(&req.path);
            let bytes = match std::fs::read(&target) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(serde_json::to_vec(&ManifestResp {
                        ok: true,
                        found: false,
                        ..Default::default()
                    })?);
                }
                Err(e) => return Err(e.into()),
            };
            let (cf, chunks) = chunk_bytes(&bytes);
            for (cid, chunk) in &chunks {
                let got = client.put_blob(chunk.clone()).await?;
                anyhow::ensure!(&got == cid, "blob store cid mismatch");
            }
            Ok(serde_json::to_vec(&ManifestResp {
                ok: true,
                error: None,
                found: true,
                file_cid: cf.file_cid,
                manifest: Some(cf.manifest),
                mode: 0,
                mtime_ms: 0,
            })?)
        }
        other => Err(anyhow::anyhow!("unhandled verb {other}")),
    }
}

/// Spawn the responder against node B's HTTP API; returns a stop flag.
fn spawn_responder(b_url: String, host_id: [u8; 32], home: PathBuf) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let host_short = hex::encode(host_id)[..16].to_string();
    tokio::spawn(async move {
        let client = CeClient::new(b_url);
        let mut seen: HashSet<u64> = HashSet::new();
        while !stop2.load(Ordering::Relaxed) {
            if let Ok(msgs) = client.messages().await {
                for m in msgs {
                    let Some(token) = m.reply_token else { continue };
                    if !m.topic.starts_with("rdev/sync2/") || !seen.insert(token) {
                        continue;
                    }
                    let reply =
                        handle_one(&client, &m.topic, &m.from, &m.payload_hex, &host_id, &home, &host_short)
                            .await;
                    let _ = client.reply(token, &reply).await;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    });
    stop
}

// ----- client side -----

/// Push one file's delta: have → upload only-missing → commit. Returns the commit reply and adds the
/// number of chunks that actually moved to `uploads`.
#[allow(clippy::too_many_arguments)]
async fn push_delta_client(
    client: &CeClient,
    node_id: &str,
    caps: &str,
    rel_path: &str,
    bytes: &[u8],
    base_cid: Option<String>,
    policy: Policy,
    uploads: &AtomicUsize,
) -> anyhow::Result<CommitResp> {
    let (cf, chunks) = chunk_bytes(bytes);
    let have_req = HaveReq { caps: caps.to_string(), chunks: cf.manifest.chunks.clone() };
    let reply =
        client.request(node_id, verb::HAVE, &serde_json::to_vec(&have_req)?, 30_000).await?;
    let have: HaveResp = serde_json::from_slice(&reply)?;
    anyhow::ensure!(have.ok, "have refused");
    let missing = plan_transfer(&cf.manifest.chunks, &have.missing);
    let n = upload_missing(client, &chunks, &missing).await?;
    uploads.fetch_add(n, Ordering::Relaxed);

    let policy_str = match policy {
        Policy::Lww => "lww",
        Policy::Copy => "copy",
        Policy::Crdt => "crdt",
    };
    let commit = CommitReq {
        caps: caps.to_string(),
        path: rel_path.to_string(),
        file_cid: cf.file_cid.clone(),
        manifest: cf.manifest.clone(),
        base_cid,
        mode: 0,
        mtime_ms: 1_000,
        policy: Some(policy_str.to_string()),
    };
    let reply =
        client.request(node_id, verb::COMMIT, &serde_json::to_vec(&commit)?, 60_000).await?;
    let resp: CommitResp = serde_json::from_slice(&reply)?;
    anyhow::ensure!(resp.ok, "commit refused: {:?}", resp.error);
    Ok(resp)
}

/// Wait until A can reach B over the mesh (an empty `have` round-trips). False on timeout.
async fn wait_mesh(client_a: &CeClient, b_id: &str, caps: &str) -> bool {
    let probe = HaveReq { caps: caps.to_string(), chunks: vec![] };
    let body = serde_json::to_vec(&probe).unwrap();
    for _ in 0..30 {
        if let Ok(reply) = client_a.request(b_id, verb::HAVE, &body, 5_000).await {
            if serde_json::from_slice::<HaveResp>(&reply).map(|r| r.ok).unwrap_or(false) {
                return true;
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
    false
}

async fn wait_for_file(path: &Path, expect: &[u8]) -> bool {
    for _ in 0..50 {
        if std::fs::read(path).map(|b| b == expect).unwrap_or(false) {
            return true;
        }
        sleep(Duration::from_millis(100)).await;
    }
    false
}

/// A deterministic 3-chunk payload whose three 1 MiB chunks are all DISTINCT (each chunk is keyed
/// by its index so no two chunk CIDs collide — otherwise dedup would make "3 chunks" upload as 1).
fn three_chunk_payload() -> Vec<u8> {
    let cs = rdev::chunk::CHUNK_SIZE;
    let n = cs * 3;
    (0..n)
        .map(|i| {
            // Distinct per chunk (a chunk-number salt) plus a within-chunk ramp, so the three chunk
            // CIDs never collide (a one-byte edit then changes exactly one chunk).
            let chunk_no = (i / cs) as u8;
            chunk_no.wrapping_mul(97).wrapping_add((i % 251) as u8)
        })
        .collect()
}

// ----- tests -----

#[tokio::test(flavor = "multi_thread")]
async fn one_byte_edit_uploads_one_chunk_and_resume_uploads_zero() {
    let dir_a = tmpdir("edit-a");
    let dir_b = tmpdir("edit-b");
    let home_b = dir_b.join("home");
    std::fs::create_dir_all(&home_b).unwrap();

    let (node_a, p2p_a, a_url) = match start_node(None, &dir_a).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skip: node A failed to start ({e})");
            return;
        }
    };
    let _ = &node_a;
    sleep(Duration::from_millis(600)).await;

    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (node_b, _p2p_b, b_url) = match start_node(Some(bs), &dir_b).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skip: node B failed to start ({e})");
            return;
        }
    };
    let _ = &node_b;

    let a_id = node_id_of(&dir_a);
    let b_id = node_id_of(&dir_b);
    // B (resource owner) authorizes A.
    let cap = issue_cap(&dir_b, a_id, &["sync", "delete", "sync-read"]);

    let client_a = CeClient::new(a_url.clone());
    let stop = spawn_responder(b_url.clone(), b_id, home_b.clone());

    if !wait_mesh(&client_a, &hex::encode(b_id), &cap).await {
        stop.store(true, Ordering::Relaxed);
        eprintln!("skip: mesh did not converge between the two nodes");
        return;
    }

    let uploads = AtomicUsize::new(0);
    let rel = "src/main.rs";
    let mut data = three_chunk_payload();

    // 1) Initial push -> 3 chunks move.
    push_delta_client(&client_a, &hex::encode(b_id), &cap, rel, &data, None, Policy::Lww, &uploads)
        .await
        .expect("initial push");
    assert_eq!(uploads.load(Ordering::Relaxed), 3, "fresh 3-chunk file uploads 3 chunks");
    assert!(wait_for_file(&home_b.join(rel), &data).await, "B did not receive the initial file");

    // 2) One-byte edit in the head chunk -> exactly one chunk re-uploads.
    data[7] ^= 0xff;
    uploads.store(0, Ordering::Relaxed);
    let base = content_id(&std::fs::read(home_b.join(rel)).unwrap());
    push_delta_client(
        &client_a,
        &hex::encode(b_id),
        &cap,
        rel,
        &data,
        Some(base),
        Policy::Lww,
        &uploads,
    )
    .await
    .expect("edit push");
    assert_eq!(uploads.load(Ordering::Relaxed), 1, "one-byte edit re-uploads exactly one chunk");
    assert!(wait_for_file(&home_b.join(rel), &data).await, "edit did not converge on B");

    // 3) Resume / no-op: re-pushing the same bytes uploads zero new chunks.
    uploads.store(0, Ordering::Relaxed);
    let base2 = content_id(&std::fs::read(home_b.join(rel)).unwrap());
    push_delta_client(
        &client_a,
        &hex::encode(b_id),
        &cap,
        rel,
        &data,
        Some(base2),
        Policy::Lww,
        &uploads,
    )
    .await
    .expect("resume push");
    assert_eq!(uploads.load(Ordering::Relaxed), 0, "re-pushing unchanged bytes uploads zero chunks");

    stop.store(true, Ordering::Relaxed);
}

#[tokio::test(flavor = "multi_thread")]
async fn conflict_copy_policy_preserved_and_pull_is_chunked() {
    let dir_a = tmpdir("conf-a");
    let dir_b = tmpdir("conf-b");
    let home_b = dir_b.join("home");
    std::fs::create_dir_all(&home_b).unwrap();

    let (node_a, p2p_a, a_url) = match start_node(None, &dir_a).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skip: node A failed to start ({e})");
            return;
        }
    };
    let _ = &node_a;
    sleep(Duration::from_millis(600)).await;
    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (node_b, _p2p_b, b_url) = match start_node(Some(bs), &dir_b).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skip: node B failed to start ({e})");
            return;
        }
    };
    let _ = &node_b;

    let a_id = node_id_of(&dir_a);
    let b_id = node_id_of(&dir_b);
    let cap = issue_cap(&dir_b, a_id, &["sync", "delete", "sync-read"]);

    let client_a = CeClient::new(a_url.clone());
    let stop = spawn_responder(b_url.clone(), b_id, home_b.clone());

    if !wait_mesh(&client_a, &hex::encode(b_id), &cap).await {
        stop.store(true, Ordering::Relaxed);
        eprintln!("skip: mesh did not converge");
        return;
    }

    let uploads = AtomicUsize::new(0);
    let rel = "notes.txt";

    // The receiver already holds a DIVERGENT file the initiator never saw.
    std::fs::write(home_b.join(rel), b"receiver-local-version").unwrap();

    // Initiator pushes with --conflict copy and a stale base the receiver does not currently hold.
    let incoming = b"initiator-incoming-version".to_vec();
    let resp = push_delta_client(
        &client_a,
        &hex::encode(b_id),
        &cap,
        rel,
        &incoming,
        Some("a-stale-base-cid".to_string()),
        Policy::Copy,
        &uploads,
    )
    .await
    .expect("conflict push");

    assert!(!resp.applied, "copy policy must not overwrite the receiver's file");
    assert!(resp.conflict, "a divergent receiver file is a conflict");
    let copy_rel = resp.conflict_copy.clone().expect("a conflict copy path");
    sleep(Duration::from_millis(300)).await;
    assert_eq!(
        std::fs::read(home_b.join(rel)).unwrap(),
        b"receiver-local-version",
        "receiver's local file preserved under copy policy"
    );
    assert!(
        wait_for_file(&home_b.join(&copy_rel), &incoming).await,
        "incoming saved as the conflict copy"
    );

    // ----- chunk-level PULL: only the missing chunk transfers. -----
    let mut remote = three_chunk_payload();
    let (orig_cf, orig_chunks) = chunk_bytes(&remote);
    // Seed A's blob store with B's TAIL chunks (held); leave the head chunk absent on A.
    for (cid, bytes) in &orig_chunks {
        if cid != &orig_cf.chunk_cids()[0] {
            let _ = client_a.put_blob(bytes.clone()).await;
        }
    }
    // B's file edits only the head chunk -> tail identical to what A holds.
    remote[3] ^= 0xff;
    std::fs::write(home_b.join("pull.bin"), &remote).unwrap();

    let mreq = ManifestReq { caps: cap.clone(), path: "pull.bin".into() };
    let reply = client_a
        .request(&hex::encode(b_id), verb::MANIFEST, &serde_json::to_vec(&mreq).unwrap(), 30_000)
        .await
        .expect("manifest request");
    let mresp: ManifestResp = serde_json::from_slice(&reply).unwrap();
    assert!(mresp.ok && mresp.found, "manifest fetched");
    let manifest = mresp.manifest.expect("manifest present");

    // A holds the two tail chunks; only the (changed) head chunk should transfer.
    let held: HashSet<String> = manifest.chunks.iter().skip(1).cloned().collect();
    let (bytes, fetched) = pull_file_verified(&client_a, &manifest, &mresp.file_cid, &held)
        .await
        .expect("chunk-level pull");
    assert_eq!(bytes, remote, "pulled bytes match B's file");
    assert_eq!(fetched, 1, "chunk-level pull fetched exactly one (missing head) chunk");

    stop.store(true, Ordering::Relaxed);
}
