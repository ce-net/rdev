//! rdev — remote-dev services on CE, as an **application** (not part of the node).
//!
//! This is the reference for the CE primitives-vs-apps boundary: device-to-device features are apps
//! built on CE's mesh + capability primitives, NOT bespoke node RPCs. rdev moves files between
//! machines over the mesh, authorized by capabilities, using only:
//!   - `ce-rs`  — the mesh transport: directed request/response (`AppRequest`/`reply`) + `/status`.
//!   - `ce-cap` — the capability verifier (does a signed, attenuating chain authorize an action?).
//! No new node code, no new consensus tx, no stored IP:port — CE moves the bytes, rdev is the policy.
//!
//! ## Protocol (over CE `AppRequest`)
//!
//! The client sends an `AppRequest` to the target node with topic `rdev/<action>` and a JSON
//! payload. The target runs `rdev serve`, which verifies the capability and performs the op under
//! its home directory, then replies. Actions implemented here:
//!   - `rdev/sync`   `{ caps, path, data_hex }` — write a file.
//!   - `rdev/delete` `{ caps, path }`           — delete a file.
//!
//! ## Staged (next), and why they aren't here yet
//!   - `exec`/`deploy` — same pattern, but the handler runs a container; it composes the
//!     `ce-container` primitive (bollard/gVisor) + the job store. Straightforward follow-on.
//!   - `tunnel` — streaming, not request/response. It needs a CE node primitive that lets a local
//!     app accept/open raw mesh streams (the stream control is currently node-internal). That
//!     primitive must land in CE first; then tunnel becomes an rdev sub-command.
//!   - Migration: once proven on a live mesh, the node's bespoke `SyncFile`/`SyncDelete` RPCs (and
//!     `mirror`'s use of them) move here, removing the duplicate from CE.
//!
//! v0 limitations: capability revocation is not consulted (relies on expiry); the inbox is polled.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use ce_cap::{SignedCapability, authorize, decode_chain};
use ce_rs::CeClient;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "rdev", version, about = "Remote-dev file services over the CE mesh (an app on CE)")]
struct Cli {
    /// Local CE node API URL.
    #[arg(long, global = true, default_value = "http://127.0.0.1:8844")]
    node: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server: accept rdev requests addressed to this node and perform them.
    Serve,
    /// Push a single file to a peer: `rdev push <file> <node-id>:<remote-path> --cap <token>`.
    Push {
        file: PathBuf,
        /// `<node-id>:<remote-path>` (remote path is relative to the target's home).
        dest: String,
        #[arg(long)]
        cap: String,
    },
    /// Delete a file on a peer: `rdev rm <node-id>:<remote-path> --cap <token>`.
    Rm {
        dest: String,
        #[arg(long)]
        cap: String,
    },
}

/// Wire payload for an rdev request.
#[derive(Serialize, Deserialize)]
struct Req {
    caps: String,
    path: String,
    #[serde(default)]
    data_hex: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Resp {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = CeClient::new(cli.node.clone());
    if !client.health().await.unwrap_or(false) {
        return Err(anyhow!("local CE node not reachable at {} — is `ce start` running?", cli.node));
    }
    match cli.cmd {
        Cmd::Serve => serve(&client).await,
        Cmd::Push { file, dest, cap } => push(&client, &file, &dest, &cap).await,
        Cmd::Rm { dest, cap } => rm(&client, &dest, &cap).await,
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn parse_dest(dest: &str) -> Result<(String, String)> {
    let (node_id, path) = dest
        .split_once(':')
        .ok_or_else(|| anyhow!("dest must be <node-id>:<remote-path>"))?;
    Ok((node_id.to_string(), path.to_string()))
}

// ----- client -----

async fn push(client: &CeClient, file: &PathBuf, dest: &str, cap: &str) -> Result<()> {
    let (node_id, path) = parse_dest(dest)?;
    let data = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    let req = Req { caps: cap.to_string(), path: path.clone(), data_hex: Some(hex::encode(&data)) };
    let reply = client
        .request(&node_id, "rdev/sync", &serde_json::to_vec(&req)?, 30_000)
        .await?;
    finish(&reply, &format!("pushed {} -> {node_id}:{path}", file.display()))
}

async fn rm(client: &CeClient, dest: &str, cap: &str) -> Result<()> {
    let (node_id, path) = parse_dest(dest)?;
    let req = Req { caps: cap.to_string(), path: path.clone(), data_hex: None };
    let reply = client
        .request(&node_id, "rdev/delete", &serde_json::to_vec(&req)?, 30_000)
        .await?;
    finish(&reply, &format!("deleted {node_id}:{path}"))
}

fn finish(reply: &[u8], ok_msg: &str) -> Result<()> {
    let r: Resp = serde_json::from_slice(reply).context("decode reply")?;
    if r.ok {
        println!("{ok_msg}");
        Ok(())
    } else {
        Err(anyhow!("remote refused: {}", r.error.unwrap_or_default()))
    }
}

// ----- server -----

async fn serve(client: &CeClient) -> Result<()> {
    let host_hex = client.status().await?.node_id;
    let host_id: [u8; 32] = hex::decode(&host_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("bad node id from /status"))?;
    println!("rdev serving as {}… (handles rdev/sync, rdev/delete)", &host_hex[..16]);

    let mut seen: HashSet<u64> = HashSet::new();
    loop {
        let msgs = client.messages().await.unwrap_or_default();
        for m in msgs {
            let Some(token) = m.reply_token else { continue };
            if !m.topic.starts_with("rdev/") || !seen.insert(token) {
                continue;
            }
            let resp = handle(&m.topic, &m.from, &m.payload_hex, &host_id);
            let body = serde_json::to_vec(&resp).unwrap_or_default();
            if let Err(e) = client.reply(token, &body).await {
                eprintln!("reply failed: {e}");
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Verify the capability and perform the action. Returns the reply.
fn handle(topic: &str, from_hex: &str, payload_hex: &str, host_id: &[u8; 32]) -> Resp {
    match handle_inner(topic, from_hex, payload_hex, host_id) {
        Ok(()) => Resp { ok: true, error: None },
        Err(e) => Resp { ok: false, error: Some(e.to_string()) },
    }
}

fn handle_inner(topic: &str, from_hex: &str, payload_hex: &str, host_id: &[u8; 32]) -> Result<()> {
    let action = topic.strip_prefix("rdev/").unwrap_or(topic);
    let bytes = hex::decode(payload_hex).context("payload hex")?;
    let req: Req = serde_json::from_slice(&bytes).context("payload json")?;
    let from: [u8; 32] = hex::decode(from_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("bad sender id"))?;

    // Authorize via the capability primitive. accepted_roots is empty: self-issued caps (issuer ==
    // this node) are always honored; configured org roots would be added here. Revocation is not
    // consulted in v0 (rely on expiry).
    let chain: Vec<SignedCapability> = decode_chain(&req.caps).map_err(|_| anyhow!("bad capability"))?;
    authorize(host_id, &[], &[], now(), &from, action, &chain, &|_, _| false)
        .map_err(|e| anyhow!("denied: {e}"))?;

    // Confine to the home directory; honor a path_prefix caveat on the leaf if present.
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let home_canon = home.canonicalize().unwrap_or_else(|_| home.clone());
    if req.path.contains("..") {
        return Err(anyhow!("path traversal not allowed"));
    }
    if let Some(prefix) = chain.last().and_then(|c| c.cap.caveats.path_prefix.as_ref()) {
        if !req.path.starts_with(prefix.as_str()) {
            return Err(anyhow!("path '{}' outside capability prefix '{prefix}'", req.path));
        }
    }
    let target = home.join(&req.path);

    match action {
        "sync" => {
            let data = hex::decode(req.data_hex.unwrap_or_default()).context("data hex")?;
            if let Some(p) = target.parent() {
                std::fs::create_dir_all(p).ok();
                let canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
                if !canon.starts_with(&home_canon) {
                    return Err(anyhow!("path traversal not allowed"));
                }
            }
            std::fs::write(&target, &data).with_context(|| format!("write {}", target.display()))?;
            Ok(())
        }
        "delete" => {
            match std::fs::remove_file(&target) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // idempotent
                Err(e) => Err(anyhow!("delete failed: {e}")),
            }
        }
        other => Err(anyhow!("unknown rdev action '{other}'")),
    }
}
