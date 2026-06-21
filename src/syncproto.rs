//! Wire types for the Auto-Sync v2 protocol (`rdev/sync2/<verb>` over CE `AppRequest`).
//!
//! Per `PLAN/05-autosync.md` §4. Every request carries `caps` (the encoded capability chain) and is
//! authorized server-side exactly as rdev's existing `handle_inner` does, with `action` =
//! `"sync"`/`"delete"`/`"sync-read"`. Payloads are JSON, hex-encoded into the `AppRequest` payload
//! (matching rdev's `Req`/`Resp` convention). **Bytes never travel here** — only CIDs, manifests,
//! and have/missing sets. The chunk bytes move through the content-addressed blob store.
//!
//! The four verbs:
//!   - `have`   — "do you already hold these chunk CIDs?" → `missing` subset.
//!   - `commit` — "this file is now this manifest; apply it."
//!   - `delete` — tombstone a path (idempotent).
//!   - `list`   — "return your index for this subtree" (initial reconcile / bidir pull).

use ce_rs::data::Manifest;
use serde::{Deserialize, Serialize};

/// Topic prefix for the v2 protocol.
pub const TOPIC_PREFIX: &str = "rdev/sync2/";

/// The verbs of the v2 protocol.
pub mod verb {
    pub const HAVE: &str = "rdev/sync2/have";
    pub const COMMIT: &str = "rdev/sync2/commit";
    pub const DELETE: &str = "rdev/sync2/delete";
    pub const LIST: &str = "rdev/sync2/list";
    /// Return a remote file's chunk manifest (for chunk-level bidirectional PULL).
    pub const MANIFEST: &str = "rdev/sync2/manifest";
}

/// `rdev/sync2/have` request — "do you hold these chunks?" (read-only, idempotent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaveReq {
    /// Encoded capability chain.
    pub caps: String,
    /// Chunk CIDs being offered.
    pub chunks: Vec<String>,
}

/// `rdev/sync2/have` reply — the subset of offered chunks the receiver does NOT hold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaveResp {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub missing: Vec<String>,
}

/// `rdev/sync2/commit` request — apply a file's manifest at `path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitReq {
    pub caps: String,
    /// Relative path; the receiver joins it under home and enforces the `path_prefix` caveat.
    pub path: String,
    /// `sha256` of the full file (cross-checked against the reassembled bytes).
    pub file_cid: String,
    /// The chunk manifest (`ce-object-v1`).
    pub manifest: Manifest,
    /// What the initiator believed the receiver's file was (conflict base; empty == none).
    #[serde(default)]
    pub base_cid: Option<String>,
    /// Unix mode bits (0 on Windows; receiver applies the x-bit only).
    #[serde(default)]
    pub mode: u32,
    /// Initiator's file mtime in ms.
    #[serde(default)]
    pub mtime_ms: u64,
    /// The initiator's chosen conflict policy (`lww` | `copy` | `crdt`). Absent on legacy clients →
    /// the receiver defaults to `lww`. The receiver always preserves the loser as a conflict copy,
    /// so honoring the initiator's policy never lets it silently destroy the receiver's data.
    #[serde(default)]
    pub policy: Option<String>,
}

/// `rdev/sync2/commit` reply.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommitResp {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    /// Whether the incoming file became the canonical file.
    #[serde(default)]
    pub applied: bool,
    /// Set when a conflict was detected.
    #[serde(default)]
    pub conflict: bool,
    /// The receiver's current file CID at conflict time.
    #[serde(default)]
    pub remote_cid: Option<String>,
    /// The receiver's current file mtime (ms) at conflict time.
    #[serde(default)]
    pub remote_mtime_ms: u64,
    /// If a conflict copy was written on the receiver, its relative path.
    #[serde(default)]
    pub conflict_copy: Option<String>,
}

/// `rdev/sync2/delete` request — tombstone a path (idempotent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteReq {
    pub caps: String,
    pub path: String,
    #[serde(default)]
    pub base_cid: Option<String>,
}

/// `rdev/sync2/delete` reply.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeleteResp {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub conflict: bool,
    #[serde(default)]
    pub remote_cid: Option<String>,
}

/// `rdev/sync2/list` request — return the receiver's index for a subtree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListReq {
    pub caps: String,
    /// Relative subtree prefix ("" == whole tree).
    #[serde(default)]
    pub prefix: String,
}

/// One entry in a `list` reply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListEntry {
    pub path: String,
    pub file_cid: String,
    #[serde(default)]
    pub mtime_ms: u64,
    #[serde(default)]
    pub mode: u32,
}

/// `rdev/sync2/list` reply.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListResp {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub entries: Vec<ListEntry>,
}

/// `rdev/sync2/manifest` request — fetch the chunk manifest for one remote file (chunk-level pull).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestReq {
    pub caps: String,
    /// Relative path under home; the receiver enforces the `path_prefix` caveat + `..` guard.
    pub path: String,
}

/// `rdev/sync2/manifest` reply — the file's CID + chunk manifest, plus mode/mtime for the puller's
/// index. `found == false` (with `ok == true`) means the path does not exist on the receiver.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestResp {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    /// Whether the file exists on the receiver.
    #[serde(default)]
    pub found: bool,
    /// `sha256` of the full file bytes.
    #[serde(default)]
    pub file_cid: String,
    /// The chunk manifest (`ce-object-v1`); empty/absent when `found == false`.
    #[serde(default)]
    pub manifest: Option<Manifest>,
    /// Unix mode bits (0 on Windows).
    #[serde(default)]
    pub mode: u32,
    /// File mtime in ms.
    #[serde(default)]
    pub mtime_ms: u64,
}

/// Map a `sync2` verb topic to the capability action string used for authorization.
/// `have`/`list`/`manifest` are read operations (the `sync-read` ability); `commit`/`delete` are
/// writes.
pub fn action_for(topic: &str) -> Option<&'static str> {
    match topic {
        verb::COMMIT => Some("sync"),
        verb::DELETE => Some("delete"),
        verb::HAVE | verb::LIST | verb::MANIFEST => Some("sync-read"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_mapping() {
        assert_eq!(action_for(verb::COMMIT), Some("sync"));
        assert_eq!(action_for(verb::DELETE), Some("delete"));
        assert_eq!(action_for(verb::HAVE), Some("sync-read"));
        assert_eq!(action_for(verb::LIST), Some("sync-read"));
        assert_eq!(action_for(verb::MANIFEST), Some("sync-read"));
        assert_eq!(action_for("rdev/sync2/bogus"), None);
    }

    #[test]
    fn have_roundtrip() {
        let r = HaveReq { caps: "ab".into(), chunks: vec!["c1".into(), "c2".into()] };
        let back: HaveReq = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(back.chunks, vec!["c1".to_string(), "c2".to_string()]);
    }

    #[test]
    fn commit_roundtrip_carries_only_cids() {
        let manifest = Manifest {
            kind: "ce-object-v1".into(),
            chunk_size: 1048576,
            total_size: 5,
            chunks: vec!["aa".into()],
        };
        let r = CommitReq {
            caps: "x".into(),
            path: "a/b.rs".into(),
            file_cid: "ff".into(),
            manifest,
            base_cid: Some("ee".into()),
            mode: 33188,
            mtime_ms: 1718900000000,
            policy: Some("lww".into()),
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        // The manifest carries CIDs, never bytes.
        let s = String::from_utf8(bytes.clone()).unwrap();
        assert!(s.contains("\"file_cid\":\"ff\""));
        let back: CommitReq = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.path, "a/b.rs");
        assert_eq!(back.base_cid.as_deref(), Some("ee"));
    }

    #[test]
    fn list_entry_roundtrip() {
        let e = ListEntry { path: "a.rs".into(), file_cid: "cid".into(), mtime_ms: 9, mode: 33188 };
        let back: ListEntry = serde_json::from_slice(&serde_json::to_vec(&e).unwrap()).unwrap();
        assert_eq!(back, e);
    }
}
