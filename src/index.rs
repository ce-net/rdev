//! Persistent, crash-safe sync index for Auto-Sync.
//!
//! Per `PLAN/05-autosync.md` §5: a per-session index records, for every synced file, its
//! `(size, mtime_ms)` plus the cached `file_cid` and chunk CIDs. The `(size, mtime_ms)` "rsync
//! trick" lets a re-walk skip re-hashing unchanged files; the cached chunk CIDs make resume free
//! (no re-hash after a kill). `remote_seen` records the last-acked remote state per path, the
//! conflict base for bidirectional sync.
//!
//! Storage: a single file at `~/.local/share/rdev/sync/<session>.idx`, written via temp-file +
//! fsync + atomic rename so a crash mid-write never corrupts the index. The on-disk format is
//! **bincode** (CE standard for disk/wire), length-prefixed by bincode itself.
//!
//! `<session> = cid(local_root || ":" || remote_node_id || ":" || remote_root)[..16]` — a stable
//! per-pair id so the same sync resumes its own index.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ce_rs::cid;
use serde::{Deserialize, Serialize};

/// Current on-disk index format version.
pub const INDEX_VERSION: u32 = 1;

/// One synced file's cached state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Forward-slash path relative to the local root.
    pub rel_path: String,
    /// `sha256` of the file's bytes (== `ce_rs::cid`).
    pub file_cid: String,
    /// File size in bytes.
    pub size: u64,
    /// Local filesystem mtime in milliseconds since the epoch.
    pub mtime_ms: u64,
    /// Unix mode bits (0 on Windows / unknown).
    pub mode: u32,
    /// Ordered chunk CIDs (so resume needs no re-hash if size+mtime are unchanged).
    pub chunks: Vec<String>,
}

/// The last remote state we saw acknowledged for a path — the conflict base for bidir sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSeen {
    /// The file CID the remote last confirmed (empty string == "remote has no such file").
    pub file_cid: String,
    /// The remote mtime (ms) at that point, if known.
    pub mtime_ms: u64,
}

/// The persistent sync index for one (local_root, remote_node, remote_root) session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    /// On-disk format version.
    pub version: u32,
    /// Absolute local root (informational).
    pub local_root: String,
    /// Remote node id (64-hex).
    pub remote_node_id: String,
    /// Remote root path.
    pub remote_root: String,
    /// Last-acked remote state per rel_path (conflict base).
    pub remote_seen: BTreeMap<String, RemoteSeen>,
    /// Local file state per rel_path.
    pub entries: BTreeMap<String, IndexEntry>,
}

impl Index {
    /// A fresh, empty index for the given session.
    pub fn new(local_root: &str, remote_node_id: &str, remote_root: &str) -> Self {
        Index {
            version: INDEX_VERSION,
            local_root: local_root.to_string(),
            remote_node_id: remote_node_id.to_string(),
            remote_root: remote_root.to_string(),
            remote_seen: BTreeMap::new(),
            entries: BTreeMap::new(),
        }
    }

    /// The stable 16-hex session id for a (local_root, remote_node, remote_root) tuple.
    pub fn session_id(local_root: &str, remote_node_id: &str, remote_root: &str) -> String {
        let key = format!("{local_root}:{remote_node_id}:{remote_root}");
        let full = cid(key.as_bytes());
        full[..16].to_string()
    }

    /// Default directory for index files: `~/.local/share/rdev/sync/`.
    pub fn default_dir() -> PathBuf {
        // Honor $RDEV_SYNC_DIR for tests / custom data dirs.
        if let Some(d) = std::env::var_os("RDEV_SYNC_DIR") {
            return PathBuf::from(d);
        }
        let base = dirs_next::data_dir()
            .or_else(dirs_next::home_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("rdev").join("sync")
    }

    /// The on-disk path for this index's session inside `dir`.
    pub fn path_in(dir: &Path, local_root: &str, remote_node_id: &str, remote_root: &str) -> PathBuf {
        let sid = Self::session_id(local_root, remote_node_id, remote_root);
        dir.join(format!("{sid}.idx"))
    }

    /// Load the index for this session from `dir`, or a fresh empty one if absent / unreadable /
    /// the wrong version (a version mismatch starts clean — a full reconcile re-derives state).
    pub fn load(dir: &Path, local_root: &str, remote_node_id: &str, remote_root: &str) -> Self {
        let path = Self::path_in(dir, local_root, remote_node_id, remote_root);
        match std::fs::read(&path) {
            Ok(bytes) => match bincode::deserialize::<Index>(&bytes) {
                Ok(idx) if idx.version == INDEX_VERSION => idx,
                _ => Self::new(local_root, remote_node_id, remote_root),
            },
            Err(_) => Self::new(local_root, remote_node_id, remote_root),
        }
    }

    /// Persist the index to `dir` crash-safely: write to a temp file, fsync, atomic rename.
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let final_path =
            Self::path_in(dir, &self.local_root, &self.remote_node_id, &self.remote_root);
        let tmp = final_path.with_extension("idx.tmp");
        let bytes = bincode::serialize(self).context("serialize index")?;
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &final_path).with_context(|| format!("rename into {}", final_path.display()))?;
        Ok(())
    }

    /// Fast-skip test: if the cached entry's `(size, mtime_ms)` match the freshly-stat'd values,
    /// the file is unchanged and need not be re-hashed.
    pub fn is_unchanged(&self, rel_path: &str, size: u64, mtime_ms: u64) -> bool {
        match self.entries.get(rel_path) {
            Some(e) => e.size == size && e.mtime_ms == mtime_ms,
            None => false,
        }
    }

    /// Insert / update a file entry.
    pub fn upsert(&mut self, entry: IndexEntry) {
        self.entries.insert(entry.rel_path.clone(), entry);
    }

    /// Remove a file entry (on delete).
    pub fn remove(&mut self, rel_path: &str) {
        self.entries.remove(rel_path);
    }

    /// Record the last-acked remote state for a path (the conflict base for bidir sync).
    pub fn set_remote_seen(&mut self, rel_path: &str, file_cid: &str, mtime_ms: u64) {
        self.remote_seen.insert(
            rel_path.to_string(),
            RemoteSeen { file_cid: file_cid.to_string(), mtime_ms },
        );
    }

    /// The conflict base CID for a path (empty if the remote was last seen without the file).
    pub fn base_cid(&self, rel_path: &str) -> Option<String> {
        self.remote_seen.get(rel_path).map(|r| r.file_cid.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("rdev-idx-{}-{}-{tag}", std::process::id(), now_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn now_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn entry(p: &str, c: &str, size: u64, mtime: u64) -> IndexEntry {
        IndexEntry {
            rel_path: p.into(),
            file_cid: c.into(),
            size,
            mtime_ms: mtime,
            mode: 0o644,
            chunks: vec![c.into()],
        }
    }

    #[test]
    fn session_id_is_stable_and_16_hex() {
        let a = Index::session_id("/a", "deadbeef", "proj");
        let b = Index::session_id("/a", "deadbeef", "proj");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        // Different inputs -> different session.
        assert_ne!(a, Index::session_id("/b", "deadbeef", "proj"));
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tmp_dir("rt");
        let mut idx = Index::new("/local", &"a".repeat(64), "remote");
        idx.upsert(entry("src/main.rs", "cid1", 10, 111));
        idx.set_remote_seen("src/main.rs", "cid1", 111);
        idx.save(&dir).unwrap();

        let back = Index::load(&dir, "/local", &"a".repeat(64), "remote");
        assert_eq!(back, idx);
        assert_eq!(back.base_cid("src/main.rs").as_deref(), Some("cid1"));
    }

    #[test]
    fn load_missing_returns_fresh() {
        let dir = tmp_dir("missing");
        let idx = Index::load(&dir, "/x", &"b".repeat(64), "r");
        assert!(idx.entries.is_empty());
        assert_eq!(idx.version, INDEX_VERSION);
    }

    #[test]
    fn unchanged_skip_logic() {
        let mut idx = Index::new("/l", "n", "r");
        idx.upsert(entry("a.rs", "c", 100, 5000));
        assert!(idx.is_unchanged("a.rs", 100, 5000));
        assert!(!idx.is_unchanged("a.rs", 101, 5000)); // size changed
        assert!(!idx.is_unchanged("a.rs", 100, 5001)); // mtime changed
        assert!(!idx.is_unchanged("missing.rs", 100, 5000));
    }

    #[test]
    fn remove_and_base_cid() {
        let mut idx = Index::new("/l", "n", "r");
        idx.upsert(entry("a.rs", "c", 1, 1));
        idx.remove("a.rs");
        assert!(!idx.entries.contains_key("a.rs"));
        assert!(idx.base_cid("a.rs").is_none());
    }

    #[test]
    fn save_is_atomic_no_tmp_left() {
        let dir = tmp_dir("atomic");
        let idx = Index::new("/l", &"c".repeat(64), "r");
        idx.save(&dir).unwrap();
        let path = Index::path_in(&dir, "/l", &"c".repeat(64), "r");
        assert!(path.exists());
        assert!(!path.with_extension("idx.tmp").exists(), "temp file must be renamed away");
    }
}
