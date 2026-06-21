//! Content-addressed chunking for the Auto-Sync v2 substrate.
//!
//! This is the thin, reusable layer over `ce-rs::data` that Auto-Sync, `ce-pin`, and Notes all
//! share. The actual byte-splitting / CID / manifest machinery lives in `ce-rs::data`
//! ([`chunk_object`], [`reassemble`], [`cid`], [`Manifest`]) — the same code the node's blob store
//! is keyed by. We re-export it here so downstream apps depend on one stable surface (`rdev::chunk`)
//! and so we can layer the *file*-level helpers (chunk a file, compute its file CID, a per-tree
//! manifest) without re-implementing chunking.
//!
//! Design (per `PLAN/05-autosync.md` §4–5): **fixed-size 1 MiB chunks**. The design explicitly
//! reuses `ce-rs::data`'s fixed-size chunker (rolling-hash content-defined chunking is a noted
//! future option but not the v1 substrate). A file's CID is `sha256(file_bytes)`; its chunk list is
//! the manifest's `chunks`. Unchanged chunks share a CID across files and across edits — that is the
//! whole point of delta transfer.

use std::path::Path;

use anyhow::{Context, Result};
use ce_rs::data::{self, DEFAULT_CHUNK_SIZE, Manifest, chunk_object};
use ce_rs::cid;
use serde::{Deserialize, Serialize};

/// Re-export the canonical chunk size (1 MiB) so callers do not hard-code it.
pub use ce_rs::data::DEFAULT_CHUNK_SIZE as CHUNK_SIZE;

/// The content id (lowercase-hex sha256) of a byte slice. Re-exported from `ce-rs` so the substrate
/// and the node's `/blobs` store agree on keying.
pub fn content_id(bytes: &[u8]) -> String {
    cid(bytes)
}

/// A chunked file: its full-file CID plus the ordered manifest of its chunk CIDs.
///
/// `file_cid == cid(file_bytes)` and is what a `commit` cross-checks against the reassembled bytes.
/// The `manifest` is the `ce-object-v1` manifest (chunk size, total size, ordered chunk CIDs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkedFile {
    /// `sha256` of the whole file's bytes (hex). Equal to the reassembled-bytes hash.
    pub file_cid: String,
    /// The ordered chunk manifest (`ce-object-v1`).
    pub manifest: Manifest,
}

/// A `(cid, chunk_bytes)` pair ready to hand to `put_blob`. The CID is the chunk's content id.
pub type ChunkPair = (String, Vec<u8>);

impl ChunkedFile {
    /// The ordered chunk CIDs of this file.
    pub fn chunk_cids(&self) -> &[String] {
        &self.manifest.chunks
    }

    /// Total size in bytes.
    pub fn size(&self) -> u64 {
        self.manifest.total_size
    }
}

/// Chunk `bytes` into fixed-size chunks, returning the [`ChunkedFile`] (file CID + manifest) and the
/// `(cid, chunk_bytes)` pairs ready to hand to `put_blob`. The manifest is *not* among the returned
/// chunks (store it as its own blob if you need the object-CID indirection; for file sync the
/// `file_cid` plus the explicit manifest in the `commit` are enough).
pub fn chunk_bytes(bytes: &[u8]) -> (ChunkedFile, Vec<ChunkPair>) {
    let file_cid = cid(bytes);
    let (manifest, chunks) = chunk_object(bytes, DEFAULT_CHUNK_SIZE);
    (ChunkedFile { file_cid, manifest }, chunks)
}

/// Read a file from disk and chunk it. Returns the [`ChunkedFile`] plus the chunk byte payloads.
pub fn chunk_file(path: &Path) -> Result<(ChunkedFile, Vec<ChunkPair>)> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(chunk_bytes(&bytes))
}

/// Reassemble a file's bytes from its manifest, pulling each chunk via `fetch` and verifying every
/// chunk against its CID (trustless). Re-exported behaviour of `ce-rs::data::reassemble`, plus a
/// cross-check that the reassembled bytes hash to `expected_file_cid` when provided.
pub fn reassemble_verified(
    manifest: &Manifest,
    expected_file_cid: Option<&str>,
    fetch: impl FnMut(&str) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let out = data::reassemble(manifest, fetch)?;
    if let Some(want) = expected_file_cid {
        let got = cid(&out);
        if got != want {
            anyhow::bail!("reassembled file cid {got} != expected {want}");
        }
    }
    Ok(out)
}

/// A per-tree manifest: a snapshot of every regular file in a subtree, addressed by relative path.
///
/// `ce-pin` pins a whole tree by its [`TreeManifest`] (pin the root CID → pin every file CID → every
/// chunk CID). Notes addresses a notebook the same way. The `tree_cid` is a deterministic hash over
/// the sorted `(path, file_cid)` entries, so two trees with identical content have identical
/// `tree_cid` regardless of walk order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeManifest {
    /// Format discriminator.
    pub kind: String,
    /// Deterministic hash over the sorted entries (the tree's content id).
    pub tree_cid: String,
    /// Sorted (by `path`) file entries.
    pub entries: Vec<TreeEntry>,
}

/// One file in a [`TreeManifest`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TreeEntry {
    /// Forward-slash relative path from the tree root.
    pub path: String,
    /// `sha256` of the file's bytes.
    pub file_cid: String,
    /// File size in bytes.
    pub size: u64,
}

/// `kind` tag for the v1 tree manifest.
pub const TREE_MANIFEST_KIND_V1: &str = "ce-tree-v1";

impl TreeManifest {
    /// Build a tree manifest from `(path, file_cid, size)` entries. Entries are sorted by path and
    /// the `tree_cid` is derived deterministically, so the result is independent of input order.
    pub fn from_entries(mut entries: Vec<TreeEntry>) -> Self {
        entries.sort();
        let tree_cid = Self::compute_tree_cid(&entries);
        TreeManifest { kind: TREE_MANIFEST_KIND_V1.to_string(), tree_cid, entries }
    }

    /// All distinct file CIDs referenced by this tree (for pinning / GC roots).
    pub fn file_cids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.entries.iter().map(|e| e.file_cid.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    fn compute_tree_cid(sorted: &[TreeEntry]) -> String {
        // Hash the canonical "path\0file_cid\0size\n" lines. Deterministic and order-independent
        // (the slice is pre-sorted). Not a Merkle proof — just a stable content id for the tree.
        let mut buf = String::new();
        for e in sorted {
            buf.push_str(&e.path);
            buf.push('\0');
            buf.push_str(&e.file_cid);
            buf.push('\0');
            buf.push_str(&e.size.to_string());
            buf.push('\n');
        }
        cid(buf.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_bytes_roundtrips_and_file_cid_matches() {
        let data: Vec<u8> = (0..2_500_000u32).map(|i| (i % 251) as u8).collect();
        let (cf, chunks) = chunk_bytes(&data);
        assert_eq!(cf.file_cid, content_id(&data));
        // 2_500_000 / 1_048_576 -> 3 chunks.
        assert_eq!(cf.chunk_cids().len(), 3);
        assert_eq!(cf.size(), 2_500_000);

        let store: std::collections::HashMap<String, Vec<u8>> = chunks.into_iter().collect();
        let back = reassemble_verified(&cf.manifest, Some(&cf.file_cid), |c| {
            store.get(c).cloned().ok_or_else(|| anyhow::anyhow!("missing {c}"))
        })
        .unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn reassemble_rejects_wrong_file_cid() {
        let data = b"hello world".to_vec();
        let (cf, chunks) = chunk_bytes(&data);
        let store: std::collections::HashMap<String, Vec<u8>> = chunks.into_iter().collect();
        let err = reassemble_verified(&cf.manifest, Some("deadbeef"), |c| Ok(store[c].clone()))
            .unwrap_err();
        assert!(err.to_string().contains("expected deadbeef"), "{err}");
    }

    #[test]
    fn identical_content_shares_chunk_cids() {
        let a = vec![7u8; CHUNK_SIZE * 2];
        let (cfa, _) = chunk_bytes(&a);
        let (cfb, _) = chunk_bytes(&a);
        assert_eq!(cfa.chunk_cids(), cfb.chunk_cids());
        // Both chunks of an all-same file are the same CID (dedup).
        assert_eq!(cfa.chunk_cids()[0], cfa.chunk_cids()[1]);
    }

    #[test]
    fn empty_file_has_no_chunks() {
        let (cf, chunks) = chunk_bytes(&[]);
        assert!(cf.chunk_cids().is_empty());
        assert!(chunks.is_empty());
        assert_eq!(cf.size(), 0);
        assert_eq!(cf.file_cid, content_id(b""));
    }

    #[test]
    fn tree_manifest_is_order_independent() {
        let e1 = TreeEntry { path: "b.rs".into(), file_cid: "11".into(), size: 2 };
        let e2 = TreeEntry { path: "a.rs".into(), file_cid: "22".into(), size: 3 };
        let t1 = TreeManifest::from_entries(vec![e1.clone(), e2.clone()]);
        let t2 = TreeManifest::from_entries(vec![e2, e1]);
        assert_eq!(t1.tree_cid, t2.tree_cid);
        // Sorted by path.
        assert_eq!(t1.entries[0].path, "a.rs");
        assert_eq!(t1.entries[1].path, "b.rs");
    }

    #[test]
    fn tree_manifest_file_cids_dedup() {
        let t = TreeManifest::from_entries(vec![
            TreeEntry { path: "a".into(), file_cid: "x".into(), size: 1 },
            TreeEntry { path: "b".into(), file_cid: "x".into(), size: 1 },
            TreeEntry { path: "c".into(), file_cid: "y".into(), size: 1 },
        ]);
        assert_eq!(t.file_cids(), vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn tree_cid_changes_with_content() {
        let base = TreeManifest::from_entries(vec![TreeEntry {
            path: "a".into(),
            file_cid: "x".into(),
            size: 1,
        }]);
        let changed = TreeManifest::from_entries(vec![TreeEntry {
            path: "a".into(),
            file_cid: "y".into(),
            size: 1,
        }]);
        assert_ne!(base.tree_cid, changed.tree_cid);
    }
}
