//! Filesystem walk + scan for Auto-Sync: produce an up-to-date [`Index`] for a local tree, reusing
//! cached chunk CIDs for files whose `(size, mtime_ms)` are unchanged (the rsync fast-skip), and
//! applying the `.ceignore` [`Matcher`].
//!
//! This is the piece the daemon calls on startup (reconcile) and on each debounced batch. It is
//! kept in the library so `ce-pin` can reuse it to snapshot a tree into a [`TreeManifest`].

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use walkdir::WalkDir;

use crate::ceignore::Matcher;
use crate::chunk::{TreeEntry, TreeManifest, chunk_file};
use crate::index::{Index, IndexEntry};

/// A scanned file: its relative path plus the metadata needed to build an [`IndexEntry`].
#[derive(Debug, Clone)]
pub struct ScannedFile {
    pub rel_path: String,
    pub abs_path: PathBuf,
    pub size: u64,
    pub mtime_ms: u64,
    pub mode: u32,
}

/// Load (or build) the `.ceignore` [`Matcher`] for `root`: built-in defaults plus the root's
/// `.ceignore` file if present.
pub fn load_matcher(root: &Path) -> Matcher {
    match std::fs::read_to_string(root.join(".ceignore")) {
        Ok(contents) => Matcher::from_ceignore(&contents),
        Err(_) => Matcher::builtin(),
    }
}

/// Forward-slash relative path of `abs` under `root`.
pub fn rel_of(root: &Path, abs: &Path) -> Option<String> {
    let rel = abs.strip_prefix(root).ok()?;
    if rel.as_os_str().is_empty() {
        return None;
    }
    Some(rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/"))
}

/// File mtime in ms since epoch (0 if unavailable).
pub fn mtime_ms(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Unix mode bits (0 on non-unix).
pub fn mode_of(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.mode()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

/// Walk `root`, skipping ignored entries, returning every regular file as a [`ScannedFile`].
/// Symlinks are not followed; special files are skipped.
pub fn scan_tree(root: &Path) -> Result<Vec<ScannedFile>> {
    let matcher = load_matcher(root);
    let mut out = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).into_iter() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let abs = entry.path();
        let Some(rel) = rel_of(root, abs) else { continue };
        let is_dir = entry.file_type().is_dir();
        if matcher.is_ignored(&rel, is_dir) {
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        out.push(ScannedFile {
            rel_path: rel,
            abs_path: abs.to_path_buf(),
            size: meta.len(),
            mtime_ms: mtime_ms(&meta),
            mode: mode_of(&meta),
        });
    }
    out.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(out)
}

/// Build a fresh [`Index`] for `root`, reusing `prev`'s cached chunk CIDs for any file whose
/// `(size, mtime_ms)` is unchanged (no re-hash). Files that changed are re-chunked. The returned
/// index's `remote_seen` is carried over from `prev` (conflict bases survive a re-walk).
pub fn build_index(root: &Path, prev: &Index) -> Result<Index> {
    let scanned = scan_tree(root)?;
    let mut next =
        Index::new(&prev.local_root, &prev.remote_node_id, &prev.remote_root);
    next.remote_seen = prev.remote_seen.clone();
    for f in scanned {
        if prev.is_unchanged(&f.rel_path, f.size, f.mtime_ms) {
            // Reuse the cached entry verbatim (no re-hash).
            if let Some(e) = prev.entries.get(&f.rel_path) {
                next.upsert(e.clone());
                continue;
            }
        }
        let (cf, _chunks) = chunk_file(&f.abs_path)
            .with_context(|| format!("chunk {}", f.abs_path.display()))?;
        next.upsert(IndexEntry {
            rel_path: f.rel_path,
            file_cid: cf.file_cid,
            size: f.size,
            mtime_ms: f.mtime_ms,
            mode: f.mode,
            chunks: cf.manifest.chunks,
        });
    }
    Ok(next)
}

/// Snapshot `root` into a [`TreeManifest`] (the content id of the whole tree). Used by `ce-pin` to
/// pin a tree by one CID. Reuses `scan_tree` + per-file chunking.
pub fn tree_manifest(root: &Path) -> Result<TreeManifest> {
    let scanned = scan_tree(root)?;
    let mut entries = Vec::new();
    for f in scanned {
        let (cf, _) = chunk_file(&f.abs_path)
            .with_context(|| format!("chunk {}", f.abs_path.display()))?;
        entries.push(TreeEntry { path: f.rel_path, file_cid: cf.file_cid, size: f.size });
    }
    Ok(TreeManifest::from_entries(entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rdev-walk-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn scan_respects_ceignore_and_defaults() {
        let root = tmp("scan");
        std::fs::write(root.join("keep.rs"), b"fn main(){}").unwrap();
        std::fs::write(root.join("skip.log"), b"noise").unwrap();
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(root.join("target/out"), b"build").unwrap();
        std::fs::write(root.join(".ceignore"), b"*.log\n").unwrap();

        let files = scan_tree(&root).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(paths.contains(&"keep.rs"));
        assert!(!paths.iter().any(|p| p.ends_with(".log")), "{paths:?}");
        assert!(!paths.iter().any(|p| p.starts_with("target/")), "{paths:?}");
    }

    #[test]
    fn build_index_reuses_unchanged_and_rechunks_changed() {
        let root = tmp("idx");
        std::fs::write(root.join("a.txt"), b"hello").unwrap();
        let empty = Index::new(&root.to_string_lossy(), "node", "remote");
        let idx1 = build_index(&root, &empty).unwrap();
        assert!(idx1.entries.contains_key("a.txt"));
        let cid1 = idx1.entries["a.txt"].file_cid.clone();

        // Rebuild with no change -> same cid (reused cache path).
        let idx2 = build_index(&root, &idx1).unwrap();
        assert_eq!(idx2.entries["a.txt"].file_cid, cid1);

        // Change content -> mtime/size differ -> rehash -> new cid.
        // Ensure mtime advances (some filesystems have coarse resolution).
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(root.join("a.txt"), b"hello world, longer now").unwrap();
        let idx3 = build_index(&root, &idx2).unwrap();
        assert_ne!(idx3.entries["a.txt"].file_cid, cid1);
    }

    #[test]
    fn tree_manifest_snapshot() {
        let root = tmp("tree");
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        std::fs::write(root.join("b.txt"), b"b").unwrap();
        let t = tree_manifest(&root).unwrap();
        assert_eq!(t.entries.len(), 2);
        assert_eq!(t.entries[0].path, "a.txt");
        assert!(!t.tree_cid.is_empty());
    }
}
