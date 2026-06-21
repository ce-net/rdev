//! The content-addressed delta engine — the shared substrate Auto-Sync, `ce-pin`, and Notes reuse.
//!
//! Per `PLAN/05-autosync.md` §4 + §9, this is the "dumb files over CID-delta" core, factored so
//! Notes can layer encrypted-attachment shipping and CRDT docs on the identical path. The engine is
//! deliberately transport-agnostic: it computes *which chunks to move* and provides the verified
//! reassembly; the caller wires it to `ce-rs` `put_blob`/`get_blob` and the `rdev/sync2/*` verbs.
//!
//! Core operations:
//!   - [`plan_transfer`] — given a file's chunk CIDs and the receiver's `have`-reply, compute the
//!     set of chunks that must actually be uploaded (deduped, order-preserving).
//!   - [`upload_missing`] — `put_blob` each missing chunk (honoring the blob-retention caveat:
//!     the initiator uploads *before* announcing the commit so chunks are DHT-fetchable).
//!   - [`apply_commit_verified`] — receiver-side: `get_blob` each chunk, reassemble, verify against
//!     the file CID. Pure of the filesystem (the caller does the atomic write).
//!
//! The engine never inlines bytes in the control plane: only CIDs travel in have/commit. Bytes move
//! through the content-addressed blob store, which dedups, self-replicates over the mesh, and
//! verifies every chunk against its CID.

use std::collections::HashSet;

use anyhow::Result;
use ce_rs::CeClient;
use ce_rs::data::Manifest;

use crate::chunk::{ChunkPair, reassemble_verified};

/// Compute the minimal upload set: the distinct chunk CIDs the receiver is missing.
///
/// `local_chunks` is the file's ordered chunk CIDs (with possible repeats — a file of zeros repeats
/// one CID). `receiver_missing` is the receiver's `have`-reply (the subset it does NOT hold).
/// Returns the distinct missing CIDs in first-seen order — these are the only bytes that move.
pub fn plan_transfer(local_chunks: &[String], receiver_missing: &[String]) -> Vec<String> {
    let missing: HashSet<&String> = receiver_missing.iter().collect();
    let mut seen: HashSet<&String> = HashSet::new();
    let mut out = Vec::new();
    for c in local_chunks {
        if missing.contains(c) && seen.insert(c) {
            out.push(c.clone());
        }
    }
    out
}

/// Compute the receiver-side `have` reply: of `requested` chunk CIDs, which are NOT in `held`.
/// (`held` is the receiver's local chunk set — in practice the blob-store keys it already has.)
pub fn compute_missing(requested: &[String], held: &HashSet<String>) -> Vec<String> {
    let mut seen: HashSet<&String> = HashSet::new();
    requested
        .iter()
        .filter(|c| !held.contains(*c) && seen.insert(*c))
        .cloned()
        .collect()
}

/// Upload each `(cid, bytes)` whose CID is in `missing` to the blob store, verifying the store
/// returns the expected CID (mirrors `put_object`'s self-check). Honors the blob-retention caveat:
/// call this **before** sending the `commit`, so the chunks are present and DHT-announced when the
/// receiver pulls them.
///
/// `chunks` is the full `(cid, bytes)` list from chunking; only those in `missing` are uploaded.
pub async fn upload_missing(
    client: &CeClient,
    chunks: &[ChunkPair],
    missing: &[String],
) -> Result<usize> {
    let want: HashSet<&String> = missing.iter().collect();
    let mut uploaded = 0usize;
    // Upload each missing chunk once (dedup: a repeated CID is uploaded a single time).
    let mut done: HashSet<&String> = HashSet::new();
    for (cid, bytes) in chunks {
        if !want.contains(cid) || !done.insert(cid) {
            continue;
        }
        let got = client.put_blob(bytes.clone()).await?;
        if &got != cid {
            anyhow::bail!("blob store returned cid {got}, expected {cid}");
        }
        uploaded += 1;
    }
    Ok(uploaded)
}

/// Compute the chunk-level pull plan: of `manifest`'s ordered chunk CIDs, which distinct CIDs are
/// NOT already in `held` (the puller's local chunk set). These are the only chunks that must be
/// fetched over the wire — chunks the puller already holds (because it pushed or pulled them before)
/// never re-transfer. This is the pull-direction mirror of [`plan_transfer`].
pub fn plan_pull(manifest_chunks: &[String], held: &HashSet<String>) -> Vec<String> {
    compute_missing(manifest_chunks, held)
}

/// Receiver/puller-side: reassemble a file from `manifest` by fetching each distinct chunk via
/// `fetch`, but only for chunks NOT already in `held` (held chunks are supplied from `held_bytes`).
/// Verifies every chunk against its CID and the final bytes against `file_cid`. The number of
/// `fetch` calls equals exactly the size of [`plan_pull`] — i.e. only missing chunks transfer.
/// Returns `(bytes, n_fetched)`.
///
/// This is the pure core of chunk-level bidirectional PULL: the caller supplies a `fetch` closure
/// (wired to `get_blob`, which is local-first then mesh fetch-by-hash) and the set of chunk CIDs it
/// already holds locally; only the genuinely-missing chunks move.
pub fn pull_with_held(
    manifest: &Manifest,
    file_cid: &str,
    held: &HashSet<String>,
    mut held_bytes: impl FnMut(&str) -> Option<Vec<u8>>,
    mut fetch: impl FnMut(&str) -> Result<Vec<u8>>,
) -> Result<(Vec<u8>, usize)> {
    use std::collections::HashMap;
    let mut cache: HashMap<String, Vec<u8>> = HashMap::new();
    let mut fetched = 0usize;
    let mut distinct: Vec<&String> = Vec::new();
    let mut seen: HashSet<&String> = HashSet::new();
    for c in &manifest.chunks {
        if seen.insert(c) {
            distinct.push(c);
        }
    }
    for c in distinct {
        if held.contains(c) {
            if let Some(b) = held_bytes(c) {
                cache.insert(c.clone(), b);
                continue;
            }
        }
        let bytes = fetch(c)?;
        fetched += 1;
        cache.insert(c.clone(), bytes);
    }
    let out = reassemble_verified(manifest, Some(file_cid), |c| {
        cache.get(c).cloned().ok_or_else(|| anyhow::anyhow!("chunk {c} not fetched"))
    })?;
    Ok((out, fetched))
}

/// Receiver-side: fetch every chunk in `manifest` via the blob store, reassemble, and verify the
/// result hashes to `file_cid`. The fetch goes local-first, else mesh fetch-by-hash (already
/// implemented in the node's `get_blob`), and verifies each chunk against its CID. Returns the
/// reconstructed bytes; the caller writes them atomically.
///
/// `get_blob` is itself local-first, so a chunk the node already holds (from a prior push/pull)
/// resolves without any wire transfer — that is what makes chunk-level pull a true delta even
/// though this convenience wrapper fetches every distinct chunk. For an explicit
/// already-held-chunk accounting (and a fetch count), use [`pull_with_held`].
pub async fn apply_commit_verified(
    client: &CeClient,
    manifest: &Manifest,
    file_cid: &str,
) -> Result<Vec<u8>> {
    // Fetch chunks once, cache locally (a file of repeated chunks fetches each CID a single time).
    use std::collections::HashMap;
    let mut cache: HashMap<String, Vec<u8>> = HashMap::new();
    // Pre-fetch distinct chunks.
    let mut distinct: Vec<&String> = Vec::new();
    let mut seen: HashSet<&String> = HashSet::new();
    for c in &manifest.chunks {
        if seen.insert(c) {
            distinct.push(c);
        }
    }
    for c in distinct {
        let bytes = client.get_blob(c).await?;
        cache.insert(c.clone(), bytes);
    }
    reassemble_verified(manifest, Some(file_cid), |c| {
        cache
            .get(c)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("chunk {c} not fetched"))
    })
}

/// Chunk-level PULL against the live blob store: fetch only the chunks of `manifest` that are not in
/// `held` (the puller's already-known chunk CIDs), reassemble, and verify against `file_cid`.
/// Returns `(bytes, n_fetched)` where `n_fetched == plan_pull(manifest.chunks, held).len()` — i.e.
/// only genuinely-missing chunks transfer (held chunks are pulled local-first via `get_blob`, which
/// resolves them without a mesh round-trip, but are not counted as new transfers).
///
/// This is the chunk-granular replacement for fetching a whole file by `file_cid`: a remote file
/// that differs by one chunk costs one `get_blob`, not a whole-file blob.
pub async fn pull_file_verified(
    client: &CeClient,
    manifest: &Manifest,
    file_cid: &str,
    held: &HashSet<String>,
) -> Result<(Vec<u8>, usize)> {
    use std::collections::HashMap;
    let mut cache: HashMap<String, Vec<u8>> = HashMap::new();
    let mut fetched = 0usize;
    let mut seen: HashSet<&String> = HashSet::new();
    for c in &manifest.chunks {
        if !seen.insert(c) {
            continue;
        }
        // Held chunks still resolve via get_blob (local-first), but do not count as a new transfer.
        let bytes = client.get_blob(c).await?;
        if !held.contains(c) {
            fetched += 1;
        }
        cache.insert(c.clone(), bytes);
    }
    let out = reassemble_verified(manifest, Some(file_cid), |c| {
        cache.get(c).cloned().ok_or_else(|| anyhow::anyhow!("chunk {c} not fetched"))
    })?;
    Ok((out, fetched))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::chunk_bytes;

    #[test]
    fn plan_transfer_returns_only_missing_deduped() {
        let local = vec!["a".to_string(), "b".to_string(), "a".to_string(), "c".to_string()];
        // receiver is missing a and c.
        let missing = vec!["a".to_string(), "c".to_string()];
        let plan = plan_transfer(&local, &missing);
        // a appears twice in local but is uploaded once; order preserved (a before c).
        assert_eq!(plan, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn plan_transfer_empty_when_receiver_has_all() {
        let local = vec!["a".into(), "b".into()];
        let plan = plan_transfer(&local, &[]);
        assert!(plan.is_empty());
    }

    #[test]
    fn one_byte_edit_moves_one_chunk() {
        // A multi-chunk file; edit one byte in the first chunk; only that chunk's CID changes.
        let mut data: Vec<u8> = (0..(crate::chunk::CHUNK_SIZE * 3) as u32).map(|i| i as u8).collect();
        let (orig, _) = chunk_bytes(&data);
        data[5] ^= 0xff;
        let (edited, _) = chunk_bytes(&data);

        assert_eq!(orig.chunk_cids().len(), edited.chunk_cids().len());
        // Exactly the first chunk differs.
        assert_ne!(orig.chunk_cids()[0], edited.chunk_cids()[0]);
        assert_eq!(orig.chunk_cids()[1], edited.chunk_cids()[1]);
        assert_eq!(orig.chunk_cids()[2], edited.chunk_cids()[2]);

        // Receiver already has the original's chunks. Plan transfer for the edited file:
        let held: HashSet<String> = orig.chunk_cids().iter().cloned().collect();
        let missing = compute_missing(edited.chunk_cids(), &held);
        let plan = plan_transfer(edited.chunk_cids(), &missing);
        assert_eq!(plan.len(), 1, "exactly one chunk should move on a one-byte edit");
        assert_eq!(plan[0], edited.chunk_cids()[0]);
    }

    #[test]
    fn dedup_identical_file_at_two_paths_uploads_once() {
        // Two files with identical content: the second uploads zero new chunks.
        let data = vec![9u8; crate::chunk::CHUNK_SIZE * 2];
        let (f1, _) = chunk_bytes(&data);
        let held: HashSet<String> = f1.chunk_cids().iter().cloned().collect();
        let (f2, _) = chunk_bytes(&data);
        let missing = compute_missing(f2.chunk_cids(), &held);
        assert!(missing.is_empty(), "identical content should need no new chunks");
        assert!(plan_transfer(f2.chunk_cids(), &missing).is_empty());
    }

    #[test]
    fn compute_missing_dedups_and_filters_held() {
        let requested = vec!["a".into(), "a".into(), "b".into(), "c".into()];
        let held: HashSet<String> = ["b".to_string()].into_iter().collect();
        let missing = compute_missing(&requested, &held);
        assert_eq!(missing, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn plan_pull_returns_only_unheld_chunks() {
        let manifest = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let held: HashSet<String> = ["b".to_string()].into_iter().collect();
        // Pulling: the puller already holds b, so only a and c must be fetched.
        assert_eq!(plan_pull(&manifest, &held), vec!["a".to_string(), "c".to_string()]);
        // Holding everything -> nothing transfers.
        let all: HashSet<String> = manifest.iter().cloned().collect();
        assert!(plan_pull(&manifest, &all).is_empty());
    }

    #[test]
    fn pull_with_held_fetches_only_missing_chunks() {
        // A 3-chunk file; the puller already holds chunk 1 and 2, lacks chunk 0 (one-byte edit case).
        let mut data: Vec<u8> = (0..(crate::chunk::CHUNK_SIZE * 3) as u32).map(|i| i as u8).collect();
        data[3] ^= 0xff;
        let (cf, chunks) = chunk_bytes(&data);
        let store: std::collections::HashMap<String, Vec<u8>> = chunks.into_iter().collect();
        // Held = the unchanged tail chunks (1 and 2).
        let cids = cf.chunk_cids();
        let held: HashSet<String> = [cids[1].clone(), cids[2].clone()].into_iter().collect();

        let mut fetch_calls = 0usize;
        let (out, fetched) = pull_with_held(
            &cf.manifest,
            &cf.file_cid,
            &held,
            |c| store.get(c).cloned(), // held-bytes source
            |c| {
                fetch_calls += 1;
                store.get(c).cloned().ok_or_else(|| anyhow::anyhow!("missing {c}"))
            },
        )
        .unwrap();
        assert_eq!(out, data, "reassembled bytes must match");
        assert_eq!(fetched, 1, "exactly one chunk fetched on a one-byte edit pull");
        assert_eq!(fetch_calls, 1, "fetch closure called once (only the missing chunk)");
    }

    #[test]
    fn pull_with_held_verifies_file_cid() {
        let data = vec![3u8; crate::chunk::CHUNK_SIZE + 7];
        let (cf, chunks) = chunk_bytes(&data);
        let store: std::collections::HashMap<String, Vec<u8>> = chunks.into_iter().collect();
        let held: HashSet<String> = HashSet::new();
        // Wrong expected file_cid -> error.
        let err = pull_with_held(
            &cf.manifest,
            "deadbeef",
            &held,
            |_| None,
            |c| store.get(c).cloned().ok_or_else(|| anyhow::anyhow!("missing {c}")),
        )
        .unwrap_err();
        assert!(err.to_string().contains("deadbeef"), "{err}");
    }
}
