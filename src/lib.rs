//! rdev substrate library — the content-addressed chunk/CID delta-sync engine (Auto-Sync v2).
//!
//! This crate exposes, as a reusable library, the lower half that Auto-Sync, `ce-pin`, and Notes
//! all build on (see `PLAN/05-autosync.md` §9): content-addressed chunking, per-file/per-tree
//! manifests, the delta engine ("which chunks does the receiver lack → send only those"), a
//! crash-safe index, `.ceignore` matching, the `rdev/sync2/*` wire types, and conflict handling.
//!
//! The `rdev` binary (`src/main.rs`) is the first consumer: it wires these modules to `ce-rs`
//! transport + `ce-cap` authorization to provide `rdev syncd` continuous folder sync. `ce-pin` and
//! Notes depend on this same crate for the identical CID/delta path — file sync is the "dumb files
//! over CID-delta" consumer; Notes layers CRDT/encryption on the same engine.
//!
//! Design constraints honored: edition 2024; `anyhow::Result` on fallible public fns; no `unsafe`;
//! no `unwrap`/`expect` in production paths (tests excepted); bincode for disk (the index); pure
//! unit-testable cores for chunking, delta, ignore, index, and conflict logic.

pub mod ceignore;
pub mod chunk;
pub mod conflict;
pub mod delta;
pub mod index;
pub mod syncproto;
pub mod walk;

// Re-export the most-used items at the crate root for ergonomic downstream use.
pub use chunk::{ChunkedFile, TreeEntry, TreeManifest, chunk_bytes, chunk_file, content_id};
pub use conflict::{ConflictInput, Policy, Resolution, resolve};
pub use delta::{
    apply_commit_verified, compute_missing, plan_pull, plan_transfer, pull_file_verified,
    pull_with_held, upload_missing,
};
pub use index::{Index, IndexEntry};
