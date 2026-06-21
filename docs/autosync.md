# Auto-Sync v2 (`rdev syncd`)

Continuous, content-addressed, resumable folder sync as a CE **app** — zero node changes. The full
design is `PLAN/05-autosync.md`; this doc records what is implemented in this repo and how the
pieces fit, including the v2-finish follow-ups (chunk-level pull, conflict-policy threading, the
two-node integration test).

## What ships

| Piece | Where |
|---|---|
| Fixed-size 1 MiB chunking + file/tree CID + manifest | `src/chunk.rs` (over `ce-rs::data`) |
| Delta engine (`plan_transfer`, `upload_missing`, `apply_commit_verified`, chunk-level pull) | `src/delta.rs` |
| Crash-safe per-session index (bincode, temp+fsync+rename) | `src/index.rs` |
| `.ceignore` (gitignore semantics, built-in defaults) | `src/ceignore.rs` |
| Walk + `(size,mtime)` fast-skip → fresh `Index` | `src/walk.rs` |
| `rdev/sync2/*` wire types (`have`/`commit`/`delete`/`list`/`manifest`) | `src/syncproto.rs` |
| Conflict engine (LWW / copy; crdt falls back to LWW) | `src/conflict.rs` |
| `syncd` daemon + `serve` sync2 dispatch | `src/main.rs` |

## Protocol verbs (over CE `AppRequest`, JSON hex-encoded)

- `rdev/sync2/have   {caps, chunks}` → `{ok, missing}` — which chunk CIDs the receiver lacks.
- `rdev/sync2/commit {caps, path, file_cid, manifest, base_cid, mode, mtime_ms, policy}` →
  `{ok, applied, conflict, conflict_copy, remote_cid, remote_mtime_ms}`.
- `rdev/sync2/delete {caps, path, base_cid}` → `{ok, deleted, conflict, remote_cid}`.
- `rdev/sync2/list   {caps, prefix}` → `{ok, entries:[{path,file_cid,mtime_ms,mode}]}`.
- `rdev/sync2/manifest {caps, path}` → `{ok, found, file_cid, manifest, mode, mtime_ms}` —
  **chunk-level pull**: returns a remote file's manifest (and publishes its chunks to the blob
  store) so the puller fetches only the chunks it lacks.

Authorization: every verb is checked with `ce_cap::authorize(host, roots, …, action, chain, …)`.
`commit`/`delete` map to the `sync`/`delete` abilities; `have`/`list`/`manifest` map to `sync-read`.
The `path_prefix` caveat + `..` traversal guard apply to every path.

## Bytes never travel in the RPC

A `commit` carries only CIDs. Chunk bytes move through the content-addressed blob store
(`put_blob`/`get_blob`, which is local-first then mesh fetch-by-hash, verified per chunk). A 1-byte
edit in a multi-chunk file ships exactly one chunk; an unchanged re-push ships zero.

## Chunk-level bidirectional pull (v2-finish)

`pull_remote` (under `--bidirectional`) now:
1. `list`s the remote subtree, finds entries whose `file_cid` differs from the local file;
2. for each, fetches the remote **manifest** (`sync2/manifest`);
3. reassembles via `delta::pull_file_verified`, fetching only chunks not already held locally
   (held chunks resolve from the local blob store without a mesh round-trip), and verifies the
   result against the remote `file_cid` before an atomic write.

This replaces the previous whole-file `get_blob(file_cid)` pull. `delta::pull_with_held` is the pure,
unit-tested core (returns `(bytes, n_fetched)` with `n_fetched == plan_pull(...).len()`).

## Conflict-policy threading (v2-finish)

`CommitReq` carries the initiator's chosen `policy` (`lww` | `copy` | `crdt`). The server commit
handler honors it (default LWW when absent, e.g. legacy clients). Every policy preserves the loser
as a conflict copy, so honoring the initiator's request can never make the receiver silently lose
data:
- `lww` — newer `mtime_ms` wins (deterministic `file_cid` tie-break); loser kept as a conflict copy.
- `copy` — never overwrite; incoming always lands as a conflict copy.
- `crdt` — falls back to LWW until the shared `TextDoc` engine (co-developed with Notes) lands (M5).

## SSE transport (deferred)

`rdev serve` polls `messages()` every 500 ms. The node exposes `GET /mesh/messages/stream` (SSE),
but the pinned `ce-rs` does not yet wrap it as `messages_stream()`. There is a clear `TODO(M5)` at the
poll site in `serve`; idempotent verbs + reconcile-on-start already recover any missed message, so
polling is correct (only higher-latency) for v1.

## Tests

- Pure unit tests: chunking/CID, delta (`plan_transfer`/`plan_pull`/`pull_with_held`), index
  round-trip + crash-safe write, `.ceignore`, conflict decision table, syncproto round-trips.
- `tests/two_node_sync.rs` — two real in-process nodes (`NEXT_PORT` pattern) over the live mesh:
  one-byte edit ⇒ one chunk re-upload; resume ⇒ zero extra uploads; `copy` policy preserves a
  divergent receiver file; chunk-level pull fetches only the missing chunk. The test skips
  gracefully (prints a `skip:` note, returns) if a node cannot start or the mesh does not converge.
