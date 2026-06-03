# rdev

Remote-dev services over the CE mesh — built as an **application on CE**, not as node features.

This repo is the reference for CE's primitives-vs-apps boundary. Device-to-device features belong
in apps over CE's primitives, **not** in the node as bespoke RPCs/endpoints/consensus types. rdev
moves files between machines, authorized by capabilities, using only:

- **`ce-rs`** — the mesh transport: directed request/response (`AppRequest`/`reply`), `/status`.
- **`ce-cap`** — the capability verifier: does a signed, attenuating chain authorize an action?

No new node code, no new consensus tx, no stored IP:port. CE moves the bytes; rdev is the policy.

## Use

```bash
# On the target machine (its node already trusts you via a capability you hold):
rdev serve

# From your machine — push / delete a file on the target, over CE:
rdev push ./Cargo.toml <node-id>:proj/Cargo.toml --cap <token-from: ce grant ... --can sync,delete>
rdev rm <node-id>:proj/Cargo.toml --cap <token>
```

`<token>` is a capability the **target** issued (`ce grant <your-node-id> --can sync,delete`). The
server verifies it with `ce-cap` (chain rooted at the target's own key, attenuation, expiry, and an
optional `path_prefix` caveat confining writes) before touching the filesystem.

## Protocol (over CE `AppRequest`)

Client → target node, topic `rdev/<action>`, JSON payload; the target runs `rdev serve` and replies.

| action | payload | effect |
|---|---|---|
| `rdev/sync` | `{ caps, path, data_hex }` | write a file under the target's home |
| `rdev/delete` | `{ caps, path }` | delete a file (idempotent) |
| `rdev/exec` | `{ caps, image, cmd, cwd }` | run a command in a sandboxed container (gVisor, network off) |
| `rdev/spawn` | `{ caps, cmd, cwd }` | **start a HOST process** (NOT sandboxed); `cwd` confined to home |

`rdev/spawn` is deliberately powerful — it runs native code on the host, which is what lets one node
bring up a CE node + `rdev serve` on another (the basis for self-replicating fleets; see the
`replicator` app). It is reachable only with the `spawn` ability, which a capability must carry
explicitly. `rdev serve` honors chains rooted at this host **or** at any key in `$RDEV_ROOTS`
(else `$CE_DATA_DIR/roots`, else `~/.local/share/ce/roots`) — a fleet shares one org root so a seed
can delegate attenuated caps down a replication tree that every node accepts.

## Status

`sync`, `delete`, `exec`, and `spawn` are implemented and tested — unit tests for the auth path
(self-issued, delegated/org-root, expiry, audience, escalation) plus live mesh end-to-end runs
(`~/ce-net/e2e-local.sh` for sync/delete, `~/ce-net/e2e-replicate.sh` for spawn + delegation).
`tunnel` stays a CE primitive (`ce tunnel`) since it needs raw mesh streams, not request/response.

## Remaining refinements

- Capability **revocation is not consulted** yet (relies on expiry). A node endpoint to query the
  on-chain revocation set would close this.
- The inbox is **polled** (500 ms); switching to the SSE stream is a refinement.
- `sync` ships file bytes inline as `data_hex` in one `AppRequest` — fine for small files; large
  binaries should move to `put_blob`/`get_object` (content-addressed, chunked).
