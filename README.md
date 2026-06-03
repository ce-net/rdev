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

## Roadmap — the rest of the extraction

This v0 proves the pattern with `sync`/`delete` (the `mirror` backend). The other former node
features move here the same way, each gated on one thing:

- **`exec` / `deploy`** — identical pattern; the handler composes the **`ce-container`** primitive
  (bollard/gVisor) + a job store. Straightforward follow-on.
- **`tunnel`** — streaming, not request/response. Needs a CE node primitive that lets a *local app*
  accept/open raw mesh streams (the stream control is currently node-internal). That primitive must
  land in CE first; then `rdev tunnel` is a thin wrapper.
- **Migration** — once proven on a live mesh, the node's `SyncFile`/`SyncDelete` RPCs (and
  `mirror`'s use of them) repoint here, removing the duplicate from CE — the point of the exercise.

## v0 limitations

- Capability **revocation is not consulted** yet (relies on expiry). A node endpoint to query the
  on-chain revocation set would close this.
- The inbox is **polled** (500 ms); switching to the SSE stream is a refinement.
- Untested against a live two-node mesh — it compiles and the protocol is wired, but the end-to-end
  path needs two running nodes to validate.
