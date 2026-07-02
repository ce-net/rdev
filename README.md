# rdev

Remote-dev services over the CE mesh — built as an **application on CE**, not as node features.

This repo is the reference for CE's primitives-vs-apps boundary. Device-to-device features belong
in apps over CE's primitives, **not** in the node as bespoke RPCs/endpoints/consensus types. rdev
moves files between machines, authorized by capabilities, using only:

- **`ce-rs`** — the mesh transport: directed request/response (`AppRequest`/`reply`), `/status`.
- **`ce-cap`** — the capability verifier: does a signed, attenuating chain authorize an action?

No new node code, no new consensus tx, no stored IP:port. CE moves the bytes; rdev is the policy.

> **FILE TRANSFER DISABLED (2026-07-02, by order).** The live sync destroyed a real working tree
> (stale-peer apply after a history rewrite) and cross-node sync2 loses blobs mid-transfer, so every
> file-copying surface — `push`, `rm`, `pull`, `syncd`, `watch`, `gitsync`, `build`, `dev --via`,
> and the serving daemon's sync/sync2/gitsync — is refused until the protocol is hardened
> (base-commit refusal, reliable chunk transport, refused-commit index fix). `exec`, `run`, `spawn`
> and the **local `rdev dev` loop** (moves no files) are unaffected. `RDEV_DANGEROUS_SYNC=1` on both
> ends is the protocol-development-only override. Remote builds: use `tools/ce-build` meanwhile.

## Use

```bash
# THE dev loop — one command in any ceapp directory (defaults read from ceapp.toml):
rdev dev                        # watch -> rebuild -> restart -> stream output (local)
rdev dev --via hetzner          # same loop, but build+run on a remote node over the mesh

# On the target machine (its node already trusts you via a capability you hold):
rdev serve

# From your machine — push / pull / delete a file on the target, over CE:
rdev push ./Cargo.toml <node-id>:proj/Cargo.toml --cap <token-from: ce grant ... --can sync,delete>
rdev pull <target>:proj/target/release/myapp ./myapp    # chunk-level, CID-verified, mode kept
rdev rm <node-id>:proj/Cargo.toml --cap <token>

# Long-running remote run with LIVE logs (gated by the `spawn` ability, like `rdev spawn`):
rdev run <target> --cwd proj -- cargo build --release      # streams output live; Ctrl-C kills it

# One-command dogfooded build/test loop: content-addressed-sync a dir, then run there with live logs:
rdev build <target> ./ce --remote ce -- cargo test --workspace
```

## The dev loop (`rdev dev`)

`rdev dev [dir]` is the one-command local development loop for a ceapp — the answer to "edit,
build, deploy, test on a live domain takes minutes." It reads `ceapp.toml` and needs no config:
the default build is `cargo build --bin <native.bin>` (plus `[build].features`), the default run
is the built executable with `[daemon].args`. On every source change (debounced, `.ceignore`
honored, `target/`/`.git` skipped) it rebuilds and restarts; a FAILING build never kills the
running app — the previous process keeps serving until a build succeeds. Ctrl-C tears everything
down.

`rdev dev --via <target>` is the same loop with the heavy lifting elsewhere: the tree is
content-addressed-synced to the target (only changed chunks move), the build and the app run on
the target host (`spawn`-gated, allowlisted), and logs stream back live. The 4-core laptop never
compiles.

An optional rdev-owned `[dev]` section in `ceapp.toml` overrides any part (ce-appmgr ignores it,
so manifests stay installable everywhere):

```toml
[dev]
build       = "npm run build"      # custom build (sh -c); requires `run`
run         = "npm run preview"    # custom run (sh -c)
args        = ["serve", "--dev"]   # args for the default run (else [daemon].args)
web         = "npm run dev"        # optional frontend dev process, spawned in web_dir
web_dir     = "web"
env         = { RUST_LOG = "debug" }
debounce_ms = 400
```

Full doc: [`docs/dev-loop.md`](docs/dev-loop.md).

`rdev run`/`rdev build` are the dogfooded distributed build/test loop: a 15–30 min `cargo build`
runs on a beefy remote (e.g. the relay) with its output streamed back live, instead of bespoke
`ssh + rsync + cargo`. They poll `rdev/run/logs` (~700 ms) — request/reply only, no stream
primitive — so there is no 10-minute request cap and the remote `target/` persists between runs.

`<token>` is a capability the **target** issued (`ce grant <your-node-id> --can sync,delete`). The
server verifies it with `ce-cap` (chain rooted at the target's own key, attenuation, expiry, and an
optional `path_prefix` caveat confining writes) before touching the filesystem.

## Remote build/test over the mesh

Dogfood CE for distributed builds: run a heavy `cargo build`/`cargo test` on a beefy remote (the
Hetzner relay, or any node you hold a capability for) and watch the logs stream back **live** —
instead of `ssh + rsync + cargo`. Source is content-addressed-synced over the mesh, the build runs
on the remote **host** (network on, persistent `target/`), and the exit code comes back over the
mesh. Full rationale + protocol + troubleshooting: [`docs/remote-build.md`](docs/remote-build.md).

**One-time setup.** On the remote: a current `ce` node + `rdev serve` with the spawn allowlist set
(`RDEV_SPAWN_ALLOW=bash,sh,cargo`), then self-issue the client a capability:

```bash
# On the REMOTE (the build host), as a systemd unit or by hand:
RDEV_SPAWN_ALLOW=bash,sh,cargo rdev serve
ce grant <client-node-id> --can sync,spawn --expires 7d    # → a token; sync = push, spawn = run
```

On your machine: a current `ce start` running, plus a config alias
(`~/.config/rdev/config.toml`; macOS: `~/Library/Application Support/rdev/config.toml`):

```toml
[node]
url = "http://127.0.0.1:8844"

[alias.hetzner]
node_id = "21f5c206ffbf88d7bebdf9078d687e30be5b9a3c6e7ac752e018a559faf171d4"
cap = "<token from `ce grant` on the remote>"
```

**The loop** — one command syncs the worktree, builds remotely, streams logs, returns the exit code:

```bash
# Fast per-crate check (tight loop). Pick a representative crate; target/ persists between runs.
rdev build hetzner <a-ce-worktree-dir> --remote build/ce-dogfood -- \
  bash -lc "source /root/.cargo/env && cargo check -p ce-chain"

# Full run: same shape, just a heavier command.
rdev build hetzner <a-ce-worktree-dir> --remote build/ce-dogfood -- \
  bash -lc "source /root/.cargo/env && cargo test --workspace"
```

If `rdev build` has rough edges, the two explicit steps are equivalent:

```bash
rdev syncd <a-ce-worktree-dir> hetzner:build/ce-dogfood --once       # content-addressed push
rdev run   hetzner --cwd build/ce-dogfood -- \
  bash -lc "source /root/.cargo/env && cargo check -p ce-chain"      # live logs + exit code
```

`source /root/.cargo/env` puts `cargo` on PATH (the run env is scrubbed to PATH + HOME).
**Note:** the client's local `ce` node must be a current build that speaks the live mesh wire
protocol; a stale node fails directed requests with `504 peer app did not reply in time` /
`502 outbound failure` even though `rdev serve` is healthy on the remote. See the Troubleshooting
section of [`docs/remote-build.md`](docs/remote-build.md).

## Protocol (over CE `AppRequest`)

Client → target node, topic `rdev/<action>`, JSON payload; the target runs `rdev serve` and replies.

| action | payload | effect |
|---|---|---|
| `rdev/sync` | `{ caps, path, data_hex }` | write a file under the target's home |
| `rdev/delete` | `{ caps, path }` | delete a file (idempotent) |
| `rdev/exec` | `{ caps, image, cmd, cwd }` | run a command in a sandboxed container (gVisor, network off) |
| `rdev/spawn` | `{ caps, cmd, cwd }` | **start a HOST process** (NOT sandboxed); `cwd` confined to home |
| `rdev/run/start` | `{ caps, cmd, cwd }` | start a **long-lived detached HOST job**; stdout+stderr → logfile; returns `{ job_id }` |
| `rdev/run/logs` | `{ caps, job_id, offset }` | delta log read + liveness: `{ data_hex, next_offset, running, exit_code }` |
| `rdev/run/kill` | `{ caps, job_id }` | signal the job's process group (idempotent) |

`rdev/run/*` is the CE-native long-running remote run with **live logs**, request/reply only (no new
stream primitive): `run/start` spawns the child detached in its own session/process group with
stdout+stderr redirected to `~/.rdev/jobs/<job_id>/log`, wrapped so its exit code lands in a `status`
file on completion. `run/logs` is a short, cheap poll — read the log from `offset`, report
running/exit — so the buffered-`exec` 10-minute request cap never applies and a 15–30 min build is
fully observable. Jobs persist on disk (logs survive a `serve` restart) with a small retention cap.
`run/*` is gated by the **same `spawn` ability** + `$RDEV_SPAWN_ALLOW` basename allowlist + cwd
confinement + scrubbed env as `rdev/spawn` (it runs native host code), unlike sandboxed `exec`.

`rdev/spawn` is deliberately powerful — it runs native code on the host, which is what lets one node
bring up a CE node + `rdev serve` on another (the basis for self-replicating fleets; see the
`replicator` app). It is reachable only with the `spawn` ability, which a capability must carry
explicitly. `rdev serve` honors chains rooted at this host **or** at any key in `$RDEV_ROOTS`
(else `$CE_DATA_DIR/roots`, else `~/.local/share/ce/roots`) — a fleet shares one org root so a seed
can delegate attenuated caps down a replication tree that every node accepts.

## Status

`sync`, `delete`, `exec`, `spawn`, and `run/*` (long-lived host jobs with live logs) are implemented
and tested — unit tests for the auth path
(self-issued, delegated/org-root, expiry, audience, escalation) plus live mesh end-to-end runs
(`~/ce-net/e2e-local.sh` for sync/delete, `~/ce-net/e2e-replicate.sh` for spawn + delegation).
`tunnel` stays a CE primitive (`ce tunnel`) since it needs raw mesh streams, not request/response.

## Remaining refinements

- Capability **revocation is not consulted** yet (relies on expiry). A node endpoint to query the
  on-chain revocation set would close this.
- The inbox is **polled** (500 ms); switching to the SSE stream is a refinement.
- `sync` ships file bytes inline as `data_hex` in one `AppRequest` — fine for small files; large
  binaries should move to `put_blob`/`get_object` (content-addressed, chunked).
