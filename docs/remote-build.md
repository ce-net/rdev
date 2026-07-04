# Remote build/test over the CE mesh

Dogfood CE's own tooling for distributed builds: run a heavy `cargo build`/`cargo test` on a
beefy remote (the Hetzner relay, or any node you hold a capability for) and watch the logs stream
back live — instead of bespoke `ssh + rsync + cargo`.

This is `rdev build` / `rdev run`: source is content-addressed-synced over the mesh, the build runs
on the remote **host** (network on, persistent `target/`), and stdout+stderr stream back live over
request/reply. No new node RPCs, no `ssh`, no `rsync`.

## Why CE instead of ssh+rsync+cargo

- **No ssh.** Reachability is the CE mesh: device-to-device over libp2p (relay/NAT-traversed),
  addressed by node-id, never a stored `ip:port`. The remote can be behind NAT.
- **Capability-authed, not a login.** The remote runs `rdev serve` and honors a signed, attenuating
  capability chain rooted at *its own* key (see `ce/docs/capabilities.md`). The build runs under the
  `spawn` ability plus a `$RDEV_SPAWN_ALLOW` program-basename allowlist (default-deny) and cwd
  confinement — a far tighter blast radius than an ssh shell. Revocation = on-chain + expiry.
- **Content-addressed sync, not rsync.** `rdev build` runs `syncd --once`: files are chunked
  client-side, the receiver is asked which chunk CIDs it lacks, and only the missing chunks move
  (via the blob store, by hash). An unchanged tree transfers nothing; a one-line edit transfers one
  chunk. A crash-safe index gives fast-skip + resume. `.ceignore` is honored (and `target/`, `.git`,
  `node_modules` are skipped by default).
- **Live logs, no stream primitive, no request cap.** `rdev exec` is the *wrong* tool for a long
  build: it is a sandboxed container with network OFF, no persistent `target/`, buffered output, and
  a 10-minute request cap. `rdev run`/`rdev build` instead start a **detached host job** whose
  stdout+stderr stream to `~/.rdev/jobs/<job_id>/log`, then poll `rdev/run/logs` (~700 ms) — each
  poll is a short, cheap request, so there is no long-held connection and the 10-min cap never
  applies. The remote `target/` persists between runs, so incremental builds are fast.
- **Correct exit code over the mesh.** A wrapper records the child's exit code to a `status` file;
  `rdev/run/logs` surfaces `running` + `exit_code`, and `rdev run` exits with the job's code. Ctrl-C
  on the client sends `rdev/run/kill` and signals the remote job's whole process group.

## One-time setup

### On the remote (the build host — e.g. the relay)

1. A CE node is running and reachable on the mesh (`ce start`; on the relay, the `ce-relay`
   systemd service runs `ce start --no-mine --port 4001 --api-port 8844`).

2. `rdev serve` is running, with the `spawn` allowlist set. On the relay this is a systemd unit
   `/etc/systemd/system/rdev-serve.service`:

   ```ini
   [Unit]
   Description=rdev serve (remote-dev over CE mesh)
   After=network-online.target ce-relay.service
   Wants=network-online.target

   [Service]
   Type=simple
   Environment=HOME=/root
   Environment=RDEV_SPAWN_ALLOW=bash,sh,cargo
   ExecStart=/usr/local/bin/rdev serve
   Restart=always
   RestartSec=3

   [Install]
   WantedBy=multi-user.target
   ```

   `RDEV_SPAWN_ALLOW` is a default-deny allowlist of program **basenames** the `run`/`spawn` actions
   may launch. `bash,sh,cargo` is enough for `bash -lc "… cargo …"`. With HOME=/root, cwd is
   confined under `/root` and `rdev build … --remote build/ce-dogfood` writes the tree to
   `/root/build/ce-dogfood`.

3. Issue the client a capability. The remote (resource owner) self-issues, signed by its own key:

   ```bash
   # On the REMOTE:
   ce grant <client-node-id> --can sync,spawn --expires 7d
   # → prints a token. `sync` authorizes the content-addressed sync (rdev/sync2/*);
   #   `spawn` authorizes rdev/run/* (long-lived host jobs). Copy the token.
   ```

### On your machine (the client)

1. A local CE node is running (`ce start`) — `rdev` talks to it over the local HTTP API and the node
   moves the bytes over the mesh. **The local node must be a current build that speaks the live mesh
   wire protocol** (directed `AppRequest` over `/ce/rpc/1`, blob store, `/mesh/request` with API
   token). A stale node silently fails directed requests (see Troubleshooting).

2. Add a config alias (`~/.config/rdev/config.toml`, or `~/Library/Application Support/rdev/config.toml`
   on macOS):

   ```toml
   [node]
   url = "http://127.0.0.1:8844"

   [alias.hetzner]
   node_id = "21f5c206ffbf88d7bebdf9078d687e30be5b9a3c6e7ac752e018a559faf171d4"
   cap = "<the token ce grant printed on the remote>"
   ```

   `node_id` is the remote's CE node id (`ce id` on the remote); `cap` is the token from step 3.

## The dogfooded dev loop

One command — content-addressed-sync a worktree to the remote, then build there with live logs:

```bash
rdev build hetzner <a-ce-worktree-dir> --remote build/ce-dogfood -- \
  bash -lc "source /root/.cargo/env && cargo check -p ce-chain"
```

- `<a-ce-worktree-dir>` is your local `ce` checkout; it is synced (chunk-delta) to
  `~/build/ce-dogfood` on the remote.
- `--remote build/ce-dogfood` is the remote subdir (relative to the remote's HOME). Defaults to the
  local dir's basename.
- everything after `--` is the command, run with cwd = the synced remote dir, output streamed live.
- `rdev build` exits with the remote command's exit code.

`source /root/.cargo/env` puts `cargo` on PATH (the scrubbed env keeps only PATH + HOME). Pick a
**fast, representative per-crate check** (`cargo check -p ce-chain`) for the tight loop; swap in
`cargo test --workspace` for a full run — the remote `target/` persists, so the second run is
incremental.

If the one-command `rdev build` has rough edges, the two explicit steps are equivalent:

```bash
rdev syncd <a-ce-worktree-dir> hetzner:build/ce-dogfood --once       # content-addressed push
rdev run   hetzner --cwd build/ce-dogfood -- \
  bash -lc "source /root/.cargo/env && cargo check -p ce-chain"      # run with live logs + exit code
```

## Wire protocol (what moves over the mesh)

All over CE `AppRequest` (topic `rdev/<action>`), JSON payloads, request/reply only:

| step | verbs | effect |
|---|---|---|
| sync | `rdev/sync2/have` → `rdev/sync2/commit` | ask which chunk CIDs are missing, upload only those (via the blob store), commit the manifest |
| start | `rdev/run/start` | spawn a detached host job (own session/process group), stdout+stderr → `~/.rdev/jobs/<job_id>/log`; returns `{job_id}` |
| stream | `rdev/run/logs` (poll ~700 ms) | `{data_hex, next_offset, running, exit_code}` — delta log read + liveness |
| cancel | `rdev/run/kill` | Ctrl-C → signal the job's whole process group (idempotent) |

`run/*` is gated by the **`spawn`** ability (it runs native host code, unlike sandboxed `exec`),
plus the `$RDEV_SPAWN_ALLOW` basename allowlist + cwd confinement + a scrubbed environment.

## Troubleshooting

- **`CE API 504 "peer app did not reply in time"` or `502 "outbound failure: unexpected end of
  file"`** on every request, while the remote's `rdev serve` is up and other peers reach it: your
  **local** `ce` node binary is too old to speak the current mesh wire protocol. Symptoms on the
  local node's logs are constant `bad syncresp / bad block gossip: unexpected end of file`, an empty
  `/atlas`, and a hanging `/status` (older `--light` builds). The remote node will *see* your node in
  its `/atlas`, but your directed `AppRequest` payload never lands in the remote node's
  `/mesh/messages`. Fix: update the local `ce` binary (build current `ce`, or install a current
  release) and re-run. rdev itself is unaffected — the break is entirely in the node transport.
- **`run denied: '<prog>' not in RDEV_SPAWN_ALLOW`**: add the program basename to the remote's
  `$RDEV_SPAWN_ALLOW` (e.g. `bash`) and restart `rdev serve`.
- **`denied: …` (capability)**: the cap is expired, revoked, lacks the needed ability (`sync` for
  the push, `spawn` for `run`), or isn't rooted at the remote's key. Re-issue with `ce grant`.
- **A local CE node is required**: `rdev` errors `local CE node not reachable` if `ce start` isn't
  running — it is the mesh transport for the client side.
</content>
</invoke>
