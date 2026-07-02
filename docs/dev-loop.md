# The ceapp dev loop — `rdev dev`

One command to develop any ceapp: watch the sources, rebuild on change, restart the app, stream
its output. Locally by default; on a beefy remote node with `--via`. This is the tool the
2026-06-25 dev-environment review named the single highest-leverage missing piece ("no `ce-app
dev` that runs the whole stack with hot reload — this would have turned this session from hours
into minutes").

## Zero-config defaults (the manifest is the source of truth)

`rdev dev [dir]` reads `<dir>/ceapp.toml`:

| What | Default | Override |
|---|---|---|
| build | `cargo build --bin <[native].bin>` + `[build].features` | `[dev].build` (sh -c) |
| run | the built executable + `[daemon].args` | `[dev].run` (sh -c), `[dev].args` |
| watch | the whole dir, `.ceignore` honored; `target/`, `.git`, `node_modules`, editor droppings skipped | — |
| frontend | none | `[dev].web` (sh -c) in `[dev].web_dir` (default `web/`) |
| env | inherited | `[dev].env` table |
| debounce | 500 ms | `[dev].debounce_ms` |

The executable path comes from cargo's JSON messages, so shared target dirs (the workspace
`.cargo-shared` remap) resolve correctly. `--release` builds release (default is debug for fast
iteration). `--no-web` skips the frontend process.

`[dev]` is rdev-owned: ce-appmgr's manifest parser ignores unknown sections, so a manifest with
`[dev]` still installs and publishes everywhere unchanged.

## Loop semantics

- A failing build never kills the running app. The previous process keeps serving; the next
  successful build swaps it.
- Restart kills the whole process group (the app, its `sh -c` wrapper, its children), then
  spawns the new build.
- If the app exits on its own, the loop reports it and relaunches on the next successful build.
- Ctrl-C tears down the app, the web process, and (in `--via` mode) the remote job.

## `--via <target>`: the loop without local compiles

`rdev dev --via hetzner` keeps the watcher local and moves everything else to the target
(a config alias from `~/.config/rdev/config.toml`, or a 64-hex node id):

1. The tree is content-addressed-synced to `<target>:dev/<app>` — only changed chunks move; the
   remote `target/` persists, so rebuilds are incremental.
2. One remote host job runs `build && exec run` (`spawn`-ability-gated, `RDEV_SPAWN_ALLOW`
   allowlisted, cwd-confined — same gating as `rdev run`).
3. Logs stream back live (the ~700 ms `rdev/run/logs` poll — no long-held connection).
4. On a local change: kill the remote job, sync the delta, restart. On Ctrl-C: kill and exit.

Same primitives as `rdev build`/`rdev run`; NAT-traversing, capability-authed, no ssh.

Note: `[dev].web` always runs locally (the browser is local); only build+run move to the target.

## Companion verb: `rdev pull`

`rdev pull <target>:<path> [out]` fetches one file back over the mesh (chunk-level via the blob
store, file-CID-verified, mode bits preserved so binaries stay executable). It is the counterpart
of `push` and what lets `ce-publish app --build --via linux-amd64=hetzner` retrieve remotely-built
release artifacts without ssh/scp — publishing composes rdev as an app.

## Requirements

- Local mode: a running local node (`ce start`) — the loop itself is plain cargo + processes.
- `--via` mode: the target runs `rdev serve` with `RDEV_SPAWN_ALLOW=bash,sh,cargo`, and you hold
  a capability with `sync,spawn` (plus `sync-read` if you also `pull`). See
  [`remote-build.md`](remote-build.md) for the one-time setup.
