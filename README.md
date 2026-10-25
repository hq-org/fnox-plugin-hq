# fnox-plugin-hq

A [fnox](https://fnox.jdx.dev) provider for **sealed stores**: servers that keep only
[age](https://age-encryption.org) ciphertext. Values are encrypted on your machine to the public keys the server
lists for a scope, and decrypted on your machine with your own identity. The server never sees a value.

- `provider.lua` — the fnox Lua plugin (`get`, `get_batch`, `put`, `test`): since v0.5.0 a thin shim over the `hq`
  command, which does the protocol, the age encryption and the session unlock natively (no crypto in Lua).
- `hq` — hq-org's command line (the platform's `hq`, Rust): `hq keygen|unlock|lock|status|recipient|passwd`,
  `hq secrets ls|get|set|rm|exec|reseal`, and the `--batch` forms this plugin calls. Up to v0.4.1 this repo shipped
  its own `bin/hq` (sh); the new `hq` keeps its key cache names and formats, so an unlock carries over.
- [`PROTOCOL.md`](PROTOCOL.md) — the HTTP protocol a server implements (5 requests).
- `conformance/` — a test suite any server can run; `reference/` — an in-memory reference server.

Servers: tasks (hq-org's task graph service) implements the protocol at `/secrets`.

## Setup

Needs `fnox` and `hq` on `PATH` (`cargo build --release -p platform-cli` in the hq repo → `target/release/hq`;
or point `HQ_BIN` / the `hq` option at it). `age` is no longer needed.

```sh
# 1. once per machine: a passphrase-protected identity; prints your public key (age1…)
fnox plugin install hq hq-org/fnox-plugin-hq#v0.5.0
hq keygen                      # → ~/.config/hq/identity.age
# 2. register the printed age1… key with the server (tasks: an admin sets it on your Person)
```

`fnox.toml` in a project:

```toml
[plugins]
hq = "hq-org/fnox-plugin-hq#v0.5.0"

[providers.hq]
type = "lua"
plugin = "hq"
auth_command = "hq unlock"
options = { endpoint = "https://tasks.example.com/secrets", scope = "prj_7k2m9q4xwd", token_file = "~/.config/tasks/config.json", login_hint = "tasks login <url> <token>" }

[secrets]
CLOUDFLARE_API_TOKEN = { provider = "hq", value = "default/CLOUDFLARE_API_TOKEN" }
```

```sh
fnox set CLOUDFLARE_API_TOKEN --provider hq   # hidden prompt; encrypted here, stored there
fnox exec -- ./deploy.sh
```

### Options

| option | default | |
|---|---|---|
| `endpoint` | required | protocol base URL |
| `scope` | required | the server's scope id (tasks: project id) |
| `profile` | `default` | profile used for bare names in `fnox set`; refs are `<profile>/<KEY>` |
| `token` | — | bearer token (may be `{ secret = "NAME" }`); else `HQ_TOKEN`, else `token_file` |
| `token_file` | — | file with the token: a bare token, or JSON with a `token` field (e.g. `~/.config/tasks/config.json`) |
| `identity_file` | `~/.config/hq/identity.age` | your identity; else `HQ_IDENTITY_FILE`. A plain `AGE-SECRET-KEY-…` file (machines, CI) needs no unlock; `HQ_IDENTITY` (contents) overrides both |
| `key_cache` | `auto` | `auto`, `keyctl`, `macos`, `none`; else `HQ_KEY_CACHE` |
| `key_ttl` | `28800` | seconds the unlocked identity stays cached |
| `login_hint` | — | appended to "the store refused the token (401)" |
| `locked_message` | `locked — run \`hq unlock\` in a terminal` | the error when the identity is locked and nobody can type the passphrase; else `HQ_LOCKED_MESSAGE` (e.g. `locked — ask Michael to run \`hq unlock\``) |
| `hq` | `hq` | the `hq` binary; else `HQ_BIN` |
| `context`, `space` | — | instead of `endpoint`/`token`: an `hq` context (`hq instances`) and a space name or id |

Every option is passed to `hq` as a flag (`token_file` → `--token-file`, …); `token` goes through the environment
(`HQ_TOKEN`), refs and values through stdin/stdout: no secret in any argv. `hq` exits 3 for authentication problems
(a refused token, a wrong passphrase), which the plugin reports as fnox's auth error.

## Unlock once per session

The identity file is protected by a passphrase. The first decrypt in a terminal asks for it (`hq` prompts on the
terminal, echo off), and `hq` puts the unlocked identity into the session **key cache** for `key_ttl`. From then on
every `fnox exec` by you or your agents, in any shell of your user, decrypts on its own, including secrets added
later (from the web, from a teammate). `hq unlock` does the same explicitly; `hq lock` ends it early;
`hq status` tells which; `hq passwd` changes the passphrase (same key). `hq decrypt` (ciphertext on stdin, plaintext
out) uses the same identity, for re-encryption tools; `hq secrets reseal` re-encrypts a scope to its current
recipients itself.
**Never blocks an agent.** When the identity is locked and nobody can type the passphrase, the plugin and `hq` fail
at once with `locked_message` instead of waiting on a prompt; with `fnox exec --if-missing error` the command then
does not run at all. In a terminal of your own, a locked identity asks for the passphrase once (age's prompt) and
caches it. "Someone can type" means:

- the **stdin of your command is a terminal**, and `/dev/tty` opens (`hq` prompts there). A terminal merely existing is
  not enough: agents run inside tmux, where `/dev/tty` opens, but with stdin `/dev/null` or a pipe and nobody watching.
  This is fnox's own rule for prompting (`auth_command`).
- `fnox exec` / `fnox get`: fnox runs `hq secrets get --batch` with the refs on its stdin, so `hq` reads fnox's stdin
  instead (the one your command inherits): `/proc/<fnox pid>/fd/0` on Linux, `lsof` on macOS (untested on real macOS).
  When neither answers, the answer is no; `hq unlock` still works.
- `hq unlock`, `hq secrets get|exec`: their own stdin. `hq decrypt`, `hq identity` and the `--batch` forms: their stdin
  is data, so their caller's stdin (fnox, the shell).
- `HQ_NONINTERACTIVE=1` forces no (CI; an agent typing into a terminal of its own, e.g. tmux `send-keys`, where stdin
  is a terminal nobody watches); it wins over `HQ_INTERACTIVE=1`, which forces yes (stdin redirected in a terminal
  you are watching).

fnox's own [daemon](https://fnox.jdx.dev/guide/daemon.html) still caches resolved values; it is optional. It alone
is not enough for agents: a value the daemon has not seen yet is resolved outside it, and any change to a
`fnox.toml` empties it. The key cache covers both.

### Break-glass: fnox's age provider with the same unlock

fnox's built-in `age` provider cannot read a passphrase-protected identity file. A second instance of this plugin
with `mode = "identity"` hands it the identity from the key cache (asking for the passphrase in a terminal if
locked), so values encrypted into `fnox.toml` itself decrypt with the same session unlock, without any server:

```toml
[providers.hq-identity]
type = "lua"
plugin = "hq"
daemon_cache = false
options = { mode = "identity" }

[profiles.break-glass.providers.age]
type = "age"
recipients = ["age1…"]
identity = { provider = "hq-identity", value = "~/.config/hq/identity.age" }
```

### Key cache

One small seam (in hq's secrets core, `platform/core/features/secrets/src/keycache.rs`; the same names and formats as
v0.4's `lib/hq/keycache.lua` and `bin/hq`): `get(id)`, `put(id, value, ttl)`, `clear(id)`,
where `id` is the absolute path of the identity file.

| backend | where | expiry |
|---|---|---|
| `keyctl` (Linux) | kernel user keyring, key `fnox-plugin-hq:<id>`, perms possessor-all + user view/read/search | kernel timeout |
| `macos` | login Keychain generic password, service `fnox-plugin-hq`, account `<id>`, value `fnox-plugin-hq:v1:<unix expiry>:<base64 identity>`; written through `security -i` on stdin (never in argv) | checked on every read; expired items are deleted |
| `none` | — | every decrypt asks |

`auto` = `macos` on Darwin, else `keyctl` when installed, else `none`.

**The macOS backend is untested on real macOS**: its argv, stdin and expiry logic are tested against a fake
`security` (`test/fake-security`). Verify on a Mac: `hq keygen`, `hq unlock`, `hq status`, `fnox exec` from a
second terminal, `hq lock`.

Security: anything running as your user can read the cached identity while it is unlocked, as it could use
fnox's daemon or your SSH agent. The identity never appears in argv, environment of other processes, or files:
`hq` decrypts in process (the Rust `age` crate) and talks to `keyctl` / `security` on stdin.
`test/hq.test.ts` logs every argv of `hq` and `keyctl` during set/get/exec and checks that no value and no
`AGE-SECRET-KEY` is in them or in any output.

## Conformance

```ts
// my-server.test.ts (bun test)
import { conformance, PLANT } from "fnox-plugin-hq/conformance"
conformance("my server", async () => ({
  url: "http://127.0.0.1:8787/secrets", scope: "test", token: RW_TOKEN,
  identity: TEST_IDENTITY,            // plain AGE-SECRET-KEY whose age1 key is among the scope's recipients
  noReadToken, readOnlyToken,         // optional: 403 checks
  plugin: { dir: "node_modules/fnox-plugin-hq" }, // optional: end to end through fnox (and hq: $HQ_BIN or PATH)
}))
// afterwards: grep your storage for PLANT — it must not be there
```

Add it with `bun add -d github:hq-org/fnox-plugin-hq#v0.5.0`.

## Development

```sh
bun install
HQ_BIN=…/hq/target/release/hq bun test
                    # reference server + conformance, fnox end to end through hq, key cache (keyctl, fake security),
                    # who can type (tmux pane = agent, `script` pseudo-terminal = human), the v0.4 → hq unlock
                    # transition, keygen/passwd, no secret in argv or output
```

Without an `hq` that has `hq secrets` (CI: hq is not public yet), the cases that need it are skipped and the protocol
cases against the reference server still run.

MIT License.
