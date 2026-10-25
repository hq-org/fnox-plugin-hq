// The plugin (a shim over `hq`) and `hq` itself (hq-org's platform cli: HQ_BIN or `hq` on PATH) end to end without a
// terminal, on the macOS backend (fake `security` on PATH) and on the real Linux keyring (keyctl, when present). The unlocked identity is
// seeded the way `hq unlock` stores it; a passphrase typed into a pseudo-terminal (`script`) covers the unlock itself.
import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { armor, Encrypter, generateX25519Identity, identityToRecipient } from "age-encryption"
import { createReferenceServer } from "../reference/server"

const root = join(import.meta.dir, "..")
/** The `hq` under test; a pre-v0.5 `hq` (the shell script without `secrets`) does not count. */
const HQ = process.env.HQ_BIN ?? Bun.which("hq") ?? "hq"
const hqOk = Bun.spawnSync([HQ, "help"], { stderr: "ignore" }).stdout?.toString().includes("hq secrets exec") ?? false
const tools = !!Bun.which("fnox") && hqOk
const setsid = Bun.which("setsid")
const PASS = "correct horse battery staple"

let dir = ""
let identity = ""
let idFile = ""
let server: ReturnType<typeof Bun.serve>

// SHELL: `script -c` runs its command with $SHELL. HQ_IDENTITY_FILE: never the developer's own identity
const testEnv = (env: Record<string, string>): Record<string, string> => ({
  PATH: `${join(dir, "bin")}:${dirname(HQ)}:${process.env.PATH}`, HQ_BIN: HQ, SHELL: "/bin/sh", FNOX_DAEMON: "off", FNOX_CONFIG_DIR: join(dir, "cfg"), HQ_IDENTITY: "", HQ_IDENTITY_FILE: idFile,
  HQ_TOKEN: "", HQ_NONINTERACTIVE: "", HQ_INTERACTIVE: "", HQ_LOCKED_MESSAGE: "", FAKE_SECURITY_DIR: join(dir, "keychain"), ...env,
})
async function sh(cmd: string[], env: Record<string, string> = {}, stdin?: string) {
  const p = Bun.spawn(setsid && !stdin ? [setsid, "-w", ...cmd] : cmd, {
    cwd: dir, stdout: "pipe", stderr: "pipe", stdin: stdin === undefined ? "ignore" : new TextEncoder().encode(stdin),
    env: { ...process.env, ...testEnv(env) },
  })
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited])
  return { out, err, code }
}
const hq = (args: string[], env: Record<string, string> = {}) => sh([HQ, ...args, idFile], env)
const seedMac = (expiry: number) =>
  sh(["security", "-i"], {}, `add-generic-password -U -s fnox-plugin-hq -a "${idFile}" -w fnox-plugin-hq:v1:${expiry}:${btoa(identity)}\n`)
const keychainItems = () => readdirSync(join(dir, "keychain")).filter((f) => f.startsWith("item_"))
const now = () => Math.floor(Date.now() / 1000)

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "hq-keycache-"))
  mkdirSync(join(dir, "bin"))
  mkdirSync(join(dir, "keychain"))
  symlinkSync(join(root, "test/fake-security"), join(dir, "bin/security"))
  chmodSync(join(root, "test/fake-security"), 0o755)
  identity = `${await generateX25519Identity()}\n`
  const e = new Encrypter()
  e.setPassphrase(PASS)
  e.setScryptWorkFactor(12)
  idFile = join(dir, "identity.age")
  writeFileSync(idFile, armor.encode(await e.encrypt(identity)), { mode: 0o600 })
  const ref = createReferenceServer({ tokens: { t: { person: "me", read: true, write: true } }, recipients: { s: [await identityToRecipient(identity.trim())] } })
  server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: ref.fetch })
  writeFileSync(join(dir, "fnox.toml"), `root = true
default_provider = "hq"
[providers.hq]
type = "lua"
plugin = ${JSON.stringify(root)}
options = { endpoint = "http://127.0.0.1:${server.port}", scope = "s", token = "t", identity_file = ${JSON.stringify(idFile)} }
[secrets]
ALPHA = { provider = "hq", value = "default/ALPHA" }
`)
  // the value is written with the plain identity in HQ_IDENTITY: put only needs public keys, this keeps setup off any cache
  if (tools) expect((await sh(["fnox", "set", "ALPHA", "alpha-value", "--provider", "hq"], { HQ_IDENTITY: identity })).code).toBe(0)
})
afterAll(async () => {
  if (hqOk && Bun.which("keyctl") && idFile) await sh([HQ, "lock", idFile], { HQ_KEY_CACHE: "keyctl" })
  server?.stop(true)
  rmSync(dir, { recursive: true, force: true })
})

const exec = (env: Record<string, string>) => sh(["fnox", "exec", "--", "sh", "-c", 'test "$ALPHA" = alpha-value && echo match'], env)

describe("macos backend (fake security) — untested on real macOS", () => {
  const env = { HQ_KEY_CACHE: "macos" }

  test("locked: no terminal, no cache → fails at once naming `hq unlock`", async () => {
    if (!tools || !setsid) return console.warn("skipped: needs fnox, age, setsid")
    const r = await exec(env)
    expect(r.code).not.toBe(0)
    expect(r.err).toContain("locked \u2014 run `hq unlock` in a terminal")
  })

  test("HQ_NONINTERACTIVE (agents): locked fails fast even with a terminal; never a passphrase prompt; message configurable", async () => {
    if (!tools || !Bun.which("script")) return console.warn("skipped: needs fnox, age, script")
    await hq(["lock"], env)
    const msg = "locked \u2014 ask Michael to run `hq unlock`"
    const inTerminal = (c: string, e: Record<string, string>) => sh(["script", "-qec", c, "/dev/null"], { ...env, ...e }, "")
    const t0 = Date.now()
    const r = await inTerminal("fnox exec --if-missing error -- sh -c 'echo ran'", { HQ_NONINTERACTIVE: "1", HQ_LOCKED_MESSAGE: msg })
    expect(r.out).toContain(msg)
    expect(r.out).not.toContain("passphrase")
    expect(r.out).not.toContain("ran")
    const viaOption = await Bun.file(join(dir, "fnox.toml")).text()
    writeFileSync(join(dir, "fnox.toml"), viaOption.replace("identity_file =", `locked_message = ${JSON.stringify(msg)}, identity_file =`))
    const o = await inTerminal("fnox exec --if-missing error -- sh -c 'echo ran'", { HQ_NONINTERACTIVE: "1" })
    writeFileSync(join(dir, "fnox.toml"), viaOption)
    expect(o.out).toContain(msg)
    const u = await inTerminal(`${HQ} unlock ${idFile}`, { HQ_NONINTERACTIVE: "1", HQ_LOCKED_MESSAGE: msg })
    expect(u.out).toContain(msg)
    expect(u.out).not.toContain("passphrase")
    expect(Date.now() - t0).toBeLessThan(10_000)
  })

  test("unlocked: the plugin decrypts from the Keychain item without a terminal", async () => {
    if (!tools || !setsid) return console.warn("skipped: needs fnox, age, setsid")
    await seedMac(now() + 3600)
    const r = await exec(env)
    expect(r.out.trim()).toBe("match")
    expect(readFileSync(join(dir, "keychain/argv.log"), "utf8")).not.toContain("AGE-SECRET-KEY")
  })

  test("expired: the plugin deletes the item and reports locked", async () => {
    if (!tools || !setsid) return console.warn("skipped: needs fnox, age, setsid")
    await seedMac(now() - 1)
    const r = await exec(env)
    expect(r.code).not.toBe(0)
    expect(r.err).toContain("locked")
    expect(keychainItems()).toEqual([])
  })

  test("hq decrypt: ciphertext on stdin, plaintext out, identity from the cache; locked without it", async () => {
    if (!hqOk || !setsid) return console.warn("skipped: needs hq, setsid")
    const e = new Encrypter()
    e.addRecipient(await identityToRecipient(identity.trim()))
    const ct = armor.encode(await e.encrypt("re-encrypt me"))
    await seedMac(now() + 3600)
    const p = Bun.spawn([setsid, "-w", HQ, "decrypt", idFile], {
      cwd: dir, stdin: new TextEncoder().encode(ct), stdout: "pipe", stderr: "pipe",
      env: { ...process.env, PATH: `${join(dir, "bin")}:${dirname(HQ)}:${process.env.PATH}`, HQ_KEY_CACHE: "macos", HQ_IDENTITY: "", FAKE_SECURITY_DIR: join(dir, "keychain") },
    })
    expect(await new Response(p.stdout).text()).toBe("re-encrypt me")
    expect(await p.exited).toBe(0)
    await hq(["lock"], env)
    const q = Bun.spawn([setsid, "-w", HQ, "decrypt", idFile], {
      cwd: dir, stdin: new TextEncoder().encode(ct), stdout: "pipe", stderr: "pipe",
      env: { ...process.env, PATH: `${join(dir, "bin")}:${dirname(HQ)}:${process.env.PATH}`, HQ_KEY_CACHE: "macos", HQ_IDENTITY: "", FAKE_SECURITY_DIR: join(dir, "keychain") },
    })
    expect(await q.exited).not.toBe(0)
    expect(await new Response(q.stderr).text()).toContain("locked")
  })

  test("mode = identity feeds fnox's age provider (break-glass in git) from the same unlock", async () => {
    if (!tools || !setsid) return console.warn("skipped: needs fnox, age, setsid")
    const bg = join(dir, "bg")
    mkdirSync(bg, { recursive: true })
    writeFileSync(join(bg, "fnox.toml"), `root = true
[providers.hq-identity]
type = "lua"
plugin = ${JSON.stringify(root)}
daemon_cache = false
options = { mode = "identity" }
[providers.age]
type = "age"
recipients = [${JSON.stringify(await identityToRecipient(identity.trim()))}]
identity = { provider = "hq-identity", value = ${JSON.stringify(idFile)} }
`)
    const run = (args: string[]) => sh(["fnox", ...args], env).then((r) => r)
    const inBg = async (args: string[]) => {
      const p = Bun.spawn([setsid!, "-w", "fnox", ...args], {
        cwd: bg, stdout: "pipe", stderr: "pipe", stdin: "ignore",
        env: { ...process.env, PATH: `${join(dir, "bin")}:${dirname(HQ)}:${process.env.PATH}`, HQ_BIN: HQ, FNOX_DAEMON: "off", FNOX_CONFIG_DIR: join(dir, "cfg"), HQ_IDENTITY: "", FAKE_SECURITY_DIR: join(dir, "keychain"), ...env },
      })
      const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited])
      return { out, err, code }
    }
    void run
    await hq(["lock"], env)
    expect((await inBg(["set", "DEPLOY_TOKEN", "break-glass-value", "--provider", "age"])).code).toBe(0) // encrypting needs no unlock
    expect((await inBg(["exec", "--", "sh", "-c", 'test "$DEPLOY_TOKEN" = break-glass-value && echo match'])).code).not.toBe(0) // locked
    await seedMac(now() + 3600)
    expect((await inBg(["exec", "--", "sh", "-c", 'test "$DEPLOY_TOKEN" = break-glass-value && echo match'])).out.trim()).toBe("match")
  })

  test("hq status / recipient / lock read and drop the same item", async () => {
    await seedMac(now() + 3600)
    expect((await hq(["status"], env)).out.trim()).toBe("unlocked (macos)")
    expect((await hq(["recipient"], env)).out.trim()).toBe(await identityToRecipient(identity.trim()))
    expect((await hq(["lock"], env)).err.trim()).toBe("locked (macos)")
    expect(keychainItems()).toEqual([])
    const s = await hq(["status"], env)
    expect(s.out.trim()).toBe("locked (macos)")
    expect(s.code).toBe(1)
    await seedMac(now() - 5)
    expect((await hq(["status"], env)).out.trim()).toBe("locked (macos)")
    expect(keychainItems()).toEqual([])
    expect(readFileSync(join(dir, "keychain/argv.log"), "utf8")).not.toContain("AGE-SECRET-KEY")
  })
})

// Who can type the passphrase: the stdin of the user's command is a terminal (and /dev/tty opens). Agent-like = a real
// tmux pane (so /dev/tty opens) with stdin = /dev/null or a pipe; human-like = a real pseudo-terminal on stdin (`script`).
describe("who can type: stdin is a terminal, not merely a terminal exists", () => {
  const env = { HQ_KEY_CACHE: "macos" }
  const tmux = Bun.which("tmux")
  const script = Bun.which("script")
  const msg = "locked \u2014 ask Michael to run `hq unlock`"
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`
  let n = 0

  /** Runs `command` in a fresh tmux server's pane, like an agent's shell; resolves when it exits (4 s cap). */
  async function inTmux(command: string, e: Record<string, string> = {}) {
    const o = join(dir, `tmux-${++n}`)
    mkdirSync(o)
    const exports = Object.entries(testEnv({ ...env, ...e })).map(([k, v]) => `export ${k}=${q(v)}`).join("\n")
    writeFileSync(join(o, "run.sh"), `${exports}
cd ${q(dir)}
: </dev/tty 2>/dev/null && echo yes > ${q(join(o, "tty"))}
${command} > ${q(join(o, "out"))} 2>&1
echo $? > ${q(join(o, "rc.tmp"))}; mv ${q(join(o, "rc.tmp"))} ${q(join(o, "rc"))}
`)
    const sock = join(o, "sock")
    const { TMUX: _, TMUX_PANE: __, ...base } = process.env
    const t0 = Date.now()
    Bun.spawnSync([tmux!, "-S", sock, "-f", "/dev/null", "new-session", "-d", "-x", "120", "-y", "30", "sh", join(o, "run.sh")], { cwd: dir, env: base })
    try {
      while (!existsSync(join(o, "rc"))) {
        if (Date.now() - t0 > 4_000) throw new Error(`still waiting after 4 s (a prompt nobody answers?): ${command}`)
        await Bun.sleep(20)
      }
      const out = readFileSync(join(o, "out"), "utf8")
      return { ms: Date.now() - t0, code: Number(readFileSync(join(o, "rc"), "utf8").trim()), out, ttyOpens: existsSync(join(o, "tty")) }
    } finally {
      Bun.spawnSync([tmux!, "-S", sock, "kill-server"], { env: base })
    }
  }
  /** Runs `command` on a real pseudo-terminal (stdin, /dev/tty) and types `typed` into it. */
  const inPty = (command: string, e: Record<string, string> = {}, typed = `${PASS}\n`) =>
    sh([script!, "-qec", command, "/dev/null"], { ...env, ...e }, typed)
  const ciphertext = async (text: string) => {
    const enc = new Encrypter()
    enc.addRecipient(await identityToRecipient(identity.trim()))
    return armor.encode(await enc.encrypt(text))
  }
  const run = "fnox exec --if-missing error -- sh -c 'test \"$ALPHA\" = alpha-value && echo match'"

  // commands are built when the test runs: idFile is set in beforeAll
  const agentLike = (what: string, command: () => string, e: Record<string, string> = {}) =>
    test(`agent-like (tmux pane, ${what}): locked fails at once with the locked message`, async () => {
      if (!tools || !tmux) return console.warn("skipped: needs fnox, age, tmux")
      await hq(["lock"], env)
      const ct = await ciphertext("secret")
      const r = await inTmux(command(), { HQ_LOCKED_MESSAGE: msg, CT: ct, ...e })
      expect(r.ttyOpens).toBe(true) // the terminal exists: v0.4.0 called this interactive and age waited forever
      expect(r.code).not.toBe(0)
      expect(r.out).toContain(msg)
      expect(r.out).not.toContain("passphrase")
      expect(r.out).not.toContain("match")
      expect(r.ms).toBeLessThan(2_000)
      expect((await hq(["status"], env)).out.trim()).toBe("locked (macos)")
    })
  agentLike("fnox exec, stdin /dev/null", () => `${run} </dev/null`)
  agentLike("fnox exec, stdin a pipe", () => `echo | ${run}`)
  agentLike("hq unlock, stdin /dev/null", () => `${q(HQ)} unlock ${q(idFile)} </dev/null`)
  agentLike("hq decrypt, its caller's stdin /dev/null", () => `sh -c 'printf "%s" "$CT" | ${HQ} decrypt ${idFile}' </dev/null`)
  agentLike("HQ_NONINTERACTIVE=1 wins over HQ_INTERACTIVE=1, stdin a terminal", () => run, { HQ_NONINTERACTIVE: "1", HQ_INTERACTIVE: "1" })

  test("human-like (pseudo-terminal on stdin): fnox exec asks for the passphrase once and caches it", async () => {
    if (!tools || !script) return console.warn("skipped: needs fnox, age, script")
    await hq(["lock"], env)
    const r = await inPty(run)
    expect(r.out).toContain("passphrase")
    expect(r.out).toContain("match")
    expect((await hq(["status"], env)).out.trim()).toBe("unlocked (macos)")
    await hq(["lock"], env)
  })

  test("human-like: hq unlock asks; hq decrypt behind a pipe asks when its caller has the terminal", async () => {
    if (!tools || !script) return console.warn("skipped: needs fnox, age, script")
    await hq(["lock"], env)
    const u = await inPty(`${HQ} unlock ${idFile}`)
    expect(u.out).toContain("passphrase")
    expect(u.out).toContain("unlocked for 8h (macos)")
    await hq(["lock"], env)
    const d = await inPty(`printf "%s" "$CT" | ${HQ} decrypt ${idFile}`, { CT: await ciphertext("re-encrypt me") })
    expect(d.out).toContain("passphrase")
    expect(d.out).toContain("re-encrypt me")
    await hq(["lock"], env)
  })

  test("HQ_INTERACTIVE=1: asks even when stdin is not a terminal", async () => {
    if (!tools || !script) return console.warn("skipped: needs fnox, age, script")
    await hq(["lock"], env)
    const r = await inPty(`${run} </dev/null`, { HQ_INTERACTIVE: "1" })
    expect(r.out).toContain("passphrase")
    expect(r.out).toContain("match")
    await hq(["lock"], env)
    const control = await inPty(`${run} </dev/null`, {}, "")
    expect(control.out).toContain("locked")
    expect(control.out).not.toContain("match")
  })
})

describe("keyctl backend (real Linux user keyring)", () => {
  const env = { HQ_KEY_CACHE: "keyctl" }
  const ok = !!Bun.which("keyctl") && Bun.spawnSync(["keyctl", "show", "@u"]).exitCode === 0

  test("typing the passphrase once (pseudo-terminal) unlocks; later runs without a terminal use the keyring", async () => {
    if (!ok || !tools || !setsid || !Bun.which("script")) return console.warn("skipped: needs keyctl, fnox, age, setsid, script")
    await hq(["lock"], env)
    expect((await exec(env)).code).not.toBe(0)
    // `script` gives fnox a terminal: age asks for the passphrase there, the plugin then caches the identity
    const typed = await sh(["script", "-qec", "fnox exec -- sh -c 'test \"$ALPHA\" = alpha-value && echo match'", "/dev/null"], env, `${PASS}\n`)
    expect(typed.out).toContain("match")
    expect((await exec(env)).out.trim()).toBe("match")
    expect((await hq(["status"], env)).out.trim()).toBe("unlocked (keyctl)")
    expect((await hq(["lock"], env)).err.trim()).toBe("locked (keyctl)")
    expect((await exec(env)).code).not.toBe(0)
  })

  test("hq unlock (pseudo-terminal) fills the same keyring entry the plugin reads", async () => {
    if (!ok || !tools || !setsid || !Bun.which("script")) return console.warn("skipped: needs keyctl, fnox, age, setsid, script")
    const u = await sh(["script", "-qec", `${HQ} unlock ${idFile}`, "/dev/null"], env, `${PASS}\n`)
    expect(u.out).toContain("unlocked for 8h (keyctl)")
    expect((await exec(env)).out.trim()).toBe("match")
    await hq(["lock"], env)
  })

  test("the transition: an unlock by v0.4's bin/hq (sh) is read by hq, and the other way round", async () => {
    const old = Bun.spawnSync(["git", "show", "v0.4.1:bin/hq"], { cwd: root }).stdout.toString()
    if (!ok || !tools || !Bun.which("age") || !Bun.which("script") || !old.startsWith("#!")) return console.warn("skipped: needs keyctl, fnox, age, script, git tag v0.4.1")
    const oldHq = join(dir, "old-hq")
    writeFileSync(oldHq, old, { mode: 0o755 })
    await hq(["lock"], env)
    const u = await sh(["script", "-qec", `${oldHq} unlock ${idFile}`, "/dev/null"], env, `${PASS}\n`)
    expect(u.out).toContain("unlocked for 8h (keyctl)")
    expect((await hq(["status"], env)).out.trim()).toBe("unlocked (keyctl)")
    expect((await exec(env)).out.trim()).toBe("match")
    await hq(["lock"], env)
    await sh(["script", "-qec", `${HQ} unlock ${idFile}`, "/dev/null"], env, `${PASS}\n`)
    expect((await sh([oldHq, "status", idFile], env)).out.trim()).toBe("unlocked (keyctl)")
    expect((await sh([oldHq, "recipient", idFile], env)).out.trim()).toBe(await identityToRecipient(identity.trim()))
    await hq(["lock"], env)
  })
})

describe("hq: keygen, passwd; no secret in argv or output", () => {
  const env = { HQ_KEY_CACHE: "keyctl" }
  const ok = !!Bun.which("keyctl") && Bun.spawnSync(["keyctl", "show", "@u"]).exitCode === 0
  const PLANT = `hqplant${Math.random().toString(36).slice(2)}`
  /** Wrappers that log every argv of hq and keyctl, then run the real one. */
  const logged = () => {
    const log = join(dir, "argv.log")
    const lb = join(dir, "logbin")
    mkdirSync(lb, { recursive: true })
    writeFileSync(join(lb, "hq"), `#!/bin/sh\nprintf '%s\\n' "hq $*" >> ${JSON.stringify(log)}\nexec ${JSON.stringify(HQ)} "$@"\n`, { mode: 0o755 })
    const kc = Bun.which("keyctl")
    if (kc) writeFileSync(join(lb, "keyctl"), `#!/bin/sh\nprintf '%s\\n' "keyctl $*" >> ${JSON.stringify(log)}\nexec ${JSON.stringify(kc)} "$@"\n`, { mode: 0o755 })
    return { log, env: { PATH: `${lb}:${join(dir, "bin")}:${process.env.PATH}`, HQ_BIN: join(lb, "hq") } }
  }
  const store = () => ["--endpoint", `http://127.0.0.1:${server.port}`, "--scope", "s"]

  test("secrets set/get/ls/rm/exec through fnox and hq: values and the identity never in argv, never in output", async () => {
    if (!tools || !ok || !setsid) return console.warn("skipped: needs fnox, hq, keyctl, setsid")
    const w = logged()
    const e = { ...env, ...w.env, HQ_TOKEN: "t" }
    await sh(["script", "-qec", `${HQ} unlock ${idFile}`, "/dev/null"], env, `${PASS}\n`)
    const outs: string[] = []
    // the expected values reach the checking shell through its environment, so no argv of the test carries them
    const want = { WANT_B: `b ${PLANT}`, WANT_G: `g ${PLANT}` }
    const run = async (cmd: string[], stdin?: string) => {
      const r = await sh(cmd, { ...e, ...want }, stdin)
      outs.push(r.out, r.err)
      return r
    }
    expect((await run(["fnox", "set", "BETA", `b ${PLANT}`, "--provider", "hq"])).code).toBe(0) // fnox's own argv: the test's choice
    const s = await run([join(dir, "logbin/hq"), "secrets", "set", "GAMMA", ...store()], `g ${PLANT}\n`)
    expect(s.code).toBe(0)
    expect(s.out).toContain("set default/GAMMA")
    expect((await run(["fnox", "exec", "--", "sh", "-c", 'test "$BETA" = "$WANT_B" && echo match'])).out.trim()).toBe("match")
    const x = await run([join(dir, "logbin/hq"), "secrets", "exec", ...store(), "--", "sh", "-c", 'test "$GAMMA" = "$WANT_G" && test "$BETA" = "$WANT_B" && echo match'])
    expect(x.out.trim()).toBe("match")
    const ls = await run([join(dir, "logbin/hq"), "secrets", "ls", ...store()])
    expect(ls.out).toContain("default/GAMMA")
    // the one command that prints a value is get, to a pipe here
    const g = await sh([join(dir, "logbin/hq"), "secrets", "get", "GAMMA", ...store()], e)
    expect(g.out).toBe(`g ${PLANT}`)
    // a value as an argument is refused and nothing is stored
    const arg = await run([join(dir, "logbin/hq"), "secrets", "set", "DELTA", `d ${PLANT}`, ...store()])
    expect(arg.code).toBe(2)
    expect(arg.err).toContain("never an argument")
    expect((await run([join(dir, "logbin/hq"), "secrets", "ls", ...store()])).out).not.toContain("DELTA")
    expect((await run([join(dir, "logbin/hq"), "secrets", "rm", "GAMMA", ...store()])).code).toBe(0)
    // a wrong token: an authentication failure (3), the value nowhere
    const wrong = await sh([HQ, "secrets", "set", "EPS", ...store()], { ...e, HQ_TOKEN: "wrong" }, `e ${PLANT}`)
    outs.push(wrong.out, wrong.err)
    expect(wrong.code).toBe(3)
    expect(wrong.err).toContain("401")
    const argv = readFileSync(w.log, "utf8")
    expect(argv).toContain("hq secrets get --batch") // the plugin went through hq
    expect(argv).toContain("keyctl search")
    // only the argument refused above carried the plant (the test put it there)
    expect(argv.split("\n").filter((l) => l.includes(PLANT)).every((l) => l.startsWith("hq secrets set DELTA"))).toBe(true)
    expect(argv).not.toContain("AGE-SECRET-KEY")
    for (const o of outs) {
      expect(o).not.toContain(PLANT)
      expect(o).not.toContain("AGE-SECRET-KEY")
    }
    expect(JSON.stringify(Object.fromEntries(Object.entries(process.env)))).not.toContain(PLANT)
    await hq(["lock"], env)
  })

  test("hq identity refuses a terminal; hq decrypt and identity need the unlock", async () => {
    if (!hqOk || !Bun.which("script")) return console.warn("skipped: needs hq, script")
    const r = await sh(["script", "-qec", `${HQ} identity ${idFile}`, "/dev/null"], { HQ_KEY_CACHE: "none" }, "")
    expect(r.out).toContain("only into a pipe")
    expect(r.out).not.toContain("AGE-SECRET-KEY")
    const p = await sh([HQ, "identity", idFile], { HQ_KEY_CACHE: "none" })
    expect(p.code).toBe(1)
    expect(p.err).toContain("locked")
  })

  test("keygen and passwd in a terminal: same key, new passphrase, old file kept as a backup", async () => {
    if (!hqOk || !ok || !Bun.which("script")) return console.warn("skipped: needs hq, keyctl, script")
    const f = join(dir, "k2", "identity.age")
    const k = await sh(["script", "-qec", `${HQ} keygen ${f}`, "/dev/null"], env, "one\none\n")
    const pub = k.out.match(/age1[02-9ac-hj-np-z]{58}/)?.[0]
    expect(pub).toBeDefined()
    expect(readFileSync(f).toString("latin1")).not.toContain("AGE-SECRET-KEY")
    expect((await sh([HQ, "status", f], env)).out.trim()).toBe("locked (keyctl)")
    const again = await sh(["script", "-qec", `${HQ} keygen ${f}`, "/dev/null"], env, "x\nx\n")
    expect(again.out).toContain("exists")
    const pw = await sh(["script", "-qec", `${HQ} passwd ${f}`, "/dev/null"], env, "one\ntwo\ntwo\n")
    expect(pw.out).toContain("passphrase changed")
    expect(readdirSync(join(dir, "k2")).some((n) => n.startsWith("identity.age.bak."))).toBe(true)
    const bad = await sh(["script", "-qec", `${HQ} unlock ${f}`, "/dev/null"], env, "one\n")
    expect(bad.out).toContain("wrong passphrase")
    const good = await sh(["script", "-qec", `${HQ} unlock ${f}`, "/dev/null"], env, "two\n")
    expect(good.out).toContain("unlocked for 8h (keyctl)")
    expect((await sh([HQ, "recipient", f], env)).out.trim()).toBe(pub!)
    await sh([HQ, "lock", f], env)
  }, 60_000) // scrypt at age's work factor (18), five times
})
