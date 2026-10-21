// Key cache: the Lua unit spec (fake runner), then the plugin and bin/hq end to end without a terminal, on the macOS
// backend (fake `security` on PATH) and on the real Linux keyring (keyctl, when present). The unlocked identity is
// seeded the way `hq unlock` stores it; a passphrase typed into a pseudo-terminal (`script`) covers the unlock itself.
import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { armor, Encrypter, generateX25519Identity, identityToRecipient } from "age-encryption"
import { createReferenceServer } from "../reference/server"

const root = join(import.meta.dir, "..")
const lua = Bun.which("lua5.4") ?? Bun.which("lua")
const tools = !!Bun.which("fnox") && !!Bun.which("age")
const setsid = Bun.which("setsid")
const PASS = "correct horse battery staple"

let dir = ""
let identity = ""
let idFile = ""
let server: ReturnType<typeof Bun.serve>

async function sh(cmd: string[], env: Record<string, string> = {}, stdin?: string) {
  const p = Bun.spawn(setsid && !stdin ? [setsid, "-w", ...cmd] : cmd, {
    cwd: dir, stdout: "pipe", stderr: "pipe", stdin: stdin === undefined ? "ignore" : new TextEncoder().encode(stdin),
    env: { ...process.env, PATH: `${join(dir, "bin")}:${process.env.PATH}`, FNOX_DAEMON: "off", FNOX_CONFIG_DIR: join(dir, "cfg"), HQ_IDENTITY: "", HQ_TOKEN: "", FAKE_SECURITY_DIR: join(dir, "keychain"), ...env },
  })
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited])
  return { out, err, code }
}
const hq = (args: string[], env: Record<string, string> = {}) => sh([join(root, "bin/hq"), ...args, idFile], env)
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
  if (Bun.which("keyctl") && idFile) await sh([join(root, "bin/hq"), "lock", idFile], { HQ_KEY_CACHE: "keyctl" })
  server?.stop(true)
  rmSync(dir, { recursive: true, force: true })
})

const exec = (env: Record<string, string>) => sh(["fnox", "exec", "--", "sh", "-c", 'test "$ALPHA" = alpha-value && echo match'], env)

test("lua unit spec (fake runner and clock)", async () => {
  if (!lua) return console.warn("skipped: no lua5.4")
  const r = Bun.spawnSync([lua, join(root, "test/keycache_spec.lua")])
  expect(r.stdout.toString()).toContain("0 failures")
  expect(r.exitCode).toBe(0)
})

describe("macos backend (fake security) — untested on real macOS", () => {
  const env = { HQ_KEY_CACHE: "macos" }

  test("locked: no terminal, no cache → authentication failure naming `hq unlock`", async () => {
    if (!tools || !setsid) return console.warn("skipped: needs fnox, age, setsid")
    const r = await exec(env)
    expect(r.code).not.toBe(0)
    expect(r.err).toContain("hq unlock")
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
    const u = await sh(["script", "-qec", `${join(root, "bin/hq")} unlock ${idFile}`, "/dev/null"], env, `${PASS}\n`)
    expect(u.out).toContain("unlocked for 8h (keyctl)")
    expect((await exec(env)).out.trim()).toBe("match")
    await hq(["lock"], env)
  })
})
