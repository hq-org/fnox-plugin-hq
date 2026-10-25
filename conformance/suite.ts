// Conformance suite for sealed-store servers (PROTOCOL.md v1). Registers bun:test cases:
//
//   import { conformance, PLANT } from "fnox-plugin-hq/conformance"
//   conformance("my server", async () => ({ url, scope, token, identity, noReadToken, readOnlyToken, plugin }))
//
// Every value the suite writes contains PLANT (encrypted); afterwards grep your storage for PLANT: a hit = plaintext
// leaked. Each response body the suite sees is checked for PLANT too. With `plugin`, fnox on PATH and `hq` (≥ the one
// with `hq secrets`: $HQ_BIN or on PATH; the provider is a shim over it), the same checks run end to end through
// `fnox set` / `fnox exec` with this repo's provider.lua.
import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { armor, Decrypter, Encrypter, generateX25519Identity, identityToRecipient } from "age-encryption"

export interface Target {
  /** Endpoint (protocol paths are relative to it), e.g. http://127.0.0.1:8787/secrets */
  url: string
  scope: string
  /** May read and write the scope. */
  token: string
  /** Plain age identity (AGE-SECRET-KEY-…) whose recipient is in the scope's recipients. */
  identity: string
  /** A valid token that may not read the scope's secrets (GET secrets → 403). */
  noReadToken?: string
  /** A valid token that may read but not write (PUT → 403). */
  readOnlyToken?: string
  /** Directory holding provider.lua: run the fnox end-to-end cases (skipped when fnox or age is missing). */
  plugin?: { dir: string }
}

const rand = () => Math.random().toString(36).slice(2, 10)
/** Planted plaintext: in every value written, never allowed in a response or in server storage. */
export const PLANT = `hqplant${rand()}${rand()}`

export const ageEncrypt = async (recipients: string[], value: string) => {
  const e = new Encrypter()
  for (const r of recipients) e.addRecipient(r)
  return armor.encode(await e.encrypt(value))
}
export const ageDecrypt = async (identity: string, ciphertext: string) => {
  const d = new Decrypter()
  d.addIdentity(identity.split("\n").find((l) => l.startsWith("AGE-SECRET-KEY-")) ?? identity)
  return d.decrypt(armor.decode(ciphertext), "text")
}

export function conformance(name: string, target: () => Target | Promise<Target>) {
  describe(`sealed-store protocol v1: ${name}`, () => {
    let t: Target
    const seen: string[] = []
    const call = async (method: string, path: string, opts: { token?: string | null; body?: unknown; raw?: string } = {}) => {
      const headers: Record<string, string> = { "content-type": "application/json" }
      const token = opts.token === undefined ? t.token : opts.token
      if (token !== null) headers.authorization = `Bearer ${token}`
      const res = await fetch(`${t.url.replace(/\/+$/, "")}/v1/scopes/${encodeURIComponent(t.scope)}${path}`, {
        method, headers, body: opts.raw ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body)),
      })
      const text = await res.text()
      seen.push(text)
      let json: any = null
      try { json = JSON.parse(text) } catch { /* checked by callers */ }
      return { status: res.status, json, text }
    }
    const recipients = async () => (await call("GET", "/recipients")).json.recipients as string[]
    const put = async (ref: string, value: string, rs?: string[]) => {
      const r = rs ?? (await recipients())
      return call("PUT", `/secrets/${ref}`, { body: { ciphertext: await ageEncrypt(r, value), recipients: r } })
    }
    const key = (s: string) => `HQ_CONF_${rand().toUpperCase()}_${s}`

    beforeAll(async () => { t = await target() })
    afterAll(() => {
      // the last word: nothing the server ever answered contained the planted plaintext
      for (const body of seen) expect(body.includes(PLANT)).toBe(false)
    })

    test("401 without a token or with an unknown one, on every route", async () => {
      for (const token of [null, `nope-${rand()}`]) {
        expect((await call("GET", "/recipients", { token })).status).toBe(401)
        expect((await call("GET", "/secrets?ref=default/X", { token })).status).toBe(401)
        expect((await call("PUT", "/secrets/default/X", { token, body: {} })).status).toBe(401)
        expect((await call("DELETE", "/secrets/default/X", { token })).status).toBe(401)
      }
    })

    test("recipients: a non-empty list of age1 keys including the test identity", async () => {
      const r = await call("GET", "/recipients")
      expect(r.status).toBe(200)
      expect(Array.isArray(r.json.recipients)).toBe(true)
      for (const x of r.json.recipients) expect(x).toMatch(/^age1[02-9ac-hj-np-z]{58}$/)
      expect(r.json.recipients).toContain(await identityToRecipient(t.identity.split("\n").find((l) => l.startsWith("AGE-SECRET-KEY-"))!))
    })

    test("put then get by ref: same ciphertext, decryptable, rev counts writes; missing refs left out", async () => {
      const k = key("A")
      const value = `v1 ${PLANT} pä ss 🙂`
      const w = await put(`default/${k}`, value)
      expect(w.status).toBe(200)
      expect(w.json).toMatchObject({ ref: `default/${k}`, rev: 1 })
      const g = await call("GET", `/secrets?ref=${encodeURIComponent(`default/${k}`)}&ref=${encodeURIComponent(`default/${key("MISSING")}`)}`)
      expect(g.status).toBe(200)
      expect(Object.keys(g.json.secrets)).toEqual([`default/${k}`])
      const s = g.json.secrets[`default/${k}`]
      expect(s.rev).toBe(1)
      expect(new Set(s.recipients)).toEqual(new Set(await recipients()))
      expect(await ageDecrypt(t.identity, s.ciphertext)).toBe(value)
      const w2 = await put(`default/${k}`, `v2 ${PLANT}`)
      expect(w2.json.rev).toBe(2)
      const g2 = await call("GET", `/secrets?ref=${encodeURIComponent(`default/${k}`)}`)
      expect(await ageDecrypt(t.identity, g2.json.secrets[`default/${k}`].ciphertext)).toBe(`v2 ${PLANT}`)
    })

    test("profiles are separate", async () => {
      const k = key("P")
      await put(`default/${k}`, `dev ${PLANT}`)
      await put(`production/${k}`, `prod ${PLANT}`)
      const g = await call("GET", `/secrets?ref=default/${k}&ref=production/${k}`)
      expect(await ageDecrypt(t.identity, g.json.secrets[`default/${k}`].ciphertext)).toBe(`dev ${PLANT}`)
      expect(await ageDecrypt(t.identity, g.json.secrets[`production/${k}`].ciphertext)).toBe(`prod ${PLANT}`)
    })

    test("get without refs lists the scope", async () => {
      const k = key("L")
      await put(`default/${k}`, `list ${PLANT}`)
      const g = await call("GET", "/secrets")
      expect(g.status).toBe(200)
      expect(g.json.secrets[`default/${k}`]?.ciphertext).toContain("-----BEGIN AGE ENCRYPTED FILE-----")
    })

    test("plaintext and other non-age bodies are refused (400)", async () => {
      const r = await recipients()
      const k = key("BAD")
      for (const ciphertext of [PLANT, `-----BEGIN AGE ENCRYPTED FILE-----\n${btoa(PLANT)}\n-----END AGE ENCRYPTED FILE-----`, 42, null])
        expect((await call("PUT", `/secrets/default/${k}`, { body: { ciphertext, recipients: r } })).status).toBe(400)
      expect((await call("PUT", `/secrets/default/${k}`, { raw: "not json" })).status).toBe(400)
      expect(Object.keys((await call("GET", `/secrets?ref=default/${k}`)).json.secrets)).toEqual([])
    })

    test("invalid refs are refused (400)", async () => {
      const r = await recipients()
      const ct = await ageEncrypt(r, PLANT)
      for (const ref of ["default/1BAD", "default/has-dash", "Prod/KEY", "-x/KEY"])
        expect((await call("PUT", `/secrets/${ref}`, { body: { ciphertext: ct, recipients: r } })).status).toBe(400)
      expect((await call("GET", "/secrets?ref=default/has-dash")).status).toBe(400)
      expect((await call("GET", "/secrets?ref=nope")).status).toBe(400)
    })

    test("stale recipients are refused (409) with the current list", async () => {
      const r = await recipients()
      const extra = await identityToRecipient(await generateX25519Identity())
      for (const rs of [[...r, extra], r.slice(1)]) {
        if (rs.length === 0) continue
        const res = await call("PUT", `/secrets/default/${key("STALE")}`, { body: { ciphertext: await ageEncrypt(rs, PLANT), recipients: rs } })
        expect(res.status).toBe(409)
        expect(new Set(res.json.recipients)).toEqual(new Set(r))
      }
    })

    test("delete removes a value; unknown ref → 404", async () => {
      const k = key("D")
      await put(`default/${k}`, `gone ${PLANT}`)
      expect((await call("DELETE", `/secrets/default/${k}`)).status).toBe(200)
      expect(Object.keys((await call("GET", `/secrets?ref=default/${k}`)).json.secrets)).toEqual([])
      expect((await call("DELETE", `/secrets/default/${k}`)).status).toBe(404)
    })

    test("a token without read may not get secrets (403)", async () => {
      if (!t.noReadToken) return console.warn("skipped: no noReadToken")
      const k = key("NR")
      await put(`default/${k}`, `nr ${PLANT}`)
      const r = await call("GET", `/secrets?ref=default/${k}`, { token: t.noReadToken })
      expect(r.status).toBe(403)
      expect(r.text).not.toContain("BEGIN AGE")
    })

    test("a read-only token may not write (403)", async () => {
      if (!t.readOnlyToken) return console.warn("skipped: no readOnlyToken")
      const r = await recipients()
      const res = await call("PUT", `/secrets/default/${key("RO")}`, { token: t.readOnlyToken, body: { ciphertext: await ageEncrypt(r, PLANT), recipients: r } })
      expect(res.status).toBe(403)
    })

    describe("end to end through fnox", () => {
      const hq = process.env.HQ_BIN ?? Bun.which("hq") ?? "hq"
      const tools = !!Bun.which("fnox") && !!Bun.spawnSync([hq, "help"], { stderr: "ignore" }).stdout?.toString().includes("hq secrets exec")
      let dir = ""
      const fnox = async (args: string[]) => {
        const p = Bun.spawn(["fnox", ...args], {
          cwd: dir, stdout: "pipe", stderr: "pipe", stdin: "ignore",
          env: { ...process.env, FNOX_DAEMON: "off", FNOX_CONFIG_DIR: join(dir, "cfg"), HQ_IDENTITY: "", HQ_TOKEN: "", NO_COLOR: "1" },
        })
        const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited])
        return { out, err, code }
      }
      beforeAll(() => {
        if (!tools || !t.plugin) return
        dir = mkdtempSync(join(tmpdir(), "hq-conformance-"))
        writeFileSync(join(dir, "identity.txt"), `${t.identity.trim()}\n`, { mode: 0o600 })
        const opts = { endpoint: t.url, scope: t.scope, token: t.token, identity_file: join(dir, "identity.txt"), key_cache: "none" }
        const inline = Object.entries(opts).map(([k, v]) => `${k} = ${JSON.stringify(v)}`).join(", ")
        writeFileSync(join(dir, "fnox.toml"), `root = true\ndefault_provider = "hq"\n\n[providers.hq]\ntype = "lua"\nplugin = ${JSON.stringify(t.plugin.dir)}\noptions = { ${inline} }\n`)
      })
      afterAll(() => { if (dir) rmSync(dir, { recursive: true, force: true }) })

      test("fnox set encrypts locally; fnox exec gets both values in one batch; the server holds ciphertext", async () => {
        if (!tools || !t.plugin) return console.warn("skipped: needs fnox and hq on PATH and target.plugin")
        const a = key("FA")
        const b = key("FB")
        for (const [k, v] of [[a, `fa ${PLANT} ü`], [b, `fb ${PLANT}`]] as const) {
          const r = await fnox(["set", k, v, "--provider", "hq"])
          expect(r.err + r.out).not.toContain(PLANT)
          expect(r.code).toBe(0)
        }
        const exec = await fnox(["exec", "--", "sh", "-c", `test "$${a}" = "fa ${PLANT} ü" && test "$${b}" = "fb ${PLANT}" && echo match`])
        expect(exec.code).toBe(0)
        expect(exec.out.trim()).toBe("match")
        const g = await call("GET", `/secrets?ref=default/${a}`)
        expect(await ageDecrypt(t.identity, g.json.secrets[`default/${a}`].ciphertext)).toBe(`fa ${PLANT} ü`)
      })

      test("fnox set on an existing secret replaces it (put gets the saved ref)", async () => {
        if (!tools || !t.plugin) return console.warn("skipped: needs fnox and hq on PATH and target.plugin")
        const k = key("FR")
        expect((await fnox(["set", k, `one ${PLANT}`, "--provider", "hq"])).code).toBe(0)
        expect((await fnox(["set", k, `two ${PLANT}`, "--provider", "hq"])).code).toBe(0)
        const exec = await fnox(["exec", "--", "sh", "-c", `test "$${k}" = "two ${PLANT}" && echo match`])
        expect(exec.out.trim()).toBe("match")
        expect((await call("GET", `/secrets?ref=default/${k}`)).json.secrets[`default/${k}`].rev).toBe(2)
      })

      test("a bad token is an authentication failure, not a crash", async () => {
        if (!tools || !t.plugin) return console.warn("skipped: needs fnox and hq on PATH and target.plugin")
        const r = await fnox(["provider", "test", "hq"])
        expect(r.code).toBe(0)
        const bad = await Bun.file(join(dir, "fnox.toml")).text()
        writeFileSync(join(dir, "fnox.local.toml"), bad.replace(/token = "[^"]*"/, 'token = "wrong"').replace("root = true\n", ""))
        const r2 = await fnox(["provider", "test", "hq"])
        rmSync(join(dir, "fnox.local.toml"))
        expect(r2.code).not.toBe(0)
        expect(r2.err).toContain("401")
      })
    })
  })
}
