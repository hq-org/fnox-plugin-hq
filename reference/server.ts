// Reference sealed-store server (PROTOCOL.md v1): in memory, Web APIs only. The conformance suite runs against it
// in this repo's tests; it also shows a server author the whole protocol in one file.

export const SCOPE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/
export const PROFILE = /^[a-z0-9][a-z0-9_-]{0,62}$/
export const KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/
export const RECIPIENT = /^age1[02-9ac-hj-np-z]{58}$/
export const MAX_CIPHERTEXT = 64 * 1024
export const MAX_REFS = 100

const BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----"
const END = "-----END AGE ENCRYPTED FILE-----"

/** An armored age file: header/footer lines, base64 body decoding to "age-encryption.org/v1\n…". */
export function isAgeArmor(s: unknown): s is string {
  if (typeof s !== "string" || s.length > MAX_CIPHERTEXT) return false
  const t = s.trim()
  if (!t.startsWith(BEGIN) || !t.endsWith(END)) return false
  const body = t.slice(BEGIN.length, -END.length).replace(/\s+/g, "")
  if (!/^[A-Za-z0-9+/]+=*$/.test(body)) return false
  try { return atob(body.slice(0, 32)).startsWith("age-encryption.org/v1\n") } catch { return false }
}

export const sameSet = (a: readonly string[], b: readonly string[]) => {
  const x = new Set(a)
  const y = new Set(b)
  return x.size === y.size && [...x].every((r) => y.has(r))
}

export interface ReferenceOptions {
  /** token → what it may do */
  tokens: Record<string, { person: string; read: boolean; write: boolean }>
  /** scope → recipients (mutable through setRecipients) */
  recipients: Record<string, string[]>
}

export interface AuditEntry { at: string; person: string; action: "read" | "write" | "delete"; scope: string; ref: string }

export function createReferenceServer(opts: ReferenceOptions) {
  const store = new Map<string, { ciphertext: string; recipients: string[]; rev: number }>() // `${scope}\n${ref}`
  const audit: AuditEntry[] = []
  const json = (body: unknown, status = 200) => Response.json(body, { status })
  const fail = (status: number, error: string, extra: Record<string, unknown> = {}) => json({ error, ...extra }, status)
  const log = (person: string, action: AuditEntry["action"], scope: string, ref: string) =>
    audit.push({ at: new Date().toISOString(), person, action, scope, ref })

  async function fetch(req: Request): Promise<Response> {
    const url = new URL(req.url)
    const m = /^\/v1\/scopes\/([^/]+)\/(recipients|secrets)(?:\/([^/]+)\/([^/]+))?\/?$/.exec(url.pathname)
    if (!m) return fail(404, "not found")
    const caller = opts.tokens[/^Bearer\s+(\S+)$/i.exec(req.headers.get("authorization") ?? "")?.[1] ?? ""]
    if (!caller) return fail(401, "unauthorized")
    const scope = decodeURIComponent(m[1]!)
    const [, , what, profile, key] = m
    if (!SCOPE.test(scope)) return fail(400, "invalid scope")
    const recipients = opts.recipients[scope]
    if (!recipients) return fail(404, "unknown scope")

    if (what === "recipients" && !profile && req.method === "GET") {
      if (!caller.read && !caller.write) return fail(403, "forbidden")
      return json({ recipients })
    }
    if (what === "secrets" && !profile && req.method === "GET") {
      if (!caller.read) return fail(403, "forbidden: needs read")
      const refs = url.searchParams.getAll("ref")
      if (refs.length > MAX_REFS) return fail(400, `at most ${MAX_REFS} refs`)
      for (const r of refs) {
        const [p, k, extra] = r.split("/")
        if (extra !== undefined || !PROFILE.test(p ?? "") || !KEY.test(k ?? "")) return fail(400, `invalid ref ${r}`)
      }
      const wanted = refs.length ? refs : [...store.keys()].filter((k) => k.startsWith(`${scope}\n`)).map((k) => k.slice(scope.length + 1))
      const secrets: Record<string, unknown> = {}
      for (const ref of wanted) {
        const s = store.get(`${scope}\n${ref}`)
        if (!s) continue
        secrets[ref] = s
        log(caller.person, "read", scope, ref)
      }
      return json({ secrets })
    }
    if (what === "secrets" && profile && key) {
      const p = decodeURIComponent(profile)
      const k = decodeURIComponent(key)
      if (!PROFILE.test(p) || !KEY.test(k)) return fail(400, "invalid profile or key")
      const ref = `${p}/${k}`
      if (!caller.write) return fail(403, "forbidden: needs write")
      if (req.method === "DELETE") {
        if (!store.delete(`${scope}\n${ref}`)) return fail(404, "unknown ref")
        log(caller.person, "delete", scope, ref)
        return json({ ref })
      }
      if (req.method !== "PUT") return fail(405, "method not allowed")
      let body: { ciphertext?: unknown; recipients?: unknown }
      try { body = await req.json() } catch { return fail(400, "body must be JSON") }
      if (!isAgeArmor(body.ciphertext)) return fail(400, "ciphertext must be an armored age file")
      const rs = body.recipients
      if (!Array.isArray(rs) || !rs.every((r) => typeof r === "string" && RECIPIENT.test(r))) return fail(400, "recipients must be age1… keys")
      if (!sameSet(rs, recipients)) return fail(409, "recipients changed", { recipients })
      const prev = store.get(`${scope}\n${ref}`)
      const rev = (prev?.rev ?? 0) + 1
      store.set(`${scope}\n${ref}`, { ciphertext: body.ciphertext, recipients: [...recipients], rev })
      log(caller.person, "write", scope, ref)
      return json({ ref, rev })
    }
    return fail(405, "method not allowed")
  }

  return {
    fetch,
    audit,
    /** Raw stored state (for tests that grep for plaintext). */
    dump: () => JSON.stringify([...store.entries()]),
    setRecipients: (scope: string, rs: string[]) => { opts.recipients[scope] = rs },
  }
}
