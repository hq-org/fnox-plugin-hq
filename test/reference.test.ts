// The conformance suite against the in-memory reference server (and through fnox when fnox + age are installed).
import { afterAll, expect, test } from "bun:test"
import { join } from "node:path"
import { generateX25519Identity, identityToRecipient } from "age-encryption"
import { conformance, PLANT } from "../conformance/suite"
import { createReferenceServer } from "../reference/server"

const identity = await generateX25519Identity()
const other = await identityToRecipient(await generateX25519Identity())
const ref = createReferenceServer({
  tokens: {
    rw: { person: "alice", read: true, write: true },
    ro: { person: "bob", read: true, write: false },
    none: { person: "carol", read: false, write: false },
    root: { person: "admin", read: true, write: true },
  },
  recipients: { "prj_test": [await identityToRecipient(identity), other], usr_alice: [await identityToRecipient(identity)] },
  personal: { usr_alice: "alice" },
})
const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: ref.fetch })
afterAll(() => server.stop(true))

conformance("reference server", () => ({
  url: `http://127.0.0.1:${server.port}/`,
  scope: "prj_test",
  token: "rw",
  identity,
  readOnlyToken: "ro",
  noReadToken: "none",
  plugin: { dir: join(import.meta.dir, "..") },
  personal: { scope: "usr_alice", token: "rw", identity, others: ["ro", "root"] },
}))

test("storage never held the planted plaintext; reads and writes are audited", () => {
  expect(ref.dump()).not.toContain(PLANT)
  expect(ref.dump()).toContain("BEGIN AGE ENCRYPTED FILE")
  expect(ref.audit.some((a) => a.action === "read" && a.person === "alice")).toBe(true)
  expect(ref.audit.some((a) => a.action === "write")).toBe(true)
  expect(ref.audit.some((a) => a.person === "carol")).toBe(false)
})
