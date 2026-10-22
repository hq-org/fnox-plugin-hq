# Sealed-store protocol v1

A small HTTP protocol for storing secrets that the server can never read. Clients (this fnox plugin,
a web page, a CLI) encrypt every value locally with [age](https://age-encryption.org) to the public keys
the server lists for a scope, and decrypt locally with their own identity. The server stores and returns
opaque age ciphertext, checks who may read and write, and keeps an audit trail.

`conformance/` tests any server against this document (see README).

## Terms

- **endpoint**: base URL, e.g. `https://tasks.example.com/secrets`. All paths below are relative to it.
- **scope**: a group of secrets sharing one recipient list (tasks: a project id). `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`.
- **profile**: a variant of a scope (`default`, `production`, …). `^[a-z0-9][a-z0-9_-]{0,62}$`.
- **key**: the secret's name, an environment variable name. `^[A-Za-z_][A-Za-z0-9_]{0,127}$`.
- **ref**: `<profile>/<key>`; what fnox stores in `fnox.toml` as the secret's `value`.
- **recipient**: an age X25519 public key, `^age1[02-9ac-hj-np-z]{58}$`.
- **ciphertext**: an ASCII-armored age file (`-----BEGIN AGE ENCRYPTED FILE-----` … `-----END AGE ENCRYPTED FILE-----`),
  at most 64 KiB, whose decoded body starts with `age-encryption.org/v1\n`.

## Auth

Every request carries `Authorization: Bearer <token>`. Missing, unknown or revoked token → `401`
(the client should log in again). A valid token without the needed permission → `403`.

## Requests

All bodies are JSON (`Content-Type: application/json`). Errors are `{"error": "<message>"}`.

### `GET /v1/scopes/{scope}/recipients`

The public keys every new value in the scope must be encrypted to.

```json
200 {"recipients": ["age1…", "age1…"]}
```

The list may be empty (nobody can decrypt yet); clients refuse to write then.

### `GET /v1/scopes/{scope}/secrets?ref=<ref>&ref=<ref>…`

Ciphertexts by ref (each `ref` URL-encoded; at most 100). Refs that do not exist are left out.
Without any `ref` parameter: every secret of the scope (used by re-encryption tools).

```json
200 {"secrets": {"default/API_KEY": {"ciphertext": "-----BEGIN AGE…", "recipients": ["age1…"], "rev": 3}}}
```

`recipients` = the list the ciphertext was encrypted to; `rev` counts writes of the value, from 1.
A server records every returned secret as read by the caller (audit).

### `PUT /v1/scopes/{scope}/secrets/{profile}/{key}`

Create or replace a value.

```json
{"ciphertext": "-----BEGIN AGE ENCRYPTED FILE-----\n…", "recipients": ["age1…", "age1…"]}
→ 200 {"ref": "default/API_KEY", "rev": 4}
```

- `recipients` must equal the scope's current recipient list as a set; otherwise `409`
  `{"error": "…", "recipients": [current list]}` and the client encrypts again.
- Anything that is not an armored age file → `400`; a bad profile, key or scope → `400`.

### `DELETE /v1/scopes/{scope}/secrets/{profile}/{key}`

Remove a value: `200 {"ref": "default/API_KEY"}`; unknown ref → `404`. A server may keep the history.

## Status codes

| code | meaning |
|------|---------|
| 200 | done |
| 400 | invalid ref, scope or ciphertext |
| 401 | no valid token: log in |
| 403 | the token's owner may not do this |
| 404 | unknown scope, unknown ref on DELETE, unknown path |
| 409 | recipients changed: fetch them and encrypt again |

## Guarantees a server gives

1. Plaintext never reaches it: it refuses bodies that are not age ciphertext and never decrypts.
2. Every read (each secret returned) and every write is attributable to the token's owner.
3. Recipients are public keys of the people and machines allowed to read the scope. Removing someone
   from the list does not re-encrypt stored values: a client with access re-encrypts them (fetch all,
   decrypt, encrypt to the new list, `PUT`). Values the removed party has already seen must be rotated.

## Versioning

Paths carry `v1`. Additive changes (new response fields, new optional parameters) keep `v1`;
clients ignore fields they do not know.
