-- fnox provider for any server speaking the sealed-store protocol (PROTOCOL.md): a shim over the `hq` command
-- (hq-org/hq, platform/surfaces/cli; hq:Decision/one-hq-cli). `hq` does the protocol, the age crypto and the session
-- unlock natively; this file only maps fnox's hooks and options onto it. No crypto and no protocol in Lua.
--   get / get_batch  →  hq secrets get --batch   (refs as JSON on stdin, {ref: value} as JSON on stdout)
--   put              →  hq secrets set --batch K (the value on stdin, the stored ref on stdout)
--   test             →  hq secrets recipients
--   mode = identity  →  hq identity <file>        (the unlocked identity, for fnox's own age provider)
-- Secrets never travel in argv: values and refs go through stdin/stdout, a token from options.token through the env.
local fnox = require("fnox")
local json = require("fnox.json")
local cmd = require("fnox.cmd")

local function opt(ctx, k) local v = ctx.options[k]; if v ~= nil and v ~= "" then return tostring(v) end end

-- option → hq flag (endpoint, scope, profile, token_file, locked_message and the rest keep their v0.4 meaning)
local FLAGS = {
  endpoint = "--endpoint", scope = "--scope", space = "--space", context = "--ctx", profile = "--profile",
  token_file = "--token-file", identity_file = "--identity-file", key_cache = "--key-cache", key_ttl = "--key-ttl",
  login_hint = "--login-hint", locked_message = "--locked-message",
}
local ORDER = { "endpoint", "scope", "space", "context", "profile", "token_file", "identity_file", "key_cache", "key_ttl", "login_hint", "locked_message" }

local function hq(ctx, args, stdin)
  local argv = { opt(ctx, "hq") or os.getenv("HQ_BIN") or "hq" }
  for _, a in ipairs(args) do table.insert(argv, a) end
  for _, k in ipairs(ORDER) do
    local v = opt(ctx, k)
    if v then table.insert(argv, FLAGS[k]); table.insert(argv, v) end
  end
  local env = {}
  local token = opt(ctx, "token")
  if token then env.HQ_TOKEN = token end
  local r = cmd.run(argv, { stdin = stdin or "", env = env })
  if r.ok then return r.stdout end
  local msg = (r.stderr or ""):gsub("^hq: ", ""):gsub("%s+$", "")
  if msg == "" then msg = "hq exited with " .. tostring(r.status) end
  -- 3 = authentication (no or a refused token, a wrong passphrase): fnox may run auth_command (`hq unlock`).
  -- A locked identity with nobody to type is a plain error (1): auth_command would block the same way.
  if r.status == 3 then fnox.auth_error(msg) end
  error(msg, 0)
end

local function identity_mode(ctx) return opt(ctx, "mode") == "identity" end

local function get_batch(ctx, refs)
  if #refs == 0 then return {} end
  local out = hq(ctx, { "secrets", "get", "--batch" }, json.encode(refs))
  local ok, doc = pcall(json.decode, out)
  if not ok or type(doc) ~= "table" then error("hq secrets get --batch: not JSON", 0) end
  return doc
end

local function identity(ctx, ref)
  local args = { "identity" }
  if ref and ref ~= "" then table.insert(args, ref) end
  return hq(ctx, args)
end

return {
  get = function(ctx, ref)
    if identity_mode(ctx) then return identity(ctx, ref) end
    return get_batch(ctx, { ref })[ref]
  end,
  get_batch = function(ctx, refs)
    if not identity_mode(ctx) then return get_batch(ctx, refs) end
    local out = {}
    for _, ref in ipairs(refs) do out[ref] = identity(ctx, ref) end
    return out
  end,
  put = function(ctx, key, value)
    if identity_mode(ctx) then error("mode = identity is read-only", 0) end
    return (hq(ctx, { "secrets", "set", "--batch", key }, value):gsub("%s+$", ""))
  end,
  test = function(ctx)
    if identity_mode(ctx) then return end
    hq(ctx, { "secrets", "recipients" })
  end,
}
