-- fnox provider for any server speaking the sealed-store protocol (PROTOCOL.md).
-- The server only ever sees age ciphertext: put encrypts locally to the scope's recipients,
-- get/get_batch decrypt locally with the user's age identity (unlocked once per session, lib/hq/keycache.lua).
local fnox = require("fnox")
local http = require("fnox.http")
local json = require("fnox.json")
local cmd = require("fnox.cmd")
local log = require("fnox.log")
local b64 = require("fnox.base64")
local keycache = require("hq.keycache")

local DEFAULT_IDENTITY = "~/.config/hq/identity.age"
local DEFAULT_TTL = 28800 -- 8 h
local KEY = "^[A-Za-z_][A-Za-z0-9_]*$"
local PROFILE = "^[a-z0-9][a-z0-9_-]*$"

local function expand(p) return (p:gsub("^~", os.getenv("HOME") or "~")) end
local function opt(ctx, k) local v = ctx.options[k]; if v ~= nil and v ~= "" then return v end end

local function hint(ctx)
  local h = opt(ctx, "login_hint")
  return h and (" (" .. h .. ")") or ""
end

local function urlencode(s)
  return (s:gsub("[^%w%-_%.~]", function(c) return string.format("%%%02X", string.byte(c)) end))
end

-- ---------- token ----------
local function token(ctx)
  local t = opt(ctx, "token") or os.getenv("HQ_TOKEN")
  if t then return t end
  local file = opt(ctx, "token_file")
  if file then
    local f = io.open(expand(file), "r")
    if f then
      local body = f:read("a"); f:close()
      if body:match("^%s*{") then
        local ok, doc = pcall(json.decode, body)
        if ok and type(doc) == "table" and type(doc.token) == "string" then return doc.token end
      else
        local line = body:match("^%s*(%S+)")
        if line then return line end
      end
    end
  end
  fnox.auth_error("no token: set options.token, HQ_TOKEN or options.token_file" .. hint(ctx))
end

-- ---------- http ----------
local function base(ctx)
  local endpoint = opt(ctx, "endpoint") or error("options.endpoint is required")
  local scope = opt(ctx, "scope") or error("options.scope is required")
  return endpoint:gsub("/+$", "") .. "/v1/scopes/" .. urlencode(scope)
end

local function call(ctx, method, path, body)
  local resp = http.request({
    method = method,
    url = base(ctx) .. path,
    headers = { Authorization = "Bearer " .. token(ctx), ["Content-Type"] = "application/json", Accept = "application/json" },
    body = body and json.encode(body) or nil,
  })
  local ok, doc = pcall(json.decode, resp.body or "")
  if not ok or type(doc) ~= "table" then doc = {} end
  if resp.status == 401 then fnox.auth_error("the store refused the token (401)" .. hint(ctx)) end
  return resp.status, doc
end

--- call that must answer 200; returns the decoded body
local function call_ok(ctx, method, path, body, what)
  local status, doc = call(ctx, method, path, body)
  if status ~= 200 then error(what .. ": HTTP " .. status .. (doc.error and (": " .. tostring(doc.error)) or "")) end
  return doc
end

-- ---------- identity (session unlock) ----------
local function cache(ctx)
  return keycache.new(opt(ctx, "key_cache") or os.getenv("HQ_KEY_CACHE") or "auto", {
    run = cmd.run, now = os.time, b64enc = b64.encode, b64dec = b64.decode,
  })
end

local function flag(name)
  local v = os.getenv(name)
  return v ~= nil and v ~= "" and v ~= "0"
end

-- A human can type the passphrase when the user's command has a terminal on stdin and /dev/tty opens (age prompts
-- there). "/dev/tty opens" alone is not enough: an agent's commands run inside tmux with stdin = /dev/null or a pipe,
-- the terminal exists but nobody watches it. fnox's own rule for prompting is the same (stdin is a TTY).
-- fnox gives every cmd.run child stdin = /dev/null, so this sh cannot test its own fd 0; it reads the fd 0 of its
-- parent, fnox, which is the stdin `fnox exec` hands the user's command: /proc on Linux, lsof on macOS. If neither
-- answers, nobody can type (fail closed: `hq unlock` in a terminal still works).
local HUMAN = [[
: </dev/tty 2>/dev/null || exit 1
t=$(readlink "/proc/$PPID/fd/0" 2>/dev/null) || t=$(lsof -w -a -p "$PPID" -d 0 -Fn 2>/dev/null | sed -n 's/^n//p')
case $t in /dev/pts/*|/dev/tty*|/dev/console) [ -c "$t" ] ;; *) exit 1 ;; esac
]]

--- No one to ask for a passphrase: then a locked identity fails at once instead of age waiting on a prompt nobody
--- answers. HQ_NONINTERACTIVE=1 forces it (wins), HQ_INTERACTIVE=1 forces the prompt.
local function noninteractive()
  if flag("HQ_NONINTERACTIVE") then return true end
  if flag("HQ_INTERACTIVE") then return false end
  return not cmd.run({ "sh", "-c", HUMAN }).ok
end

local DEFAULT_LOCKED = "locked — run `hq unlock` in a terminal"

--- The age identity text: HQ_IDENTITY, a plain identity file (machines, CI), or the passphrase-protected
--- file, from the session cache or decrypted here (age asks for the passphrase on the terminal).
local function identity(ctx, file)
  local env = os.getenv("HQ_IDENTITY")
  if env and env ~= "" then return env end
  local path = expand(file or opt(ctx, "identity_file") or os.getenv("HQ_IDENTITY_FILE") or DEFAULT_IDENTITY)
  local f = io.open(path, "r")
  if not f then error("no age identity at " .. path .. "; create one with `hq keygen`") end
  local body = f:read("a"); f:close()
  if body:find("AGE%-SECRET%-KEY%-") then return body end
  local c = cache(ctx)
  local id = c.get(path)
  if id then return id end
  -- a plain error, not auth_error: fnox would run auth_command (`hq unlock`), which would block the same way
  if noninteractive() then
    local env_msg = os.getenv("HQ_LOCKED_MESSAGE")
    error(opt(ctx, "locked_message") or (env_msg ~= "" and env_msg) or DEFAULT_LOCKED, 0)
  end
  local r = cmd.run({ "age", "-d", path })
  if not r.ok then
    fnox.auth_error("age identity is locked: run `hq unlock` in a terminal (" .. (r.stderr:gsub("%s+$", "")) .. ")")
  end
  local ttl = tonumber(opt(ctx, "key_ttl") or DEFAULT_TTL) or DEFAULT_TTL
  local ok, err = pcall(c.put, path, r.stdout, ttl)
  if not ok then log.warn("hq: could not cache the identity (" .. c.name .. "): " .. tostring(err)) end
  return r.stdout
end

-- identity on fd 3 and ciphertext through the environment: never in argv, never in a file
local function decrypt(id, ciphertext)
  local r = cmd.run({ "sh", "-c", 'exec 3<&0; printf "%s" "$HQ_CIPHERTEXT" | age -d -i /dev/fd/3' },
    { stdin = id, env = { HQ_CIPHERTEXT = ciphertext } })
  if not r.ok then error("age could not decrypt (is your key among the scope's recipients?): " .. r.stderr) end
  return r.stdout
end

local function encrypt(recipients, value)
  if #recipients == 0 then error("the scope has no recipients; register an age key first") end
  local argv = { "age", "-a" }
  for _, r in ipairs(recipients) do table.insert(argv, "-r"); table.insert(argv, r) end
  local r = cmd.run(argv, { stdin = value })
  if not r.ok then error("age could not encrypt: " .. r.stderr) end
  return r.stdout
end

-- ---------- refs ----------
local function ref_of(ctx, key)
  local profile, name = key:match("^([^/]+)/([^/]+)$")
  if not profile then profile, name = opt(ctx, "profile") or "default", key end
  if not name:match(KEY) then error("invalid secret name '" .. name .. "'") end
  if not profile:match(PROFILE) then error("invalid profile '" .. profile .. "'") end
  return profile .. "/" .. name
end

-- ---------- hooks ----------
local function get_batch(ctx, refs)
  local q = {}
  for _, ref in ipairs(refs) do table.insert(q, "ref=" .. urlencode(ref_of(ctx, ref))) end
  local doc = call_ok(ctx, "GET", "/secrets?" .. table.concat(q, "&"), nil, "get secrets")
  local found = doc.secrets or {}
  local out, id = {}, nil
  for _, ref in ipairs(refs) do
    local s = found[ref_of(ctx, ref)]
    if s and s.ciphertext then
      id = id or identity(ctx)
      out[ref] = decrypt(id, s.ciphertext)
    end
  end
  log.debug("hq: " .. #refs .. " requested, one request")
  return out
end

-- mode = "identity": this provider instance yields the unlocked identity itself (ref = identity file path), for
-- fnox's own age provider (`identity = { provider = "hq-identity", value = "~/.config/hq/identity.age" }`), which
-- cannot read passphrase-protected identity files: break-glass configs in git, decrypted with the same session unlock.
local function identity_mode(ctx) return opt(ctx, "mode") == "identity" end

return {
  get = function(ctx, ref)
    if identity_mode(ctx) then return identity(ctx, ref ~= "" and ref or nil) end
    return get_batch(ctx, { ref })[ref]
  end,
  get_batch = function(ctx, refs)
    if not identity_mode(ctx) then return get_batch(ctx, refs) end
    local out = {}
    for _, ref in ipairs(refs) do out[ref] = identity(ctx, ref ~= "" and ref or nil) end
    return out
  end,

  put = function(ctx, key, value)
    if identity_mode(ctx) then error("mode = identity is read-only") end
    local ref = ref_of(ctx, key)
    for _ = 1, 2 do
      local recipients = call_ok(ctx, "GET", "/recipients", nil, "get recipients").recipients or {}
      local status, doc = call(ctx, "PUT", "/secrets/" .. ref, { ciphertext = encrypt(recipients, value), recipients = recipients })
      if status == 200 then return doc.ref or ref end
      if status ~= 409 then error("put " .. ref .. ": HTTP " .. status .. (doc.error and (": " .. tostring(doc.error)) or "")) end
      log.info("hq: recipients changed while writing " .. ref .. "; encrypting again")
    end
    error("put " .. ref .. ": recipients keep changing (409)")
  end,

  test = function(ctx)
    if identity_mode(ctx) then return end
    local rs = call_ok(ctx, "GET", "/recipients", nil, "get recipients").recipients or {}
    if #rs == 0 then error("reachable, but the scope has no recipients") end
  end,
}
