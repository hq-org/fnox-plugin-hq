-- Session cache for the unlocked age identity: "unlock once, then agents run on their own".
-- Backends share one interface: get(id) -> value|nil, put(id, value, ttl_seconds), clear(id).
-- `id` = the absolute path of the passphrase-protected identity file. bin/hq implements the same
-- names and formats in sh, so `hq unlock` and the plugin see the same cache.
--   keyctl  Linux kernel user keyring: key "fnox-plugin-hq:<id>", kernel-enforced timeout.
--   macos   login Keychain generic password: service "fnox-plugin-hq", account <id>; the value carries
--           its expiry ("fnox-plugin-hq:v1:<unix expiry>:<base64 identity>"), enforced here on read.
--   none    no cache: every decrypt in a terminal asks for the passphrase.
-- Dependencies are injected (run = fnox.cmd.run, now = os.time, b64enc/b64dec = fnox.base64) for tests.
local M = {}

M.NAME = "fnox-plugin-hq"
M.PREFIX = M.NAME .. ":v1:"

local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end

local function keyctl(d)
  local function find(id)
    local s = d.run({ "keyctl", "search", "@u", "user", M.NAME .. ":" .. id })
    if not s.ok then return nil end
    local kid = trim(s.stdout)
    return kid ~= "" and kid or nil
  end
  return {
    name = "keyctl",
    get = function(id)
      local kid = find(id)
      if not kid then return nil end
      local r = d.run({ "keyctl", "pipe", kid })
      if r.ok and r.stdout ~= "" then return r.stdout end
      return nil
    end,
    put = function(id, value, ttl)
      -- possess the user keyring from this session (some sessions don't link it), or setperm/timeout are refused
      d.run({ "keyctl", "link", "@u", "@s" })
      local r = d.run({ "keyctl", "padd", "user", M.NAME .. ":" .. id, "@u" }, { stdin = value })
      if not r.ok then error("keyctl padd failed: " .. r.stderr) end
      local kid = trim(r.stdout)
      -- possessor: all; user: view, read, search (other processes of the same user, e.g. agents)
      local p = d.run({ "keyctl", "setperm", kid, "0x3f0b0000" })
      local t = p.ok and d.run({ "keyctl", "timeout", kid, tostring(ttl) })
      if not (p.ok and t.ok) then
        -- never leave an identity in the keyring without its timeout
        d.run({ "keyctl", "revoke", kid })
        d.run({ "keyctl", "unlink", kid, "@u" })
        error("keyctl could not set perms/timeout: " .. ((t and t.stderr) or p.stderr))
      end
    end,
    clear = function(id)
      local kid = find(id)
      if not kid then return false end
      d.run({ "keyctl", "revoke", kid })
      d.run({ "keyctl", "unlink", kid, "@u" })
      return true
    end,
  }
end

local function macos(d)
  local function base(verb, id)
    return { "security", verb, "-s", M.NAME, "-a", id }
  end
  local self
  self = {
    name = "macos",
    get = function(id)
      local argv = base("find-generic-password", id)
      table.insert(argv, "-w")
      local r = d.run(argv)
      if not r.ok then return nil end
      local expiry, b64 = trim(r.stdout):match("^" .. M.PREFIX:gsub("%p", "%%%0") .. "(%d+):(.+)$")
      if not expiry or tonumber(expiry) <= d.now() then
        self.clear(id)
        return nil
      end
      return d.b64dec(b64)
    end,
    put = function(id, value, ttl)
      if id:find('["\\\n]') then error("identity path must not contain quotes, backslashes or newlines: " .. id) end
      local payload = M.PREFIX .. tostring(d.now() + ttl) .. ":" .. d.b64enc(value)
      -- `security -i` reads the command from stdin, so the identity never appears in argv (ps)
      local line = string.format('add-generic-password -U -s %s -a "%s" -w %s\n', M.NAME, id, payload)
      local r = d.run({ "security", "-i" }, { stdin = line })
      if not r.ok then error("security add-generic-password failed: " .. r.stderr) end
    end,
    clear = function(id)
      return d.run(base("delete-generic-password", id)).ok
    end,
  }
  return self
end

local function none()
  return { name = "none", get = function() return nil end, put = function() end, clear = function() return false end }
end

--- "auto" picks macos on Darwin, keyctl when the keyctl binary exists, else none.
function M.detect(d)
  local u = d.run({ "uname", "-s" })
  if u.ok and trim(u.stdout) == "Darwin" then return "macos" end
  if d.run({ "sh", "-c", "command -v keyctl" }).ok then return "keyctl" end
  return "none"
end

function M.new(kind, d)
  kind = kind or "auto"
  if kind == "auto" then kind = M.detect(d) end
  if kind == "keyctl" then return keyctl(d) end
  if kind == "macos" then return macos(d) end
  if kind == "none" then return none() end
  error("unknown key_cache backend '" .. kind .. "' (auto, keyctl, macos, none)")
end

return M
