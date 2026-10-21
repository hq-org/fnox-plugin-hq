-- Unit spec for lib/hq/keycache.lua with a fake command runner and clock. Run: lua5.4 test/keycache_spec.lua
package.path = arg[0]:gsub("test/keycache_spec.lua$", "") .. "lib/?.lua;" .. package.path
local keycache = require("hq.keycache")

local failures, count = 0, 0
local function check(name, cond)
  count = count + 1
  if not cond then failures = failures + 1; print("FAIL " .. name) end
end

local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64enc(s)
  return ((s:gsub(".", function(x)
    local r, b = "", x:byte()
    for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
    if #x < 6 then return "" end
    local c = 0
    for i = 1, 6 do c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0) end
    return b64chars:sub(c + 1, c + 1)
  end) .. ({ "", "==", "=" })[#s % 3 + 1])
end
local function b64dec(s)
  s = s:gsub("[^" .. b64chars .. "=]", "")
  return (s:gsub(".", function(x)
    if x == "=" then return "" end
    local r, f = "", (b64chars:find(x) - 1)
    for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
    if #x ~= 8 then return "" end
    local c = 0
    for i = 1, 8 do c = c + (x:sub(i, i) == "1" and 2 ^ (8 - i) or 0) end
    return string.char(c)
  end))
end

--- fake `security`: items keyed by service/account; records every argv and stdin
local function fake_security()
  local f = { items = {}, calls = {}, t = 1000 }
  local function key(argv)
    local s, a
    for i = 1, #argv do
      if argv[i] == "-s" then s = argv[i + 1] end
      if argv[i] == "-a" then a = argv[i + 1] end
    end
    return s .. "|" .. a
  end
  f.run = function(argv, opts)
    table.insert(f.calls, { argv = argv, stdin = opts and opts.stdin })
    local verb = argv[2]
    if argv[1] == "uname" then return { ok = true, stdout = "Darwin\n", stderr = "" } end
    if verb == "-i" then
      local svc, acct, payload = opts.stdin:match('^add%-generic%-password %-U %-s (%S+) %-a "([^"]*)" %-w (%S+)\n$')
      if not svc then return { ok = false, stdout = "", stderr = "parse error" } end
      f.items[svc .. "|" .. acct] = payload
      return { ok = true, stdout = "", stderr = "" }
    elseif verb == "find-generic-password" then
      local v = f.items[key(argv)]
      if not v then return { ok = false, stdout = "", stderr = "not found" } end
      return { ok = true, stdout = v .. "\n", stderr = "" }
    elseif verb == "delete-generic-password" then
      local k = key(argv)
      local had = f.items[k] ~= nil
      f.items[k] = nil
      return { ok = had, stdout = "", stderr = "" }
    end
    return { ok = false, stdout = "", stderr = "unexpected " .. table.concat(argv, " ") }
  end
  f.deps = { run = f.run, now = function() return f.t end, b64enc = b64enc, b64dec = b64dec }
  return f
end

local ID = "# created: x\n# public key: age1xyz\nAGE-SECRET-KEY-1FAKEFAKEFAKE\n"
local PATH = "/home/u/.config/hq/identity.age"

-- macos: argv shapes, identity never in argv, expiry enforced, delete on lock
do
  local f = fake_security()
  local c = keycache.new("macos", f.deps)
  check("macos name", c.name == "macos")
  check("macos miss", c.get(PATH) == nil)
  c.put(PATH, ID, 3600)
  local put = f.calls[#f.calls]
  check("put uses security -i", put.argv[1] == "security" and put.argv[2] == "-i" and #put.argv == 2)
  check("put stdin has service and account", put.stdin:find('-s fnox-plugin-hq -a "' .. PATH .. '" -w fnox-plugin-hq:v1:4600:', 1, true) ~= nil)
  for _, call in ipairs(f.calls) do
    check("identity never in argv", not table.concat(call.argv, " "):find("AGE-SECRET-KEY", 1, true))
  end
  check("put stdin carries no plain identity", not put.stdin:find("AGE-SECRET-KEY", 1, true))
  check("macos hit", c.get(PATH) == ID)
  local find = f.calls[#f.calls].argv
  check("find argv", table.concat(find, " ") == "security find-generic-password -s fnox-plugin-hq -a " .. PATH .. " -w")
  f.t = 4599
  check("still valid one second before expiry", c.get(PATH) == ID)
  f.t = 4600
  check("expired at expiry", c.get(PATH) == nil)
  check("expired item deleted", f.items["fnox-plugin-hq|" .. PATH] == nil)
  local del = f.calls[#f.calls].argv
  check("delete argv", table.concat(del, " ") == "security delete-generic-password -s fnox-plugin-hq -a " .. PATH)
  c.put(PATH, ID, 60)
  check("clear returns true", c.clear(PATH) == true)
  check("clear removes", c.get(PATH) == nil)
  check("clear twice returns false", c.clear(PATH) == false)
  f.items["fnox-plugin-hq|" .. PATH] = "garbage"
  check("foreign value = miss", c.get(PATH) == nil)
  check("foreign value deleted", f.items["fnox-plugin-hq|" .. PATH] == nil)
  check("quote in path refused", not pcall(c.put, '/tmp/a"b', ID, 60))
end

-- keyctl: argv shapes and perms/timeout
do
  local calls, keys, n = {}, {}, 100
  local run = function(argv, opts)
    table.insert(calls, { argv = argv, stdin = opts and opts.stdin })
    if argv[2] == "padd" then n = n + 1; keys[argv[4]] = { id = tostring(n), v = opts.stdin }; return { ok = true, stdout = n .. "\n", stderr = "" } end
    if argv[2] == "search" then local k = keys[argv[5]]; return { ok = k ~= nil, stdout = k and (k.id .. "\n") or "", stderr = "" } end
    if argv[2] == "pipe" then for _, k in pairs(keys) do if k.id == argv[3] then return { ok = true, stdout = k.v, stderr = "" } end end return { ok = false, stdout = "", stderr = "" } end
    if argv[2] == "unlink" then for name, k in pairs(keys) do if k.id == argv[3] then keys[name] = nil end end end
    return { ok = true, stdout = "", stderr = "" }
  end
  local c = keycache.new("keyctl", { run = run, now = os.time })
  check("keyctl miss", c.get(PATH) == nil)
  c.put(PATH, ID, 28800)
  check("link user keyring into the session", table.concat(calls[2].argv, " ") == "keyctl link @u @s")
  check("padd argv", table.concat(calls[3].argv, " ") == "keyctl padd user fnox-plugin-hq:" .. PATH .. " @u" and calls[3].stdin == ID)
  check("setperm user-only read", table.concat(calls[4].argv, " ") == "keyctl setperm 101 0x3f0b0000")
  check("timeout", table.concat(calls[5].argv, " ") == "keyctl timeout 101 28800")
  check("keyctl hit", c.get(PATH) == ID)
  check("keyctl clear", c.clear(PATH) == true and c.get(PATH) == nil)
  -- a refused timeout must not leave the identity behind
  local strict = function(argv, opts)
    if argv[2] == "timeout" then return { ok = false, stdout = "", stderr = "Permission denied" } end
    return run(argv, opts)
  end
  local c2 = keycache.new("keyctl", { run = strict, now = os.time })
  check("refused timeout errors", not pcall(c2.put, PATH, ID, 60))
  check("refused timeout leaves nothing", c2.get(PATH) == nil)
end

-- detect + none + unknown
do
  local f = fake_security()
  check("detect Darwin", keycache.detect(f.deps) == "macos")
  local linux = { run = function(argv) if argv[1] == "uname" then return { ok = true, stdout = "Linux\n" } end return { ok = true, stdout = "/usr/bin/keyctl\n" } end }
  check("detect keyctl", keycache.detect(linux) == "keyctl")
  local bare = { run = function(argv) if argv[1] == "uname" then return { ok = true, stdout = "Linux\n" } end return { ok = false, stdout = "" } end }
  check("detect none", keycache.detect(bare) == "none")
  local none = keycache.new("none", bare)
  none.put(PATH, ID, 1)
  check("none never caches", none.get(PATH) == nil)
  check("unknown backend errors", not pcall(keycache.new, "vault", bare))
end

print(string.format("%d checks, %d failures", count, failures))
os.exit(failures == 0 and 0 or 1)
