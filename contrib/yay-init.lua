-- fettle: yay install-time supply-chain hook (deploy with
--   cp ~/src/fettle/contrib/yay-init.lua ~/.config/yay/init.lua)
-- Advisory AUR supply-chain tripwire for yay v13 — WARN ONLY, never blocks.
--
-- Two hooks:
--   * AURPreInstall  (per package, every install): scans the PKGBUILD/.install
--     for risky build logic, then runs `fettle aur-precheck` for live RPC/IOC
--     checks (orphaned / out-of-date / stale / compromised name / bad maintainer).
--   * UpgradeSelect  (during yay -Syu): warns when an AUR package's maintainer
--     has changed since the last upgrade (the re-adoption tell) — using the
--     maintainer field yay hands us, so it needs no network.
--
-- Loud findings go through yay.log.error with a banner; lesser ones through
-- yay.log.warn. yay's normal clean/diff/edit menus still run afterward.

-- =============================================================================
-- Build-logic scan (no network) — kept from the original tripwire
-- =============================================================================

-- Case-insensitive plain substrings (matched literally, no Lua-pattern magic):
local SUSPICIOUS = {
  "npm install", "bun install", "bun add", "pnpm install", "yarn add",
  "| sh", "|sh", "| bash", "|bash",
  "atomic-lockfile", "js-digest", "lockfile-js", "nextfile-js",  -- known IOCs
}

-- Return the list of needles found in `text`.
local function scan(text)
  local hits, hay = {}, (text or ""):lower()
  for _, needle in ipairs(SUSPICIOUS) do
    if hay:find(needle, 1, true) then        -- plain find, literal match
      hits[#hits + 1] = needle
    end
  end
  return hits
end

-- =============================================================================
-- Allowlist (synced from update.sh's LUA_ALLOWLIST -> ~/.config/yay/allowlist.txt)
-- =============================================================================

local function load_allow(path)
  local allow = {}
  if not path then
    local home = os.getenv("HOME")
    path = home and (home .. "/.config/yay/allowlist.txt")
  end
  local f = path and io.open(path, "r")
  if f then
    for raw in f:lines() do
      local line = raw:gsub("^%s+", ""):gsub("%s+$", "")
      if line ~= "" and not line:match("^#") then
        allow[#allow + 1] = line
      end
    end
    f:close()
    return allow                 -- honor the synced file as-is (may be empty)
  end
  return { "mailspring" }        -- file missing: built-in fallback
end

local ALLOW = load_allow()

-- Translate a shell-style glob into an anchored Lua pattern.
local function glob_to_pat(glob)
  local p = glob:gsub("[%^%$%(%)%%%.%[%]%+%-%?]", "%%%1")
  p = p:gsub("%*", ".*")
  return "^" .. p .. "$"
end

local function is_allowed(name)
  for _, pat in ipairs(ALLOW) do
    if name == pat then return true end                       -- exact
    if pat:find("*", 1, true) and name:match(glob_to_pat(pat)) then
      return true                                             -- glob
    end
  end
  return false
end

-- =============================================================================
-- Warning channels
-- =============================================================================

local function warn_normal(msg)
  yay.log.warn(msg)
end

local function warn_loud(msg)
  yay.log.error("══════════ SUPPLY-CHAIN ALERT ══════════")
  yay.log.error(msg)
  yay.log.error("════════════════════════════════════════")
end

-- =============================================================================
-- aur-precheck.sh bridge (live RPC/IOC checks for a single package)
-- =============================================================================

local function file_exists(p)
  local f = p and io.open(p, "r")
  if f then f:close(); return true end
  return false
end

-- Locate the precheck helper. Prefer the fettle port (`fettle aur-precheck` /
-- `python -m fettle aur-precheck`); fall back to the legacy bash helper until it
-- retires (fettle M6). AUR_PRECHECK_BIN (a path to any helper) still overrides.
local function precheck_cmd()
  local env = os.getenv("AUR_PRECHECK_BIN")
  if file_exists(env) then return env end
  if os.execute("command -v fettle >/dev/null 2>&1") == 0 then
    return "fettle aur-precheck"
  end
  if os.execute("python -c 'import fettle' >/dev/null 2>&1") == 0 then
    return "python -m fettle aur-precheck"
  end
  if os.execute("command -v aur-precheck.sh >/dev/null 2>&1") == 0 then
    return "aur-precheck.sh"
  end
  local home = os.getenv("HOME")
  local cand = home and (home .. "/src/linux_hacks/aur-precheck.sh")
  if file_exists(cand) then return cand end
  return nil
end

-- Run the helper for one package; return its stdout (or nil if unavailable).
local function run_precheck(pkg)
  local cmd = precheck_cmd()
  if not cmd then return nil end
  local safe = pkg:gsub("'", "'\\''")               -- single-quote escape
  local p = io.popen(cmd .. " '" .. safe .. "' 2>/dev/null")
  if not p then return nil end
  local out = p:read("*a") or ""
  p:close()
  return out
end

-- Render helper output: lines are "CRIT <msg>" (loud) or "WARN <msg>".
local function parse_precheck(output)
  if not output then return end
  for line in output:gmatch("[^\n]+") do
    local sev, msg = line:match("^(%u+)%s+(.*)$")
    if sev == "CRIT" then
      warn_loud(msg)
    elseif sev == "WARN" then
      warn_normal(msg)
    end
  end
end

-- =============================================================================
-- Maintainer-change cache (for the UpgradeSelect hook)
-- =============================================================================

local function mc_cache_path()
  local base = os.getenv("XDG_CACHE_HOME") or ((os.getenv("HOME") or "") .. "/.cache")
  return base .. "/update-aur/maintainer_cache"
end

local function mc_load()
  local cache, f = {}, io.open(mc_cache_path(), "r")
  if not f then return cache end
  for line in f:lines() do
    local name, maint = line:match("^([^=]+)=(.*)$")
    if name then cache[name] = maint end
  end
  f:close()
  return cache
end

local function mc_save(cache)
  local path = mc_cache_path()
  os.execute("mkdir -p '" .. path:gsub("/[^/]*$", "") .. "' 2>/dev/null")
  local f = io.open(path, "w")
  if not f then return end
  for name, maint in pairs(cache) do
    f:write(name .. "=" .. maint .. "\n")
  end
  f:close()
end

-- =============================================================================
-- Hooks
-- =============================================================================

yay.create_autocmd("AURPreInstall", {
  desc = "build-logic scan + live RPC/IOC supply-chain precheck",
  callback = function(event)
    if is_allowed(event.match) then return end

    -- 1) Build-logic scan of PKGBUILD + (best-effort) the .install hook.
    local files = { PKGBUILD = event.data.pkgbuild }
    local dir = event.data.dir
    if dir then
      local declared = (event.data.pkgbuild or ""):match("install=[\"']?([%w%._%-]+)")
      for _, name in ipairs({ declared, event.match .. ".install" }) do
        if name then
          local f = io.open(dir .. "/" .. name, "r")
          if f then files[name] = f:read("*a"); f:close() end
        end
      end
    end
    for fname, text in pairs(files) do
      local hits = scan(text)
      if #hits > 0 then
        warn_normal(string.format("%s: %s contains %s — review before installing.",
          event.match, fname, table.concat(hits, ", ")))
      end
    end

    -- 2) Live RPC/IOC precheck (orphan / OOD / stale / compromised / bad maintainer).
    if os.getenv("YAY_AUR_PRECHECK") ~= "0" then
      parse_precheck(run_precheck(event.match))
    end
  end,
})

yay.create_autocmd("UpgradeSelect", {
  desc = "warn loudly on AUR maintainer changes (re-adoption tell)",
  callback = function(event)
    local cache, dirty = mc_load(), false
    for _, pkg in ipairs(event.data.upgrades) do
      if pkg.repository == "aur" and pkg.maintainer and pkg.maintainer ~= ""
         and not is_allowed(pkg.name) then
        local prev = cache[pkg.name]
        if prev == nil then
          cache[pkg.name] = pkg.maintainer; dirty = true     -- first sight: seed silently
        elseif prev ~= pkg.maintainer then
          warn_loud(string.format(
            "%s maintainer CHANGED: %s -> %s — review build files before upgrading",
            pkg.name, prev, pkg.maintainer))
          cache[pkg.name] = pkg.maintainer; dirty = true
        end
      end
    end
    if dirty then mc_save(cache) end
    return { exclude = {}, skip_menu = false }              -- advisory: never auto-exclude
  end,
})

-- Test hook: expose file-local helpers when loaded by the suite. No effect under yay.
if rawget(_G, "__YAY_TEST") then
  return {
    scan = scan,
    is_allowed = is_allowed,
    glob_to_pat = glob_to_pat,
    load_allow = load_allow,
    parse_precheck = parse_precheck,
    mc_load = mc_load,
    mc_save = mc_save,
  }
end
