--[[ 
ShieldLite v2.1 — simple, scoped anti‑tamper (Roblox‑safe)
- No global patching
- No metatable writes
- No RenderStepped hooks

Beginner one‑liner:
    local Shield = loadstring(game:HttpGet("https://raw.githubusercontent.com/notadminnn/VZN/refs/heads/main/shield.lua"))().easy("balanced")
    Shield.protect(function()
        -- your protected code here
    end)

Advanced (unchanged):
    local ShieldLite = loadstring(game:HttpGet("..."))()
    local shield = ShieldLite({
        minScore = 1,
        onDetect = ShieldLite.handlers.warnAndContinue, -- or .warnAndFail
        background = true,
        interval = 6.0,
        fingerprint = true,
    })
    shield:withGuard(function() ... end)
]]--

--// Services
local Http = game:GetService("HttpService")

--// Local helpers
local function now() return os.clock() end
local function guid() return Http:GenerateGUID(false) end
local function safepcall(f, ...) local ok,a,b,c,d = pcall(f, ...); return ok,a,b,c,d end
local function append(t, s) t[#t+1] = s end

-- // Default options
local DEFAULT_OPTS = {
    onDetect    = nil,   -- function(event, score, reasons, result) -> nil
    minScore    = 1,     -- how many findings before we act
    background  = true,  -- keep scanning every few seconds (deferred, not every frame)
    interval    = 6.0,   -- seconds between background scans
    fingerprint = true,  -- create a closure fingerprint & verify it stays the same
    checks = {
        globals       = true, -- exploit-only globals
        debugApis     = true, -- suspicious debug.* entries
        instanceMT    = true, -- instance metatable visible
        rawMTGame     = true, -- getrawmetatable(game) succeeds
        timingWarp    = true, -- abnormal wait timing

        -- NEW passive checks (no hooks/writes)
        threadIdentity= false, -- identity changes without your code doing it
        genvMismatch  = false, -- getgenv() ~= _G (env swap tell)
        executorTag   = false, -- common executor identify func exists
    },
    detectDebounce = 0.5, -- Don’t fire onDetect more often than this (seconds)
}

-- “Red flag” globals typically only present in exploit envs
local RED_GLOBALS = {
    "getgc","getreg","getgenv","getrenv","getsenv","getinstances","getloadedmodules",
    "newcclosure","clonefunction","hookmetamethod","setreadonly","make_writeable","makewritable",
    "getrawmetatable","setnamecallmethod","getnamecallmethod","checkcaller",
}

-- Debug APIs Roblox doesn’t normally expose to Luau user scripts
local RED_DEBUG = {
    "getupvalue","getupvalues","setupvalue","getconstant","getconstants",
    "getproto","getprotos","getlocal","setlocal","sethook","gethook","getregistry",
    "setmetatable","getmetatable","getuservalue","setuservalue",
}

--// Internal: fingerprint to detect closure/upvalue swapping
local function makeFingerprint()
    local secret, salt = guid(), math.random(1e6, 9e6)
    local function token(x)
        -- safer pack for Luau: no floating endian fun if bit32 missing
        local bx = (bit32 and bit32.bxor or function(a,b)
            local r,bit=0,1; while a>0 or b>0 do
                local aa=a%2; local bb=b%2
                if (aa+bb)==1 then r=r+bit end
                a=(a-aa)/2; b=(b-bb)/2; bit=bit*2
            end; return r
        end)(#secret + salt, x or 0)
        return tostring(bx) -- stable enough within this closure
    end
    return {
        secret = secret,
        check = function()
            local a = token(12345)
            local b = token(12345)
            return a == b -- true unless closure/upvalues were swapped
        end
    }
end

--// Internal: perform one scan, return score & reasons
local function scanOnce(tag, checks)
    local score, reasons = 0, {}

    -- 1) Exploit-only globals
    if checks.globals then
        for _, k in ipairs(RED_GLOBALS) do
            if rawget(_G, k) ~= nil then
                score = score + 1; append(reasons, ("global '%s' present"):format(k))
            end
        end
    end

    -- 2) Suspicious debug members
    if checks.debugApis and debug then
        for _, k in ipairs(RED_DEBUG) do
            if rawget(debug, k) ~= nil then
                score = score + 1; append(reasons, ("debug.%s present"):format(k))
            end
        end
    end

    -- 3) Instances should not expose metatables to Luau
    if checks.instanceMT then
        local ok_mt, mt = safepcall(getmetatable, game)
        if ok_mt and type(mt) == "table" then
            score = score + 1; append(reasons, "Instance metatable unexpectedly visible")
        end
    end

    -- 4) getrawmetatable(game) should be inaccessible in vanilla Luau
    if checks.rawMTGame then
        local grm = rawget(_G, "getrawmetatable")
        if grm then
            local ok_grm, mt2 = safepcall(grm, game)
            if ok_grm and type(mt2) == "table" then
                score = score + 1; append(reasons, "getrawmetatable(game) succeeded")
            end
        end
    end

    -- 5) sanity timing — extreme time warps
    if checks.timingWarp then
        local t0 = now()
        task.wait(0.01) -- tiny yield; harmless
        local dt = now() - t0
        if dt < 0 or dt > 1.0 then
            score = score + 1; append(reasons, ("weird wait dt=%.3f"):format(dt))
        end
    end

    -- 6) NEW: thread identity toggling spontaneously
    if checks.threadIdentity then
        local gettid = rawget(_G, "getthreadidentity") or rawget(_G, "getidentity")
        if type(gettid) == "function" then
            local a_ok, a = safepcall(gettid)
            task.wait() -- minimal yield
            local b_ok, b = safepcall(gettid)
            if a_ok and b_ok and a ~= b then
                score = score + 1; append(reasons, ("thread identity changed (%s -> %s)"):format(tostring(a), tostring(b)))
            end
        end
    end

    -- 7) NEW: genv mismatch (env swapped)
    if checks.genvMismatch then
        local ggv = rawget(_G, "getgenv")
        if type(ggv) == "function" then
            local ok, env = safepcall(ggv)
            if ok and env and env ~= _G then
                score = score + 1; append(reasons, "getgenv() differs from _G")
            end
        end
    end

    -- 8) NEW: executor tag (soft signal only)
    if checks.executorTag then
        if type(rawget(_G, "identifyexecutor")) == "function" then
            score = score + 1; append(reasons, "identifyexecutor() available")
        end
    end

    return score, reasons, tag
end

--// Class
local ShieldLite = {}
ShieldLite.__index = ShieldLite

-- Built-in handlers you can reuse
ShieldLite.handlers = {
    warnAndContinue = function(event, score, reasons, result)
        warn(("[ShieldLite] Detected: %s (score=%d)"):format(event, score))
        for i, r in ipairs(reasons or {}) do print(("  %d) %s"):format(i, r)) end
    end,
    warnAndFail = function(event, score, reasons, result)
        local msg = ("[ShieldLite] %s (score=%d)\n- %s")
            :format(event, score, table.concat(reasons or {}, "\n- "))
        warn(msg)
        error(msg, 0)
    end,
}

-- Factory (callable like a function): ShieldLite(opts) -> instance
setmetatable(ShieldLite, {
    __call = function(_, opts)
        return ShieldLite.new(opts)
    end
})

local function makeResult(tag, score, reasons, passed)
    return {
        tag = tag or "scan",
        score = score or 0,
        reasons = reasons or {},
        passed = passed,         -- boolean
        timestamp = os.clock(),
    }
end

function ShieldLite.new(opts)
    local merged = setmetatable(opts or {}, { __index = DEFAULT_OPTS })
    -- shallow copy checks so users can override partially
    merged.checks = setmetatable(merged.checks or {}, { __index = DEFAULT_OPTS.checks })

    local self = setmetatable({
        opts        = merged,
        fprint      = (merged.fingerprint and makeFingerprint()) or nil,
        _running    = false,
        _lastDetect = 0,
    }, ShieldLite)

    -- NEW: auto‑start background if requested (beginner‑friendly)
    if self.opts.background then
        task.defer(function()
            self:startBackground()
        end)
    end

    return self
end

-- Internal helper: should we fire onDetect now (debounce)?
function ShieldLite:_canFireDetect()
    local t = now()
    if (t - (self._lastDetect or 0)) >= (self.opts.detectDebounce or 0) then
        self._lastDetect = t
        return true
    end
    return false
end

-- Public: run a scan (returns result object)
function ShieldLite:scan(tag)
    local score, reasons = scanOnce(tag or "scan", self.opts.checks)
    if self.fprint and not self.fprint.check() then
        score = score + 1; append(reasons, "closure fingerprint mismatch")
    end

    local passed = (score < (self.opts.minScore or 1))
    local result = makeResult(tag or "scan", score, reasons, passed)

    if not passed then
        if self.opts.onDetect and self:_canFireDetect() then
            self.opts.onDetect(result.tag, result.score, result.reasons, result)
        elseif not self.opts.onDetect then
            ShieldLite.handlers.warnAndFail(result.tag, result.score, result.reasons, result)
        end
    end

    return result
end

-- Public: begin background scans (cheap, deferred)
function ShieldLite:startBackground()
    if self._running or not self.opts.background then return end
    self._running = true
    task.defer(function()
        while self._running do
            local ok = pcall(function()
                self:scan("background")
            end)
            if not ok then
                -- If handler errored intentionally, stop.
                self._running = false
                break
            end
            task.wait(self.opts.interval or 6.0)
        end
    end)
end

function ShieldLite:stopBackground()
    self._running = false
end

-- Public: Guard runs your sensitive function after a pre‑scan.
function ShieldLite:guard(fn, ...)
    assert(type(fn) == "function", "ShieldLite:guard expects a function")
    local res = self:scan("pre")
    return fn(...)
end

function ShieldLite:withGuard(fn)
    return self:guard(fn)
end

function ShieldLite:format(result)
    result = result or { score = 0, reasons = {}, tag = "scan", passed = true }
    local head = ("[%s] score=%d passed=%s"):format(result.tag, result.score, tostring(result.passed))
    if #result.reasons == 0 then return head .. " (no reasons)" end
    return head .. "\n- " .. table.concat(result.reasons, "\n- ")
end

-- NEW: Beginner presets + façade
local PRESETS = {
    low = function()
        return {
            minScore   = 2,
            background = true,
            interval   = 8.0,
            fingerprint= false,
            onDetect   = ShieldLite.handlers.warnAndContinue,
            checks = {
                globals    = true,
                debugApis  = false,
                instanceMT = true,
                rawMTGame  = true,
                timingWarp = false,
                threadIdentity = false,
                genvMismatch   = false,
                executorTag    = false,
            }
        }
    end,
    balanced = function()
        return {
            minScore   = 1,
            background = true,
            interval   = 6.0,
            fingerprint= true,
            onDetect   = ShieldLite.handlers.warnAndContinue,
            checks = {
                globals    = true,
                debugApis  = true,
                instanceMT = true,
                rawMTGame  = true,
                timingWarp = true,
                threadIdentity = false,
                genvMismatch   = false,
                executorTag    = false,
            }
        }
    end,
    strict = function()
        return {
            minScore   = 1,
            background = true,
            interval   = 5.0,
            fingerprint= true,
            onDetect   = ShieldLite.handlers.warnAndFail,
            checks = {
                globals    = true,
                debugApis  = true,
                instanceMT = true,
                rawMTGame  = true,
                timingWarp = true,
                threadIdentity = true,
                genvMismatch   = true,
                executorTag    = true,
            }
        }
    end,
}

-- Returns a super-simple wrapper for beginners.
-- Usage:
--   local Shield = ShieldLite.easy("balanced")  -- or "low"/"strict"
--   Shield.protect(function() ... end)
function ShieldLite.easy(presetOrOpts)
    local opts
    if type(presetOrOpts) == "string" and PRESETS[presetOrOpts] then
        opts = PRESETS[presetOrOpts]()
    elseif type(presetOrOpts) == "table" then
        opts = presetOrOpts
    else
        opts = PRESETS.balanced()
    end

    local core = ShieldLite.new(opts)

    local api = {}
    -- Run a quick scan and then your function. If detection fails and handler throws, your function won't run.
    function api.protect(fn, ...)
        return core:guard(fn, ...)
    end

    -- Manual check you can print / branch on
    function api.check(tag)
        local r = core:scan(tag or "manual")
        print("[ShieldLite]", core:format(r))
        return r
    end

    -- Stop background scanning (if you need quiet)
    function api.stop()
        core:stopBackground()
    end

    -- For advanced users to access the full instance later if needed
    api._core = core

    return api
end

-- Backwards-compatible factory export
local function ShieldLiteFactory(opts)
    return ShieldLite.new(opts)
end

-- Expose both the advanced factory and the easy façade/presets
ShieldLite.presets = PRESETS
ShieldLite.factory = ShieldLiteFactory

return setmetatable({
    new      = ShieldLite.new,
    handlers = ShieldLite.handlers,
    presets  = ShieldLite.presets,
    easy     = ShieldLite.easy,
}, { __call = function(_, opts) return ShieldLiteFactory(opts) end })
