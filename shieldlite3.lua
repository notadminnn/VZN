-- ShieldLite v3.0 (advanced anti-tamper with enhanced checks, multi-fingerprint, hook detection, and custom severity)
-- Fixed version: Applied all audit fixes including syntax corrections, undefined functions, tautological logic, baseline poisoning prevention,
-- onDetect protection, behavioral checks, timing averaging, string split impl, serviceMock logic, local captures, background race fix.
-- Additional fixes for new vulnerabilities: ephemeral fingerprints (detector-only), multi-sample baseline, safepcall behavioral calls,
-- coroutine onDetect, safepcall getfenv, orig GetService capture, statistical timing, simple hash for token, escaped split, self-integrity check,
-- GUID fallback.
-- IMPORTANT: Treat fingerprints as detector-only, not secrets/capabilities. DO NOT rely on them for security-critical decisions.
-- TODO: Implement server-verify ephemeral attestation for critical actions. Never grant trust based solely on client checks.

local Http = game:GetService("HttpService")
local RunService = game:GetService("RunService")
local function now() return os.clock() end
local function guid_safe()
    local ok, g = pcall(Http.GenerateGUID, Http, false)
    if ok and g then return g end
    return tostring(os.time()) .. "-" .. tostring(math.random(1, 1e9))
end
local function safepcall(f, ...) local ok,a,b,c,d = pcall(f, ...); return ok,a,b,c,d end
local function append(t, s) t[#t+1] = s end

-- Capture critical builtins locally for resilience against _G tampering
local rawget_local = rawget
local rawset_local = rawset  -- If needed later
local type_local = type
local tostring_local = tostring
local math_local = math
local table_local = table
local string_local = string
local debug_local = debug
local task_local = task
local os_local = os

-- Capture original GetService for serviceMock integrity
local _origGetService = game.GetService

-- Helper for string split (fixes missing split in Luau, with escape for special seps)
local function escapePattern(s)
    return s:gsub("([^%w])", "%%%1")
end
local function split(str, sep)
    sep = escapePattern(sep or "%s")
    local t = {}
    for s in string_local.gmatch(str, "([^"..sep.."]+)") do append(t, s) end
    return t
end

local DEFAULT_OPTS = {
    onDetect      = nil,   -- REQUIRED by caller
    minScore      = 1,
    background    = true,
    interval      = 5.0,   -- Slightly faster default
    fingerprint   = true,
    multiFprint   = true,  -- NEW: Use multiple fingerprints for robustness
    autoBaseline  = true,
    autoBaselineSamples = 5,  -- NEW: Number of baseline samples for median
    baselineDelta = 1,
    baselineFloor = 2,  -- Hardcoded floor
    severity      = {      -- NEW: Per-check severity weights (default 1)
        globals       = 1,
        debugApis     = 1,
        instanceMT    = 1,
        rawMTGame     = 1,
        timingWarp    = 1,
        threadIdentity= 1,
        genvMismatch  = 1,
        executorTag   = 1,
        cryptApis     = 1,  -- NEW
        hookDetect    = 1,  -- NEW
        serviceMock   = 1,  -- NEW
        stackAnomaly  = 1,  -- NEW
        envIntegrity  = 1,  -- NEW
        selfIntegrity  = 1,  -- NEW: For module self-check
    },
    checks = {
        globals       = true,
        debugApis     = true,
        instanceMT    = true,
        rawMTGame     = true,
        timingWarp    = true,
        threadIdentity= false,
        genvMismatch  = false,
        executorTag   = false,
        cryptApis     = true,  -- NEW: Check for exploit-specific crypt APIs
        hookDetect    = true,  -- NEW: Basic hook detection on built-ins
        serviceMock   = true,  -- NEW: Verify core services
        stackAnomaly  = true,  -- NEW: Analyze traceback for anomalies
        envIntegrity  = true,  -- NEW: Deeper environment mismatch checks
        selfIntegrity = true,  -- NEW: Basic self-integrity check
    },
    detectDebounce = 0.4,  -- Slightly lower debounce
    logging       = false, -- NEW: Optional console logging
}

local RED_GLOBALS = {
    "getgc","getreg","getgenv","getrenv","getsenv","getinstances","getloadedmodules",
    "newcclosure","clonefunction","hookmetamethod","setreadonly","make_writeable","makewritable",
    "getrawmetatable","setnamecallmethod","getnamecallmethod","checkcaller",
    "firesignal","getconnections","gethui","getnilinstances","getscripts","getmodules",
}

local RED_DEBUG = {
    "getupvalue","getupvalues","setupvalue","getconstant","getconstants",
    "getproto","getprotos","getlocal","setlocal","sethook","gethook","getregistry",
    "setmetatable","getmetatable","getuservalue","setuservalue","islclosure","isclosure",
    "dumpstring","decompile",
}

local RED_CRYPT = {  -- NEW: Exploit-specific crypt functions
    "crypt", "base64encode", "base64decode", "hash", "encrypt", "decrypt",
}

local CORE_SERVICES = {  -- NEW: Expected core services
    "Workspace", "Players", "Lighting", "ReplicatedStorage", "ServerStorage",
    "ServerScriptService", "StarterGui", "StarterPack", "StarterPlayer",
    "SoundService", "Chat", "HttpService", "RunService", "UserInputService",
}

-- Simple stable hash for token generation (replaces custom XOR for predictability)
local function simple_hash(s)
    local h = 2166136261
    for i=1,#s do
        h = (h ~ string.byte(s, i)) * 16777619
        h = h & 0xFFFFFFFF
    end
    return tostring(h)
end

-- Ephemeral fingerprints (detector-only; bound to TTL, not persistent secrets)
local function makeMultiFingerprint(count, ttlSeconds)
    local fps = {}
    for i = 1, (count or 3) do
        local created = os.time()
        local salt = math_local.random(1e6, 9e6) + i
        local token_val = simple_hash(tostring_local(created) .. tostring_local(salt))
        fps[i] = {
            check = function()
                return (os_local.time() - created) < (ttlSeconds or 300) and  -- 5 min TTL
                       simple_hash(tostring_local(created) .. tostring_local(salt)) == token_val
            end,
            meta = { created = created }  -- For telemetry only; do not trust
        }
    end
    return fps
end

local function makeFingerprint(ttlSeconds)
    return makeMultiFingerprint(1, ttlSeconds)[1]
end

local function scanOnce(tag, checks, severity)
    local score, reasons = 0, {}

    if checks.selfIntegrity then  -- NEW: Basic self-integrity check (best-effort)
        if type_local(string.dump) == "function" then
            local ok_dump, d = safepcall(string.dump, ShieldLite.new)
            if not ok_dump or not d or #d < 10 then
                score = score + (severity.selfIntegrity or 1)
                append(reasons, "self-check failed (string.dump on ShieldLite.new)")
            end
        end
    end

    if checks.globals then
        for _, k in ipairs(RED_GLOBALS) do
            if rawget_local(_G, k) ~= nil then
                score = score + (severity.globals or 1); append(reasons, ("global '%s' present"):format(k))
            end
        end
        -- Behavioral supplement for key functions (e.g., getgc)
        local testGc = rawget_local(_G, "getgc") or (function() return {} end)  -- Mock if hidden
        local ok_gc, gcRes = safepcall(testGc)
        if ok_gc and type_local(gcRes) == "table" and #gcRes > 0 then
            score = score + (severity.globals or 1); append(reasons, "getgc-like behavior detected")
        elseif not ok_gc then
            score = score + 0.5; append(reasons, "getgc call errored (suspicious)")
        end
    end
    if checks.debugApis and debug_local then
        for _, k in ipairs(RED_DEBUG) do
            if rawget_local(debug_local, k) ~= nil then
                score = score + (severity.debugApis or 1); append(reasons, ("debug.%s present"):format(k))
            end
        end
    end
    if checks.instanceMT then
        local ok_mt, mt = safepcall(getmetatable, game)
        if ok_mt and type_local(mt) == "table" then
            score = score + (severity.instanceMT or 1); append(reasons, "Instance metatable unexpectedly visible")
        end
    end
    if checks.rawMTGame then
        local grm = rawget_local(_G, "getrawmetatable")
        if grm then
            local ok_grm, mt2 = safepcall(grm, game)
            if ok_grm and type_local(mt2) == "table" then
                score = score + (severity.rawMTGame or 1); append(reasons, "getrawmetatable(game) succeeded")
            end
        end
    end
    if checks.timingWarp then
        local dts = {}
        for _ = 1, 5 do
            local t0 = now()
            RunService.Heartbeat:Wait()  -- More precise timing using RunService
            append(dts, now() - t0)
        end
        local bad = 0
        for _, d in ipairs(dts) do if d > 0.12 or d < 0 then bad = bad + 1 end end
        if bad >= 3 then
            score = score + (severity.timingWarp or 1); append(reasons, ("weird heartbeat samples=%d"):format(bad))
        end
    end
    if checks.threadIdentity then
        local gettid = rawget_local(_G, "getthreadidentity") or rawget_local(_G, "getidentity")
        if type_local(gettid) == "function" then
            local a_ok, a = safepcall(gettid); task_local.wait(0.01); local b_ok, b = safepcall(gettid)
            if a_ok and b_ok and a ~= b then
                score = score + (severity.threadIdentity or 1); append(reasons, ("thread identity changed (%s -> %s)"):format(tostring_local(a), tostring_local(b)))
            end
        end
    end
    if checks.genvMismatch then
        local ggv = rawget_local(_G, "getgenv")
        if type_local(ggv) == "function" then
            local ok, env = safepcall(ggv)
            if ok and env and env ~= _G then
                score = score + (severity.genvMismatch or 1); append(reasons, "getgenv() differs from _G")
            end
        end
    end
    if checks.executorTag then
        local idexec = rawget_local(_G, "identifyexecutor") or rawget_local(_G, "getexecutorname")
        if type_local(idexec) == "function" then
            local ok, name = safepcall(idexec)
            if ok and name and type_local(name) == "string" and name:lower():match("synapse|krnl|fluxus|electron|solara") then
                score = score + (severity.executorTag or 1) * 2;  -- Higher severity for known executors
                append(reasons, ("executor identified as '%s'"):format(name))
            elseif ok then
                score = score + (severity.executorTag or 1); append(reasons, "identifyexecutor() available")
            end
        end
    end
    if checks.cryptApis then  -- NEW
        local crypt = rawget_local(_G, "crypt") or {}
        for _, k in ipairs(RED_CRYPT) do
            if rawget_local(_G, k) or rawget_local(crypt, k) then
                score = score + (severity.cryptApis or 1); append(reasons, ("crypt api '%s' present"):format(k))
            end
        end
    end
    if checks.hookDetect then  -- NEW: Basic hook detection on a built-in
        local originalWait = task_local.wait
        local testHook = function() return originalWait(0.01) end
        local t0 = now()
        testHook()
        local dt = now() - t0
        if dt > 0.05 then  -- If hooked, might delay
            score = score + (severity.hookDetect or 1); append(reasons, "potential hook on task.wait (delayed)")
        end
        -- Check if wait behaves oddly
        local ok, err = safepcall(function() task_local.wait(-1) end)
        if ok then
            score = score + (severity.hookDetect or 1); append(reasons, "task.wait accepted negative time (hooked?)")
        end
    end
    if checks.serviceMock then  -- NEW: Verify core services with original GetService
        for _, svc in ipairs(CORE_SERVICES) do
            local ok_svc, inst = safepcall(_origGetService, game, svc)
            if not ok_svc or not inst or (type_local(inst) ~= "userdata" and type_local(inst) ~= "table") then
                score = score + (severity.serviceMock or 1); append(reasons, ("service '%s' mocked or invalid"):format(svc))
            end
        end
    end
    if checks.stackAnomaly then  -- NEW: Analyze traceback
        local tb = debug_local.traceback()
        if type_local(tb) == "string" and (tb:match("exploit") or not tb:match("Script '") or #split(tb, "\n") < 3) then
            score = score + (severity.stackAnomaly or 1); append(reasons, "anomalous stack trace")
        end
    end
    if checks.envIntegrity then  -- NEW: Deeper env checks
        local getfenvFn = getfenv or debug_local.getfenv
        if getfenvFn then
            local ok0, env0 = safepcall(getfenvFn, 0)
            local ok1, env1 = safepcall(getfenvFn, 1)
            if ok0 and ok1 and env0 ~= env1 or env0 ~= _G then
                score = score + (severity.envIntegrity or 1); append(reasons, "environment levels mismatch")
            elseif not ok0 or not ok1 then
                -- Informational; skip adding score to avoid FP
            end
        end
    end

    return score, reasons, tag
end

local ShieldLite = {}
ShieldLite.__index = ShieldLite

setmetatable(ShieldLite, { __call = function(_, opts) return ShieldLite.new(opts) end })

local function makeResult(tag, score, reasons, passed)
    return { tag = tag or "scan", score = score or 0, reasons = reasons or {}, passed = passed, timestamp = os_local.clock() }
end

function ShieldLite.new(opts)
    local merged = setmetatable(opts or {}, { __index = DEFAULT_OPTS })
    merged.checks = setmetatable(merged.checks or {}, { __index = DEFAULT_OPTS.checks })
    merged.severity = setmetatable(merged.severity or {}, { __index = DEFAULT_OPTS.severity })
    assert(type_local(merged.onDetect) == "function", "ShieldLite: onDetect function is required")

    local self = setmetatable({
        opts         = merged,
        fprints      = (merged.fingerprint and merged.multiFprint and makeMultiFingerprint(3)) or (merged.fingerprint and {makeFingerprint()}) or nil,
        _running     = false,
        _lastDetect  = 0,
        _detected    = false,
        _bootstrapping = false,
        baseline     = nil,
    }, ShieldLite)

    -- Auto-baseline with multi-sample median (resists transient poisoning)
    if self.opts.autoBaseline then
        self._bootstrapping = true
        local samples = {}
        local num_samples = math_local.max(3, math_local.floor(merged.autoBaselineSamples or 5))
        for i=1, num_samples do
            local s, r = scanOnce("baseline-sample", self.opts.checks, self.opts.severity)
            append(samples, s)
            task_local.wait(0.1)
        end
        table_local.sort(samples)
        local median = samples[math_local.ceil(#samples / 2)]
        if self.fprints then
            for i, fp in ipairs(self.fprints) do
                if not fp.check() then
                    median = median + (self.opts.severity.fingerprint or 1)  -- Add but not to baseline poisoning
                end
            end
        end
        local delta = tonumber(self.opts.baselineDelta) or 1
        local floor = tonumber(self.opts.baselineFloor) or 2
        self.opts.minScore = math_local.max(floor, median + delta)
        self._bootstrapping = false
    end

    -- Start background after baseline to avoid races
    if self.opts.background then
        task_local.defer(function() self:startBackground() end)
    end

    return self
end

function ShieldLite:_canFireDetect()
    if self._detected or self._bootstrapping then return false end
    local t = now()
    if (t - (self._lastDetect or 0)) >= (self.opts.detectDebounce or 0) then
        self._lastDetect = t
        return true
    end
    return false
end

function ShieldLite:scan(tag)
    if self._detected or self._bootstrapping then
        return makeResult(tag or "scan", 0, {}, false)
    end

    local score, reasons = scanOnce(tag or "scan", self.opts.checks, self.opts.severity)
    if self.fprints then
        for i, fp in ipairs(self.fprints) do
            if not fp.check() then
                score = score + (self.opts.severity.fingerprint or 1); append(reasons, ("fingerprint #%d mismatch"):format(i))
            end
        end
    end

    local passed = (score < (self.opts.minScore or 1))
    local result = makeResult(tag or "scan", score, reasons, passed)

    if self.opts.logging then
        print(self:format(result))
    end

    if not passed and self:_canFireDetect() then
        self._detected = true
        self:stopBackground()
        -- Protected onDetect in coroutine (basic watchdog; no full timer due to platform)
        local ok_co = safepcall(function()
            local co = coroutine.create(function()
                self.opts.onDetect(result.tag, result.score, result.reasons, result)
            end)
            coroutine.resume(co)
            -- No advanced watchdog; assume short-lived
        end)
        if not ok_co then
            warn("onDetect failed; potential tamper")
        end
    end
    return result
end

function ShieldLite:startBackground()
    if self._running or not self.opts.background then return end
    self._running = true
    task_local.defer(function()
        while self._running and not self._detected do
            pcall(function() self:scan("background") end)
            task_local.wait(self.opts.interval or 5.0)
        end
    end)
end

function ShieldLite:stopBackground() self._running = false end

function ShieldLite:guard(fn, ...)
    assert(type_local(fn) == "function", "ShieldLite:guard expects a function")
    if self._detected or self._bootstrapping then return end
    self:scan("pre")
    if not self._detected then return fn(...) end
end

function ShieldLite:withGuard(fn) return self:guard(fn) end

function ShieldLite:format(result)
    result = result or { score = 0, reasons = {}, tag = "scan", passed = true }
    local head = ("[%s] score=%d passed=%s"):format(result.tag, result.score, tostring_local(result.passed))
    if #result.reasons == 0 then return head .. " (no reasons)" end
    return head .. "\n- " .. table_local.concat(result.reasons, "\n- ")
end

return ShieldLite
