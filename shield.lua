--// Services
local Http = game:GetService("HttpService")

--// Helpers
local function now() return os.clock() end
local function guid() return Http:GenerateGUID(false) end
local function safepcall(f, ...) local ok,a,b,c,d = pcall(f, ...); return ok,a,b,c,d end
local function append(t, s) t[#t+1] = s end

-- Default options
local DEFAULT_OPTS = {
    onDetect    = nil,   -- REQUIRED: function(event, score, reasons, result)
    minScore    = 1,
    background  = true,
    interval    = 6.0,
    fingerprint = true,
    checks = {
        globals       = true,
        debugApis     = true,
        instanceMT    = true,
        rawMTGame     = true,
        timingWarp    = true,
        threadIdentity= false,
        genvMismatch  = false,
        executorTag   = false,
    },
    detectDebounce = 0.5,
}

local RED_GLOBALS = {
    "getgc","getreg","getgenv","getrenv","getsenv","getinstances","getloadedmodules",
    "newcclosure","clonefunction","hookmetamethod","setreadonly","make_writeable","makewritable",
    "getrawmetatable","setnamecallmethod","getnamecallmethod","checkcaller",
}

local RED_DEBUG = {
    "getupvalue","getupvalues","setupvalue","getconstant","getconstants",
    "getproto","getprotos","getlocal","setlocal","sethook","gethook","getregistry",
    "setmetatable","getmetatable","getuservalue","setuservalue",
}

-- Fingerprint check
local function makeFingerprint()
    local secret, salt = guid(), math.random(1e6, 9e6)
    local function token(x)
        local bx = (bit32 and bit32.bxor or function(a,b)
            local r,bit=0,1; while a>0 or b>0 do
                local aa=a%2; local bb=b%2
                if (aa+bb)==1 then r=r+bit end
                a=(a-aa)/2; b=(b-bb)/2; bit=bit*2
            end; return r
        end)(#secret + salt, x or 0)
        return tostring(bx)
    end
    return {
        secret = secret,
        check = function()
            return token(12345) == token(12345)
        end
    }
end

-- Scan function
local function scanOnce(tag, checks)
    local score, reasons = 0, {}

    if checks.globals then
        for _, k in ipairs(RED_GLOBALS) do
            if rawget(_G, k) ~= nil then
                score += 1; append(reasons, ("global '%s' present"):format(k))
            end
        end
    end

    if checks.debugApis and debug then
        for _, k in ipairs(RED_DEBUG) do
            if rawget(debug, k) ~= nil then
                score += 1; append(reasons, ("debug.%s present"):format(k))
            end
        end
    end

    if checks.instanceMT then
        local ok_mt, mt = safepcall(getmetatable, game)
        if ok_mt and type(mt) == "table" then
            score += 1; append(reasons, "Instance metatable unexpectedly visible")
        end
    end

    if checks.rawMTGame then
        local grm = rawget(_G, "getrawmetatable")
        if grm then
            local ok_grm, mt2 = safepcall(grm, game)
            if ok_grm and type(mt2) == "table" then
                score += 1; append(reasons, "getrawmetatable(game) succeeded")
            end
        end
    end

    if checks.timingWarp then
        local t0 = now()
        task.wait(0.01)
        local dt = now() - t0
        if dt < 0 or dt > 1.0 then
            score += 1; append(reasons, ("weird wait dt=%.3f"):format(dt))
        end
    end

    if checks.threadIdentity then
        local gettid = rawget(_G, "getthreadidentity") or rawget(_G, "getidentity")
        if type(gettid) == "function" then
            local a_ok, a = safepcall(gettid)
            task.wait()
            local b_ok, b = safepcall(gettid)
            if a_ok and b_ok and a ~= b then
                score += 1; append(reasons, ("thread identity changed (%s -> %s)"):format(tostring(a), tostring(b)))
            end
        end
    end

    if checks.genvMismatch then
        local ggv = rawget(_G, "getgenv")
        if type(ggv) == "function" then
            local ok, env = safepcall(ggv)
            if ok and env and env ~= _G then
                score += 1; append(reasons, "getgenv() differs from _G")
            end
        end
    end

    if checks.executorTag then
        if type(rawget(_G, "identifyexecutor")) == "function" then
            score += 1; append(reasons, "identifyexecutor() available")
        end
    end

    return score, reasons, tag
end

-- Class
local ShieldLite = {}
ShieldLite.__index = ShieldLite

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
        passed = passed,
        timestamp = os.clock(),
    }
end

function ShieldLite.new(opts)
    local merged = setmetatable(opts or {}, { __index = DEFAULT_OPTS })
    merged.checks = setmetatable(merged.checks or {}, { __index = DEFAULT_OPTS.checks })
    assert(type(merged.onDetect) == "function", "ShieldLite: onDetect function is required")

    local self = setmetatable({
        opts        = merged,
        fprint      = (merged.fingerprint and makeFingerprint()) or nil,
        _running    = false,
        _lastDetect = 0,
        _detected   = false,
    }, ShieldLite)

    if self.opts.background then
        task.defer(function()
            self:startBackground()
        end)
    end

    return self
end

function ShieldLite:_canFireDetect()
    if self._detected then return false end
    local t = now()
    if (t - (self._lastDetect or 0)) >= (self.opts.detectDebounce or 0) then
        self._lastDetect = t
        return true
    end
    return false
end

function ShieldLite:scan(tag)
    if self._detected then return makeResult(tag, 0, {}, false) end

    local score, reasons = scanOnce(tag or "scan", self.opts.checks)
    if self.fprint and not self.fprint.check() then
        score += 1; append(reasons, "closure fingerprint mismatch")
    end

    local passed = (score < (self.opts.minScore or 1))
    local result = makeResult(tag, score, reasons, passed)

    if not passed and self:_canFireDetect() then
        self._detected = true
        self:stopBackground()
        self.opts.onDetect(result.tag, result.score, result.reasons, result)
    end

    return result
end

function ShieldLite:startBackground()
    if self._running or not self.opts.background then return end
    self._running = true
    task.defer(function()
        while self._running and not self._detected do
            pcall(function()
                self:scan("background")
            end)
            task.wait(self.opts.interval or 6.0)
        end
    end)
end

function ShieldLite:stopBackground()
    self._running = false
end

function ShieldLite:guard(fn, ...)
    assert(type(fn) == "function", "ShieldLite:guard expects a function")
    if self._detected then return end
    local _ = self:scan("pre")
    if not self._detected then
        return fn(...)
    end
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

return ShieldLite
