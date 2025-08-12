--// ShieldLite Tamper Kit (for local testing)
-- Runs a few classic shenanigans to bump ShieldLite's score above baseline.
-- Assumes you're in an executor with hookfunction/newcclosure/etc.

local Tamper = {}

-- 1) Make timingWarp angry by lying about wait() elapsed time
function Tamper.warpWait(returnValue)
    if not hookfunction or not task or not task.wait then return false, "no hookfunction" end
    local old = task.wait
    local hooked
    hooked = hookfunction(old, newcclosure(function(t)
        old(t) -- still yield to avoid weirdness
        return returnValue or 2.5 -- > 1.0 triggers timingWarp
    end))
    return true
end

-- 2) Flip the fingerprint check so :scan() gets "closure fingerprint mismatch"
function Tamper.breakFingerprint(shield)
    if not shield or not shield.fprint then return false, "no fingerprint" end
    -- swap the check to always lie
    shield.fprint.check = newcclosure(function() return false end)
    return true
end

-- 3) Light up the "exploit-only globals" bucket
function Tamper.addRedGlobals()
    -- pull real ones if your executor has them so it’s not a stub
    local g = getgenv and getgenv() or _G
    if getgc then g.getgc = getgc end
    if getrawmetatable then g.getrawmetatable = getrawmetatable end
    if hookmetamethod then g.hookmetamethod = hookmetamethod end
    if setnamecallmethod then g.setnamecallmethod = setnamecallmethod end
    if identifyexecutor then g.identifyexecutor = identifyexecutor end
    -- if your env already has them, this just ensures _G has references
    return true
end

-- 4) Light up debug.* signals (no stubs — only copy if they exist)
function Tamper.addDebugAPIs()
    if not debug then return false, "no debug table" end
    local function tryCopy(name, fn)
        if type(fn) == "function" then
            debug[name] = fn
        end
    end
    -- copy real executor funcs into debug table if they exist globally
    tryCopy("getupvalues", getupvalues)
    tryCopy("setupvalue", setupvalue)
    tryCopy("getconstants", getconstants)
    tryCopy("getproto", getproto)
    tryCopy("getprotos", getprotos)
    tryCopy("getregistry", getregistry)
    tryCopy("setmetatable", setmetatable) -- makes "debug.setmetatable present"
    tryCopy("getmetatable", getmetatable)
    return true
end

-- 5) Ensure getrawmetatable(game) success path is visible (usually already true in exploits)
function Tamper.ensureRawMTSignal()
    if not getrawmetatable then return false, "no getrawmetatable" end
    local ok, mt = pcall(getrawmetatable, game)
    -- nothing to *force* here; we just call it once so Shield sees it later too
    return ok and type(mt) == "table"
end

-- 6) Make genv mismatch more obvious (if you enabled that check)
function Tamper.makeGenvMismatch()
    if not getgenv then return false, "no getgenv" end
    local env = getgenv()
    -- move one flag into genv only; Shield’s check compares getgenv() vs _G
    rawset(env, "__tamper_gflag", true)
    return env ~= _G
end

-- 7) One-shot: do a “noisy” tamper that should definitely cross BASELINE+1
function Tamper.noisyAll(shield)
    Tamper.addRedGlobals()
    Tamper.addDebugAPIs()
    Tamper.ensureRawMTSignal()
    Tamper.warpWait(2.2)
    Tamper.breakFingerprint(shield)
    Tamper.makeGenvMismatch()
end

return Tamper
