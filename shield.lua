-- ShieldLite v1 — simple, scoped anti‑tamper (Roblox-safe)
-- No global patching, no metatable writes, no RenderStepped hooks.

local RunService = game:GetService("RunService")
local Players    = game:GetService("Players")
local Http       = game:GetService("HttpService")

local function now() return os.clock() end
local function guid() return Http:GenerateGUID(false) end

local DEFAULT_OPTS = {
	onDetect    = nil,         -- function(event, score, reasons) -> nil
	minScore    = 1,           -- how many findings before we act
	background  = true,        -- keep scanning every few seconds (task.defer, not every frame)
	interval    = 6.0,         -- seconds between background scans
	fingerprint = true,        -- create a closure fingerprint & verify it stays the same
}

-- List of “red flag” globals typically only present in exploit envs
local RED_GLOBALS = {
	"getgc","getreg","getgenv","getrenv","getsenv","getinstances","getloadedmodules",
	"newcclosure","clonefunction","hookmetamethod","setreadonly","make_writeable","makewritable",
	"getrawmetatable","setnamecallmethod","getnamecallmethod","checkcaller",
}

-- Debug APIs Roblox doesn’t normally expose to LuaU user scripts.
local RED_DEBUG = {
	"getupvalue","getupvalues","setupvalue","getconstant","getconstants",
	"getproto","getprotos","getlocal","setlocal","sethook","gethook","getregistry",
	"setmetatable","getmetatable","getuservalue","setuservalue",
}

local function safepcall(f, ...)
	local ok, a = pcall(f, ...)
	return ok, a
end

local function has(tbl, key)
	local ok, v = safepcall(function() return tbl[key] end)
	return ok and v ~= nil, v
end

local function append(t, s) t[#t+1] = s end

local function scanOnce(contextTag)
	local score, reasons = 0, {}

	-- 1) Exploit-only globals
	for _, k in ipairs(RED_GLOBALS) do
		if rawget(_G, k) ~= nil then
			score += 1; append(reasons, ("global '%s' present"):format(k))
		end
	end

	-- 2) Suspicious debug members
	if debug then
		for _, k in ipairs(RED_DEBUG) do
			if rawget(debug, k) ~= nil then
				score += 1; append(reasons, ("debug.%s present"):format(k))
			end
		end
	end

	-- 3) Instances should not expose metatables to Luau
	do
		local ok, mt = safepcall(getmetatable, game)
		if ok and type(mt) == "table" then
			score += 1; append(reasons, "Instance metatable unexpectedly visible")
		end
	end

	-- 4) getrawmetatable(game) should be inaccessible in vanilla Luau
	do
		if rawget(_G, "getrawmetatable") then
			local ok, mt = safepcall(getrawmetatable, game)
			if ok and type(mt) == "table" then
				score += 1; append(reasons, "getrawmetatable(game) succeeded")
			end
		end
	end

	-- 5) sanity timing — extreme time warps
	do
		local t0 = now()
		task.wait(0.01) -- tiny yield; harmless
		local dt = now() - t0
		if dt < 0 or dt > 1.0 then
			score += 1; append(reasons, ("weird wait dt=%.3f"):format(dt))
		end
	end

	return score, reasons, contextTag
end

local function makeFingerprint()
	-- Lock some state into a closure; if an attacker swaps our function, the hash changes.
	local secret, salt = guid(), math.random(1e6, 9e6)
	local function token(x) return string.pack(">I4", bit32.bxor(#secret + salt, x or 0)) end
	return {
		secret = secret,
		check = function()
			local a = token(12345)
			local b = token(12345)
			return a == b -- true unless closure/upvalues were swapped
		end
	}
end

local ShieldLite = {}
ShieldLite.__index = ShieldLite

function ShieldLite.new(opts)
	opts = table.freeze and table.freeze(setmetatable(opts or {}, {__index = DEFAULT_OPTS})) or setmetatable(opts or {}, {__index = DEFAULT_OPTS})
	local self = setmetatable({
		opts     = opts,
		fprint   = opts.fingerprint and makeFingerprint() or nil,
		_running = false,
	}, ShieldLite)
	return self
end

function ShieldLite:_handleDetect(event, score, reasons)
	if self.opts.onDetect then
		self.opts.onDetect(event, score, reasons)
	else
		-- default behavior: hard error to stop the script
		error(("[ShieldLite] %s (score=%d)\n- %s"):format(event, score, table.concat(reasons, "\n- ")), 0)
	end
end

function ShieldLite:scan(tag)
	local score, reasons = scanOnce(tag or "scan")
	if self.fprint and not self.fprint.check() then
		score += 1; append(reasons, "closure fingerprint mismatch")
	end
	if score >= self.opts.minScore then
		self:_handleDetect(tag or "scan", score, reasons)
	end
	return score, reasons
end

function ShieldLite:startBackground()
	if self._running or not self.opts.background then return end
	self._running = true
	task.defer(function()
		while self._running do
			local ok, err = pcall(function()
				self:scan("background")
			end)
			if not ok then
				-- If onDetect raised, we stop; otherwise, keep going.
				self._running = false
				break
			end
			task.wait(self.opts.interval)
		end
	end)
end

function ShieldLite:stopBackground()
	self._running = false
end

-- Guard runs your sensitive function after a pre‑scan.
function ShieldLite:guard(fn, ...)
	assert(type(fn) == "function", "ShieldLite:guard expects a function")
	self:scan("pre")
	return fn(...)
end

-- Helper: single‑shot convenience
local function ShieldLiteFactory(opts)
	return ShieldLite.new(opts)
end

return ShieldLiteFactory
