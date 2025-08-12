--[[
Don't steal! If u want modernizate, modernizate. But if you want to post it, then mention me as the original author!
-]]

local global = (getgenv and getgenv()) or _G

-- one shared registry of messages we colored, keyed by our tag
local _colorprint_registry = _colorprint_registry or {}
local _colorprint_watcher_started = _colorprint_watcher_started or false

-- unique token markers so we can reliably find & strip them later
local TOKEN_PREFIX = "§CP:"
local TOKEN_SUFFIX = ":PC§"

-- safely get the Dev Console ClientLog (nil until console is built)
local function getClientLog()
    local coreGui = game:GetService("CoreGui")
    local master = coreGui:FindFirstChild("DevConsoleMaster")
    if not master then return nil end
    local window = master:FindFirstChild("DevConsoleWindow")
    if not window then return nil end
    local ui = window:FindFirstChild("DevConsoleUI")
    if not ui then return nil end
    local main = ui:FindFirstChild("MainView")
    if not main then return nil end
    local clientLog = main:FindFirstChild("ClientLog")
    return clientLog
end

-- apply colors/icons to any rows carrying our token
local function processClientLog()
    local clientLog = getClientLog()
    if not clientLog then return end

    for _, entry in pairs(clientLog:GetChildren()) do
        -- skip if already processed
        if entry:GetAttribute("cp_processed") then
            continue
        end

        local msgLabel = entry:FindFirstChild("msg")
        if not msgLabel or typeof(msgLabel.Text) ~= "string" then
            continue
        end

        local text = msgLabel.Text
        local tag = text:match(TOKEN_PREFIX .. "(%d+)" .. TOKEN_SUFFIX)
        if tag then
            local info = _colorprint_registry[tag]
            -- remove tag from visible text
            msgLabel.Text = text:gsub(TOKEN_PREFIX .. tag .. TOKEN_SUFFIX, "")

            if info then
                -- color text
                if info.colorText and info.textColor then
                    msgLabel.TextColor3 = info.textColor
                end
                -- icon
                local img = entry:FindFirstChild("image")
                if img and info.showIcon and info.selectedIcon then
                    img.Image = info.selectedIcon
                    if info.colorIcon and info.iconColor then
                        img.ImageColor3 = info.iconColor
                    end
                end
            end

            entry:SetAttribute("cp_processed", true)
        end
    end
end

-- a persistent watcher that re-applies formatting whenever the console exists/rebuilds
local function startWatcher()
    if _colorprint_watcher_started then return end
    _colorprint_watcher_started = true

    task.spawn(function()
        -- light polling + event hooks when possible
        while true do
            -- try each ~0.2s; cheap enough and resilient to rebuilds
            pcall(processClientLog)
            task.wait(0.2)

            -- if we have a live ClientLog, also hook into new children for faster reaction
            local clientLog = getClientLog()
            if clientLog and not clientLog:GetAttribute("cp_hooked") then
                clientLog:SetAttribute("cp_hooked", true)
                clientLog.ChildAdded:Connect(function()
                    -- slight delay so the row is fully populated
                    task.wait()
                    pcall(processClientLog)
                end)
            end
        end
    end)
end

global.colorprint = function(message, iconType, textColor)
    local message = message or "" -- text to print
    local textColor, colorText = textColor or Color3.fromRGB(255, 255, 255), true
    local iconColor, colorIcon = Color3.fromRGB(0, 0, 0), false
    local iconType, showIcon = iconType or "info", iconType ~= nil

    -- unique tag we will append to the printed text so we can find it later
    local tag = tostring(math.random(1, 1e9))
    local token = TOKEN_PREFIX .. tag .. TOKEN_SUFFIX

    -- map icon type to asset
    local iconPaths = {
        info    = "rbxasset://textures/DevConsole/Info.png",
        warn    = "rbxasset://textures/DevConsole/Warning.png",
        error   = "rbxasset://textures/DevConsole/Error.png",
        success = "rbxasset://textures/Tutorials/Tick.png",
    }

    local selectedIcon = iconPaths[(tostring(iconType)):lower()] or iconType
    if not selectedIcon:find("^rbxasset://") then
        selectedIcon = "rbxasset://" .. selectedIcon
    end
    if not (selectedIcon:find("%.png$") or selectedIcon:find("%.jpe?g$")) then
        selectedIcon = selectedIcon .. ".png"
    end

    -- remember how to restyle this print if/when the console rebuilds
    _colorprint_registry[tag] = {
        textColor = textColor,
        colorText = colorText,
        iconColor = iconColor,
        colorIcon = colorIcon,
        showIcon = showIcon,
        selectedIcon = selectedIcon,
    }

    -- actually print (include our hidden token so we can find the row later)
    print(message .. " " .. token)

    -- start/ensure the watcher is running
    startWatcher()
end

-- example:
-- colorprint("This looks like an error", "error", Color3.fromRGB(255, 0, 0))
