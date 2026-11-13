-- Copyright 2026 cuihairu <chuihairu@gmail.com>
-- SPDX-License-Identifier: Apache-2.0

module("luci.controller.meshlet", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/meshlet") then
		return
	end

	entry({"admin", "services", "meshlet"},
		cbi("meshlet"),
		_("Meshlet 组网"), 60).dependent = true

	entry({"admin", "services", "meshlet", "status"},
		template("meshlet/status"),
		_("运行状态"), 10).leaf = true

	-- Internal JSON endpoint backing the status page. Not a menu entry.
	entry({"admin", "services", "meshlet", "api", "status"},
		call("api_status")).leaf = true
end

-- Strip control characters and cap the length (same policy as the custos
-- precedent: log-derived text must not flood rows or the response).
local function sanitize(value, max)
	if value == nil then
		return ""
	end
	local s = tostring(value):gsub("%c", "")
	if #s > max then
		s = s:sub(1, max) .. "…"
	end
	return s
end

local function shell_quote(s)
	return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

-- procd state via the rc.common wrapper (exit 0 = running).
local function service_state(name)
	local code = luci.sys.call("/etc/init.d/" .. name .. " status >/dev/null 2>&1")
	return (code == 0) and "running" or "stopped"
end

function api_status()
	luci.http.prepare_content("application/json")
	local uci = require("luci.model.uci").cursor()
	local utl = require("luci.util")

	local out = {
		server = { status = service_state("meshlet-server") },
		agent = { status = service_state("meshlet-agent") },
	}

	local bind = uci:get("meshlet", "server", "bind") or "127.0.0.1:8080"
	out.server.bind = bind
	out.server.dataplane = uci:get("meshlet", "server", "dataplane") or "0"

	-- Recent meshlet syslog lines (both procd services log with the
	-- meshlet-* tags; init scripts log with the same). Tail 25, sanitized.
	out.logs = {}
	local logs_raw = utl.exec("logread -e meshlet 2>/dev/null | tail -n 25")
	if logs_raw and logs_raw ~= "" then
		for line in logs_raw:gmatch("[^\r\n]+") do
			out.logs[#out.logs + 1] = sanitize(line, 200)
		end
	end

	-- Optional read-scope API token (uci server.api_token). Only ever
	-- returned masked; the full token never leaves the router.
	local token = uci:get("meshlet", "server", "api_token") or ""
	if token == "" then
		out.token_hint = "未配置 API token（在设置页 server 段填写 read scope token 后可看设备在线）"
		luci.http.write_json(out)
		return
	end
	out.token_masked = token:sub(1, 4) .. "…" .. token:sub(-4)

	-- http:// prefix: the bind is host:port (TLS terminates at a reverse
	-- proxy in front of the hub, never here on the loopback hop).
	local base = "http://" .. bind
	local hdr = "-H " .. shell_quote("Authorization: Bearer " .. token)

	local function fetch_json(cmd)
		local raw = utl.exec(cmd)
		if raw == nil or raw == "" then
			return nil, "命令无输出"
		end
		local parsed = require("luci.jsonc").parse(raw)
		if parsed == nil then
			return nil, "JSON 解析失败"
		end
		return parsed, nil
	end

	local networks, err = fetch_json(
		"curl -s --max-time 5 " .. hdr .. " " .. shell_quote(base .. "/api/v1/networks") .. " 2>/dev/null")
	if err then
		out.error = "networks: " .. err
	else
		out.networks = {}
		for _, n in ipairs(networks or {}) do
			local row = {
				id = sanitize(n.id, 64),
				name = sanitize(n.name, 64),
				overlay_cidr = sanitize(n.overlay_cidr, 24),
			}
			local devices, derr = fetch_json("curl -s --max-time 5 " .. hdr .. " " ..
				shell_quote(base .. "/api/v1/networks/" .. tostring(n.id) .. "/devices") .. " 2>/dev/null")
			if derr then
				out.error = out.error or ("devices: " .. derr)
				row.total = 0
				row.online = 0
			else
				row.total = #devices
				row.online = 0
				row.devices = {}
				for _, d in ipairs(devices or {}) do
					if d.online_state == "online" then
						row.online = row.online + 1
					end
					row.devices[#row.devices + 1] = {
						name = sanitize(d.name, 48),
						virtual_ipv4 = sanitize(d.virtual_ipv4, 20),
						online_state = sanitize(d.online_state, 16),
						last_seen = d.last_seen_at,
					}
				end
			end
			out.networks[#out.networks + 1] = row
		end
	end

	luci.http.write_json(out)
end
