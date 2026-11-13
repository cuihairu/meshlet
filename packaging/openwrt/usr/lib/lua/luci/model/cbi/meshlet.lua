-- Copyright 2026 cuihairu <chuihairu@gmail.com>
-- SPDX-License-Identifier: Apache-2.0

m = Map("meshlet", translate("Meshlet 组网"),
	translate("自组织 overlay 组网：hub（server）+ 设备接入（agent）。路由可作 hub 或纯成员，" ..
		"两个角色各自独立启停；完整管理控制台经 server 的 web 界面访问（见 README OpenWrt 节）。"))

-- Restart both services after a successful apply; the init scripts re-render
-- the TOML from UCI, so every setting change takes effect immediately.
-- Restarting a disabled role is a no-op (start_service returns early).
function m.on_commit()
	luci.sys.call("/etc/init.d/meshlet-server restart >/dev/null 2>&1")
	luci.sys.call("/etc/init.d/meshlet-agent restart >/dev/null 2>&1")
end

-- hub 角色设置（server）。
s = m:section(NamedSection, "server", "server", translate("Hub 服务 (meshlet-server)"))
s.addremove = false

o = s:option(Flag, "enabled", translate("启用 hub 服务"))
o.rmempty = false

o = s:option(Value, "bind", translate("监听地址 (bind)"))
o.default = "127.0.0.1:8080"
o.rmempty = false
o.description = translate("API/控制台监听地址；LuCI 状态页按此地址访问")

o = s:option(Value, "state_dir", translate("状态目录"))
o.default = "/var/lib/meshlet"
o.rmempty = false

o = s:option(Flag, "dataplane", translate("启用 WireGuard hub 数据面"))
o.rmempty = false
o.description = translate("关闭 = 仅面板/API，不建 mesh；密钥缺失时首次启动自动 wg genkey 生成")

o = s:option(Value, "interface", translate("接口名"))
o.default = "meshlet"
o.rmempty = false

o = s:option(Value, "listen_port", translate("WireGuard 监听端口"))
o.default = "51820"
o.datatype = "port"
o.rmempty = false

o = s:option(Value, "private_key_file", translate("hub 私钥路径"))
o.default = "/etc/meshlet/hub.key"
o.rmempty = false

o = s:option(Value, "api_token", translate("API token (LuCI 状态页用)"))
o.password = true
o.description = translate("read scope 的 mlt_… token，仅用于状态页查设备在线；页面只显示脱敏前缀")

-- 设备接入角色设置（agent：路由自身加入 mesh）。
a = m:section(NamedSection, "agent", "agent", translate("设备接入 (meshlet-agent)"))
a.addremove = false

o = a:option(Flag, "enabled", translate("启用 agent（路由加入 mesh）"))
o.rmempty = false

o = a:option(Value, "server_url", translate("hub 地址 (server_url)"))
o.default = "http://127.0.0.1:8080"
o.rmempty = false

o = a:option(Value, "state_dir", translate("状态目录"))
o.default = "/var/lib/meshlet-agent"
o.rmempty = false

o = a:option(Value, "device_name", translate("设备名"))
o.rmempty = false

o = a:option(Value, "bootstrap_token", translate("注册 bootstrap token"))
o.password = true
o.description = translate("hub 签发的一次性注册令牌；agent 私钥缺失时首次启动自动生成")

o = a:option(Value, "hub_endpoint", translate("hub 数据面端点"))
o.description = translate("形如 host.example.com:51820（hub 的 WireGuard 端点）")

o = a:option(Value, "interface", translate("接口名"))
o.default = "meshlet"
o.rmempty = false

o = a:option(Value, "listen_port", translate("直连监听端口"))
o.default = "51821"
o.datatype = "port"
o.rmempty = false

o = a:option(Value, "private_key_file", translate("agent 私钥路径"))
o.default = "/etc/meshlet/agent.key"
o.rmempty = false

return m
