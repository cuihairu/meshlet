
- [ ] R-DIAG · P2 · agent 本地网络诊断信息面（用户令 2026-11-01：查看本地的路由表等信息）
  - 交付：agent 采集并上报「路由表（ip route/route print 全表）、接口清单（含地址/状态/MTU）、wg-mlt 接口读数（wg show：peer/握手/流量）」三类快照；console 诊断页新增展示；CLI `meshlet agent diag` 本地一键输出同内容
  - 复用：meshlet-network 已有 ip route/wg show 解析器（linux.rs §18.3/wg dump），不重写解析；Windows 侧用 `route print` + `Get-NetIPConfiguration` 等价采集
  - 验收：三类快照在 console 可见且与真实路由表一致（抽样比对 3 条）；Linux+Windows 各验一台；心跳周期内更新
- [ ] R-DIAG-2 · P2 · 直连 peers 信息展示（用户令 2026-11-01：查看已建立直连的 peers 信息）
  - 交付：诊断面增「直连 peers」区块——每 peer 展示：名称、overlay IP（10.240.x.x）、连接模式（P2P 直连 / hub 中继）、直连 endpoint（ip:port）、RTT 延迟（ms，直连路径实测）、最近握手、累计流量；命令可查：CLI `meshlet agent diag --peers`（或 `meshlet peers`）单命令输出全部 peer 的 IP/模式/延迟/endpoint 表格；数据源=agent 上报的 peer 连接状态（依赖 P2P 直连功能的状态上报）；console 诊断页同步展示
  - 验收：至少 2 peer 场景（1 直连 1 中继）模式标识与实际一致；RTT 数值与手工 ping 对账误差 <20%；直连断开回落 hub 后 60s 内模式翻转为中继
