
- [ ] R-DIAG · P2 · agent 本地网络诊断信息面（用户令 2026-11-01：查看本地的路由表等信息）
  - 交付：agent 采集并上报「路由表（ip route/route print 全表）、接口清单（含地址/状态/MTU）、wg-mlt 接口读数（wg show：peer/握手/流量）」三类快照；console 诊断页新增展示；CLI `meshlet agent diag` 本地一键输出同内容
  - 复用：meshlet-network 已有 ip route/wg show 解析器（linux.rs §18.3/wg dump），不重写解析；Windows 侧用 `route print` + `Get-NetIPConfiguration` 等价采集
  - 验收：三类快照在 console 可见且与真实路由表一致（抽样比对 3 条）；Linux+Windows 各验一台；心跳周期内更新
