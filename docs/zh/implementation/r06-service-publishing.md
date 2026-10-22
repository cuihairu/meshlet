# R-06：服务发布进展

R-06 仍保持打开。服务转发、Web 发布、授权控制、健康探测和内部服务目录已在当前代码中落地；仍需要真实 VPS/真机端到端验收。

## Implemented

- TCP 和 UDP PortForward 可通过 mesh 发布本地服务，并保留所选传输协议。
- HTTP 和 HTTPS 发布可将外部流量路由到 mesh 服务，包括边缘 TLS 终止。
- 授权控制通过 `POST /api/v1/publish/routes/check` 暴露；server 路由已在 `apps/server/src/lib.rs:1015` 接入 `meshlet-publish` 服务适配器。
- 健康探测会在流量准入前验证发布目标可达。
- 内部 DNS 服务目录支持分流式服务发现，不覆盖公共 DNS 解析。
- 当前自动化验证结果为：`cargo test -p meshlet-publish` 8 passed；`cargo test -p meshlet-server --test publish_check` 2 passed。

## Outstanding

- 运行并归档真实 VPS/真机端到端服务发布验收。TODO 记录将该事项保持为待真机验证。
