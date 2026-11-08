//! meshlet-cli：类 ZeroTier 的命令行工具。
//!
//! 常用命令：
//!   meshlet info             设备信息（名称、IP、状态）
//!   meshlet status           agent 运行状态
//!   meshlet peers            直连节点列表（IP/模式/延时/端点/流量）
//!   meshlet peer dial <node> 强制对目标节点发起直连拨号（名称/IP）
//!   meshlet agent diag       网络诊断快照（路由表/接口清单/wg 读数）
//!   meshlet agent diag --peers   在快照后追加直连 peers 表
//!   meshlet task ls          任务队列（--network <id>）
//!   meshlet task assign      下发任务（--network/--node/--cmd）
//!   meshlet task confirm <id>    确认完成（用户侧动作）
//!   meshlet task retry <id>      驳回重跑（新代任务）
//!   meshlet networks         子网/路由列表
//!   meshlet config           显示配置
//!   meshlet version          版本号

mod cli;

use cli::dispatch::dispatch;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    dispatch(args);
}
