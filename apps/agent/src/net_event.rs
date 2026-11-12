//! 网络变化事件（P1 配套，2026-11-12 用户令）：接口起落 / 地址增删时唤醒
//! 主循环的退避等待，**立即重试**——断线后最坏等一整个退避周期（300s 封顶
//! 时代最坏 5 分钟）是「老是连不上」的直接来源；网络早恢复了，agent 却还
//! 在退避里干等。
//!
//! 平台机制（二选一，最小实现）：
//! - **Linux**：netlink 订阅（`NETLINK_ROUTE` 组播
//!   `RTMGRP_LINK | RTMGRP_IPV4_IFADDR`——接口 up/down 与 IPv4 地址增删，
//!   `libc` 直达，不引新依赖）；
//! - **Windows**：`NotifyAddrChange(NULL, NULL)` 同步阻塞式——官方文档明示
//!   双 NULL 即阻塞到 IPv4 地址表变化（一次变化后需再次调用取下一次）。
//!   接口起落通常伴随地址增删即触发；纯 link 翻转不换地址的极端场景不在此
//!   最小实现的感知面内（如实记录）。
//!
//! 纪律：
//! - **监视失败绝不放大故障**：起线程 / 订阅失败只告警退出，主循环退回纯
//!   睡眠周期（行为同本模块不存在）——探测唤醒是加速器，不是依赖面；
//! - **绝不忙转**：接收端把 `Disconnected`（监视线程没了）按「等满周期」
//!   处理，见 [`crate::agent::Agent::run`]。

use std::sync::mpsc::{self, Receiver, Sender};

/// 起网络变化监视：返回事件接收端。每条消息代表「接口/地址表发生了变化」
///（不区分具体事件——主循环的重试是幂等的拉取，无须知道变化内容）。
///
/// 监视线程常驻到进程退出或订阅失败；订阅失败只记一次告警，接收端从此
/// 收不到事件（主循环退回纯睡眠周期，见模块文档）。
pub fn watch() -> Receiver<()> {
    let (tx, rx) = mpsc::channel();
    // 发送端先克隆一份留在本函数：线程起不来时保活它——接收端既无事件
    // 也无 Disconnected（否则主循环会被立刻唤醒，忙转）。
    let keeper = tx.clone();
    match std::thread::Builder::new()
        .name("meshlet-net-event".into())
        .spawn(move || monitor(tx))
    {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "net-event monitor failed to start; retry stays interval-based");
            std::mem::forget(keeper);
        }
    }
    rx
}

#[cfg(target_os = "linux")]
fn monitor(events: Sender<()>) {
    // 最小 netlink 订阅：link（接口起落）+ IPv4 地址（地址增删）组播组。
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "netlink socket failed; retry stays interval-based");
            return;
        }
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR) as u32;
        let bound = libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        if bound < 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "netlink bind failed; retry stays interval-based");
            libc::close(fd);
            return;
        }
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0);
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                tracing::warn!(error = %err, "netlink recv failed; retry stays interval-based");
                libc::close(fd);
                return;
            }
            if n == 0 {
                // 内核不会关 netlink：按异常退出处理（告警在 run 侧由
                // Disconnected 兜底为纯睡眠）。
                libc::close(fd);
                return;
            }
            if events.send(()).is_err() {
                libc::close(fd);
                return;
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn monitor(events: Sender<()>) {
    loop {
        // 双 NULL 的同步式：阻塞到 IPv4 地址表变化（官方文档），无句柄归属
        // 问题；一次变化后需再次调用取下一次。
        let rc = unsafe {
            windows_sys::Win32::NetworkManagement::IpHelper::NotifyAddrChange(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            tracing::warn!(
                error = rc,
                "NotifyAddrChange failed; retry stays interval-based"
            );
            return;
        }
        if events.send(()).is_err() {
            return;
        }
    }
}

/// 其余平台无网络变化机制：监视即退出（接收端 Disconnected → 主循环按
/// 等满周期处理，见模块文档）。
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn monitor(events: Sender<()>) {
    drop(events);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 监视启动即有可用接收端；订阅失败（CI 容器常无 netlink 权限）不 panic，
    /// 主循环按纯周期退避——启动本身不可能是故障点。
    #[test]
    fn watch_returns_a_receiver_without_panicking() {
        let rx = watch();
        // 不断言是否收到事件（真网络事件不可控）：接收端在即可。
        drop(rx);
    }
}
