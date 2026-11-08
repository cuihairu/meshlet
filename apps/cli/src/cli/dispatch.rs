use crate::cli::local_state::{cmd_config, cmd_info, cmd_networks, cmd_peers, cmd_status};
use crate::cli::peer_dial::cmd_peer_dial;
use crate::cli::task_client::{
    cmd_task_assign, cmd_task_confirm, cmd_task_ls, cmd_task_retry, print_task_usage,
};
use crate::cli::windows_diagnostics::cmd_agent_diag;

pub(crate) fn dispatch(args: Vec<String>) {
    let cmd = args.first().map(String::as_str).unwrap_or("");

    // `meshlet agent diag [--peers]`：二层子命令。
    if cmd == "agent" {
        let sub = args.get(1).map(String::as_str).unwrap_or("");
        match sub {
            "diag" => {
                let show_peers = args.iter().any(|arg| arg == "--peers");
                cmd_agent_diag(show_peers);
            }
            other => {
                eprintln!("error: unknown agent subcommand '{other}'");
                std::process::exit(1);
            }
        }
        return;
    }

    // `meshlet peer dial [<node>]`：二层子命令。
    if cmd == "peer" {
        let sub = args.get(1).map(String::as_str).unwrap_or("");
        match sub {
            "dial" => cmd_peer_dial(args.get(2).map(String::as_str)),
            other => {
                eprintln!("error: unknown peer subcommand '{other}'");
                eprintln!();
                print_usage();
                std::process::exit(1);
            }
        }
        return;
    }

    // `meshlet task <sub>`（MT-003）：控制台任务队列的 CLI 面。
    if cmd == "task" {
        let sub = args.get(1).map(String::as_str).unwrap_or("");
        let rest: Vec<String> = args.iter().skip(2).cloned().collect();
        match sub {
            "assign" => cmd_task_assign(&rest),
            "ls" | "list" => cmd_task_ls(&rest),
            "confirm" => cmd_task_confirm(&rest),
            "retry" => cmd_task_retry(&rest),
            // `meshlet task` / `--help`：任务域用法（比全局帮助更聚焦）。
            "help" | "--help" | "-h" | "" => print_task_usage(),
            other => {
                eprintln!("error: unknown task subcommand '{other}'");
                eprintln!();
                print_task_usage();
                std::process::exit(1);
            }
        }
        return;
    }

    match cmd {
        "info" => cmd_info(),
        "status" => cmd_status(),
        "peers" => cmd_peers(),
        "networks" => cmd_networks(),
        "config" => cmd_config(),
        "version" | "--version" | "-V" => {
            println!("meshlet-cli {}", env!("CARGO_PKG_VERSION"));
        }
        "help" | "--help" | "-H" | "" => print_usage(),
        other => {
            eprintln!("error: unknown command '{other}'");
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    }
}

pub(crate) fn print_usage() {
    // R-TRAY-1：帮助文本由命令目录生成（单一事实源），与托盘「命令」区
    // 同源——新增命令自动出现在两处，`--help` 与目录不可能漂移。
    print!(
        "{}",
        meshlet_commands::usage_text(env!("CARGO_PKG_VERSION"))
    );
}
