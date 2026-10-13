//! meshlet-cli：Phase 1 骨架。子命令随 Phase 1「CLI 基础命令」条目扩展。

fn usage() -> &'static str {
    "meshlet-cli <version>\n\nCommands arrive with Phase 1 (network/device enrollment)."
}

fn main() {
    println!("{}", usage());
}

#[cfg(test)]
mod tests {
    #[test]
    fn usage_mentions_phase_plan() {
        let u = super::usage();
        assert!(u.contains("meshlet-cli"));
        assert!(u.contains("Phase 1"));
    }
}
