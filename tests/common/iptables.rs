use super::FORTEXA_TEST_CHAINS_REGEX;
use std::process::Command;

#[test]
/// Cleans up iptables chains created for tests with the given prefix.
pub fn cleanup_all_test_chains() {
    let cmd = format!(
        "iptables-save | grep -v '{}' | iptables-restore -w",
        FORTEXA_TEST_CHAINS_REGEX
    );
    eprintln!("[debug] iptables cleanup command: {}", cmd);
    let status = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .status()
        .expect("Failed to run iptables cleanup");
    eprintln!("[debug] iptables bulk cleanup status: {:?}", status);
}

pub fn cleanup_test_chains(chain_prefix: &str) {
    let cmd = format!(
        "iptables-save | grep -v '{}' | iptables-restore -w",
        chain_prefix
    );
    eprintln!("[debug] iptables cleanup command: {}", cmd);
    let status = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .status()
        .expect("Failed to run iptables cleanup");
    eprintln!("[debug] iptables bulk cleanup status: {:?}", status);
}
