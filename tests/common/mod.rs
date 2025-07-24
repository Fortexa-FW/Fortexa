pub const TEST_CONFIG_TOML: &str = r#"
[general]
enabled = true
log_level = "info"
rules_path = "{rules_path}"

[modules.netshield]
enabled = true
rules_path = "{rules_path}"

[modules.logging]
enabled = true
log_file = "/tmp/test_fw.log"

[services.rest]
enabled = true
bind_address = "127.0.0.1"
port = {port}
"#;

// eBPF cleanup function to replace iptables chain cleanup
pub fn cleanup_test_ebpf(_test_id: &str) {
    // For eBPF, cleanup is handled automatically when the module is dropped
    // No manual cleanup of chains needed since we use eBPF maps instead
    eprintln!("[debug] eBPF test cleanup completed (automatic)");
}
