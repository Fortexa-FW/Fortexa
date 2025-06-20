pub mod iptables;

pub const FORTEXA_TEST_CHAINS_REGEX: &str = "FORTEXA_TST_.*";

pub const TEST_CONFIG_TOML: &str = r#"
[general]
enabled = true
log_level = "info"
rules_path = "{rules_path}"

[modules.iptables]
enabled = true
chain_prefix = "{chain_prefix}"
chains_path = "{chains_path}"

[modules.logging]
enabled = true
log_file = "/tmp/test_fw.log"

[services.rest]
enabled = true
bind_address = "127.0.0.1"
port = {port}
"#;
