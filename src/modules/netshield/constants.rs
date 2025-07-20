//! Constants shared between eBPF and userspace components

pub const NETSHIELD_PROGRAM_TC: &str = "netshield_ebpf_tc";
pub const RULES_MAP_NAME: &str = "secure_rules_map";
pub const MAX_RULE_SIZE: usize = 256;
// NetShield eBPF module constants

// Note: Action constants and other eBPF-specific constants are defined
// in netshield-ebpf-common crate to ensure consistency between userspace and eBPF code
