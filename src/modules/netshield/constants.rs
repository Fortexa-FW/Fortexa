//! Constants shared between eBPF and userspace components

pub const NETSHIELD_PROGRAM_NAME: &str = "netshield_ebpf";
pub const RULES_MAP_NAME: &str = "RULES_MAP";
pub const MAX_RULE_SIZE: usize = 256;
// NetShield eBPF module constants

// Note: Action constants and other eBPF-specific constants are defined
// in netshield-ebpf-common crate to ensure consistency between userspace and eBPF code
