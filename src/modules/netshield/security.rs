//! Security configuration for netshield eBPF operations

use std::collections::HashSet;

/// Security configuration for eBPF operations
#[derive(Debug, Clone)]
pub struct NetshieldSecurityConfig {
    /// Allowed network interfaces for XDP attachment
    pub allowed_interfaces: Option<HashSet<String>>,
    /// Whether to skip loopback interfaces (recommended: true)
    pub skip_loopback: bool,
    /// Maximum number of rules allowed
    pub max_rules: u32,
    /// Whether to verify eBPF object integrity
    pub verify_ebpf_integrity: bool,
    /// Allowed eBPF object paths (for file-based loading)
    pub allowed_ebpf_paths: Vec<String>,
}

impl Default for NetshieldSecurityConfig {
    fn default() -> Self {
        Self {
            allowed_interfaces: None, // None = auto-detect non-loopback interfaces
            skip_loopback: true,
            max_rules: 1000,
            verify_ebpf_integrity: true,
            allowed_ebpf_paths: vec![
                "/usr/lib/fortexa/netshield_tc_secure.o".to_string(),
                "/opt/fortexa/netshield_tc_secure.o".to_string(),
                "./netshield_tc_secure.o".to_string(), // Only for development
                "/usr/lib/fortexa/netshield_xdp.o".to_string(), // Legacy XDP support
                "/opt/fortexa/netshield_xdp.o".to_string(),
                "./netshield_xdp.o".to_string(), // Only for development
            ],
        }
    }
}

impl NetshieldSecurityConfig {
    /// Create a production-ready security configuration
    pub fn production() -> Self {
        Self {
            allowed_interfaces: None,
            skip_loopback: true,
            max_rules: 100, // Lower limit for production
            verify_ebpf_integrity: true,
            allowed_ebpf_paths: vec![
                "/usr/lib/fortexa/netshield_tc_secure.o".to_string(),
                "/opt/fortexa/netshield_tc_secure.o".to_string(),
                "/usr/lib/fortexa/netshield_xdp.o".to_string(), // Legacy XDP support
                "/opt/fortexa/netshield_xdp.o".to_string(),
            ],
        }
    }

    /// Create a development configuration with relaxed security
    pub fn development() -> Self {
        Self {
            allowed_interfaces: Some(
                ["lo", "docker0", "veth"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
            skip_loopback: false, // Allow loopback for testing
            max_rules: 1000,
            verify_ebpf_integrity: false, // Faster development builds
            allowed_ebpf_paths: vec![
                "./netshield_xdp.o".to_string(),
                "../netshield_xdp.o".to_string(),
                "/tmp/netshield_xdp.o".to_string(),
            ],
        }
    }

    /// Validate if an interface is allowed for XDP attachment
    pub fn is_interface_allowed(&self, interface_name: &str) -> bool {
        // Check if interface is explicitly allowed
        if let Some(ref allowed) = self.allowed_interfaces {
            return allowed.contains(interface_name);
        }

        // Default policy: allow non-loopback interfaces
        if self.skip_loopback && interface_name == "lo" {
            return false;
        }

        // Additional security: skip known virtual interfaces in production
        let restricted_interfaces = ["docker", "veth", "br-", "virbr"];
        if self.allowed_interfaces.is_none() {
            for restricted in &restricted_interfaces {
                if interface_name.starts_with(restricted) {
                    return false;
                }
            }
        }

        true
    }

    /// Validate if an eBPF path is allowed
    pub fn is_ebpf_path_allowed(&self, path: &str) -> bool {
        self.allowed_ebpf_paths.iter().any(|allowed_path| {
            // Exact match or canonicalized path match
            path == allowed_path
                || std::fs::canonicalize(path)
                    .and_then(|canon_path| {
                        std::fs::canonicalize(allowed_path)
                            .map(|canon_allowed| canon_path == canon_allowed)
                    })
                    .unwrap_or(false)
        })
    }

    /// Validate rule count against limits
    pub fn validate_rule_count(&self, count: usize) -> Result<(), String> {
        if count as u32 > self.max_rules {
            return Err(format!(
                "Rule count {} exceeds maximum allowed {}",
                count, self.max_rules
            ));
        }
        Ok(())
    }
}
