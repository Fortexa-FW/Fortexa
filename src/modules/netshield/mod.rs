//! netshield: eBPF/TC-based network filtering for Fortexa
//!
//! This module provides network filtering using eBPF/TC in Rust.
//!
//! The NetshieldModule struct initializes the netshield module.

use crate::core::rules::RulesManager;
use crate::modules::Module;
use anyhow::Result;
use aya::Ebpf;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::SchedClassifier;
use aya::programs::tc::{SchedClassifierLinkId, TcAttachType};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Mutex;

#[cfg(feature = "ebpf_enabled")]
use if_addrs::get_if_addrs;

mod constants;
pub mod security;
use constants::{NETSHIELD_PROGRAM_TC, RULES_MAP_NAME};
use security::NetshieldSecurityConfig;

// Security magic number for eBPF validation (must match C code)
const NETSHIELD_MAGIC: u32 = 0x4E455453; // "NETS"

// Rust struct that matches the eBPF C struct exactly
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SecureRule {
    magic: u32,            // Security magic number
    source_ip: u32,        // IPv4 in network byte order (0 = any)
    destination_ip: u32,   // IPv4 in network byte order (0 = any)
    source_port: u16,      // Port in host byte order (0 = any)
    destination_port: u16, // Port in host byte order (0 = any)
    protocol: u8,          // IP protocol (6=TCP, 17=UDP, 0=any)
    action: u8,            // 0=allow, 1=drop
    enabled: u8,           // 1=enabled, 0=disabled
    padding: u8,           // Padding for alignment
}

// Implement Pod trait for eBPF compatibility
unsafe impl aya::Pod for SecureRule {}

impl Default for SecureRule {
    fn default() -> Self {
        SecureRule {
            magic: NETSHIELD_MAGIC,
            source_ip: 0,
            destination_ip: 0,
            source_port: 0,
            destination_port: 0,
            protocol: 0,
            action: 1, // Default to drop
            enabled: 1,
            padding: 0,
        }
    }
}

pub struct NetshieldModule {
    pub rules_path: String,
    pub bpf: Mutex<Option<Ebpf>>,
    pub attached_links: Mutex<Vec<SchedClassifierLinkId>>,
    pub security_config: NetshieldSecurityConfig,
    /// Shared rules manager for all rule CRUD operations
    pub rules_manager: Arc<RulesManager>,
}

impl NetshieldModule {
    /// Main constructor: requires a shared RulesManager
    pub fn new(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
        rules_manager: Arc<RulesManager>,
    ) -> Self {
        NetshieldModule {
            rules_path,
            bpf: Mutex::new(None),
            attached_links: Mutex::new(Vec::new()),
            security_config,
            rules_manager,
        }
    }

    /// Advanced constructor: load eBPF and attach to all interfaces
    #[cfg(feature = "ebpf_enabled")]
    pub fn with_tc(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
        rules_manager: Arc<RulesManager>,
    ) -> anyhow::Result<Self> {
        // Check environment variable to force disable eBPF
        if std::env::var("FORTEXA_DISABLE_EBPF").is_ok() {
            log::warn!("eBPF disabled via FORTEXA_DISABLE_EBPF environment variable");
            return Ok(Self::new(rules_path, security_config, rules_manager));
        }

        // Try to detect if eBPF/TC will work by checking system capabilities first
        if !Self::is_tc_compatible() {
            log::warn!("System appears to be incompatible with TC. Falling back to basic mode.");
            return Ok(Self::new(rules_path, security_config, rules_manager));
        }

        log::info!("Attempting eBPF/TC initialization (this may take a moment)...");
        match Self::with_tc_secure(
            rules_path.clone(),
            security_config.clone(),
            rules_manager.clone(),
        ) {
            Ok(module) => {
                log::info!("Successfully initialized Netshield with eBPF/TC");
                Ok(module)
            }
            Err(e) => {
                log::warn!(
                    "Failed to initialize eBPF/TC: {}. Falling back to basic mode.",
                    e
                );
                log::warn!("Firewall will start but eBPF filtering will not be active.");

                // Fall back to basic constructor without eBPF
                Ok(Self::new(rules_path, security_config, rules_manager))
            }
        }
    }

    /// Check if the system is compatible with TC (basic heuristics)
    #[cfg(feature = "ebpf_enabled")]
    fn is_tc_compatible() -> bool {
        // Quick check: see if /sys/fs/bpf is mounted (indicates eBPF support)
        if !std::path::Path::new("/sys/fs/bpf").exists() {
            log::debug!("BPF filesystem not found at /sys/fs/bpf - likely no eBPF support");
            return false;
        }

        // Check for TC support by looking for tc command
        if std::process::Command::new("which")
            .arg("tc")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            log::debug!("tc command found - system likely supports TC eBPF");
            return true;
        }

        // Default to trying (most modern systems should work)
        log::debug!("Cannot determine TC compatibility - will attempt to load");
        true
    }

    /// Secure TC constructor with explicit security configuration
    #[cfg(feature = "ebpf_enabled")]
    pub fn with_tc_secure(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
        rules_manager: Arc<RulesManager>,
    ) -> anyhow::Result<Self> {
        // Use embedded eBPF path from build script, fallback to system location
        let bpf_path =
            option_env!("NETSHIELD_EBPF_PATH").unwrap_or("/usr/lib/fortexa/netshield_tc_secure.o");

        // Security check: validate eBPF path
        if !security_config.is_ebpf_path_allowed(bpf_path) {
            return Err(anyhow::anyhow!("eBPF path not allowed: {}", bpf_path));
        }

        // Security check: verify file exists and is readable
        if !std::path::Path::new(bpf_path).exists() {
            return Err(anyhow::anyhow!("eBPF file not found: {}", bpf_path));
        }

        let mut bpf = Ebpf::load_file(bpf_path)
            .map_err(|e| anyhow::anyhow!("Failed to load eBPF program: {}", e))?;

        let mut attached_links = Vec::new();
        let mut successful_attachments = 0;

        for iface in get_if_addrs()? {
            let name = iface.name.clone();
            log::debug!(
                "Processing interface: {} (is_loopback: {})",
                name,
                iface.is_loopback()
            );

            // Security check: validate interface against policy
            if !security_config.is_interface_allowed(&name) {
                log::debug!(
                    "Skipping interface {} (not allowed by security policy)",
                    name
                );
                continue;
            }

            if iface.is_loopback() && security_config.skip_loopback {
                log::debug!("Skipping loopback interface {}", name);
                continue;
            }

            log::debug!("Attempting to attach TC to interface: {}", name);
            // Try to attach TC programs (both ingress and egress)
            match Self::attach_tc_to_interface(&mut bpf, &name) {
                Ok(links) => {
                    attached_links.extend(links);
                    successful_attachments += 1;
                    log::info!("Successfully attached TC to interface {}", name);
                }
                Err(e) => {
                    log::warn!("Failed to attach TC to interface {}: {}", name, e);
                    // Continue with other interfaces rather than failing completely
                }
            }
        }

        if successful_attachments == 0 {
            return Err(anyhow::anyhow!(
                "Failed to attach TC to any network interface"
            ));
        }

        log::info!("TC attached to {} interfaces", successful_attachments);

        Ok(Self {
            rules_path,
            bpf: Mutex::new(Some(bpf)),
            attached_links: Mutex::new(attached_links),
            security_config,
            rules_manager,
        })
    }

    /// Helper function to attach TC to a single interface (both ingress and egress)
    #[cfg(feature = "ebpf_enabled")]
    fn attach_tc_to_interface(
        bpf: &mut Ebpf,
        interface_name: &str,
    ) -> anyhow::Result<Vec<SchedClassifierLinkId>> {
        log::debug!("Starting TC attachment to interface: {}", interface_name);

        let mut links = Vec::new();

        // Add clsact qdisc if it doesn't exist (required for TC eBPF)
        log::debug!("Adding clsact qdisc to interface: {}", interface_name);
        if let Err(e) = std::process::Command::new("tc")
            .args(&["qdisc", "add", "dev", interface_name, "clsact"])
            .output()
        {
            log::warn!("Failed to add clsact qdisc to {}: {}", interface_name, e);
            // Continue anyway - qdisc might already exist
        }

        // Get the TC program (same program used for both ingress and egress)
        let program: &mut SchedClassifier = bpf
            .program_mut(NETSHIELD_PROGRAM_TC)
            .ok_or_else(|| anyhow::anyhow!("eBPF program '{}' not found", NETSHIELD_PROGRAM_TC))?
            .try_into()?;

        log::debug!("Loading TC program for interface: {}", interface_name);
        program.load()?;

        // Attach to ingress
        log::debug!(
            "Attaching TC program to ingress on interface: {}",
            interface_name
        );
        let ingress_link = program.attach(interface_name, TcAttachType::Ingress)?;
        links.push(ingress_link);

        // Attach to egress (same program, different attach point)
        log::debug!(
            "Attaching TC program to egress on interface: {}",
            interface_name
        );
        let egress_link = program.attach(interface_name, TcAttachType::Egress)?;
        links.push(egress_link);

        log::debug!(
            "Successfully attached TC program to both ingress and egress on interface: {}",
            interface_name
        );
        Ok(links)
    }

    /// Fallback constructor when eBPF is not available
    #[cfg(not(feature = "ebpf_enabled"))]
    pub fn with_tc(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
        rules_manager: Arc<RulesManager>,
    ) -> anyhow::Result<Self> {
        log::warn!("eBPF not available on this platform, falling back to basic mode");
        Ok(Self {
            rules_path,
            bpf: Mutex::new(None),
            attached_links: Mutex::new(Vec::new()),
            security_config,
            rules_manager,
        })
    }

    /// Detach TC from all interfaces (call on shutdown)
    pub fn detach_all(self) -> anyhow::Result<()> {
        let _bpf_path =
            option_env!("NETSHIELD_EBPF_PATH").unwrap_or("/usr/lib/fortexa/netshield_tc_secure.o");

        let attached_links = self.attached_links.into_inner().unwrap();
        for link_id in attached_links {
            // TC programs will be automatically detached when links are dropped
            log::debug!("Detaching TC link: {:?}", link_id);
        }
        Ok(())
    }

    /// Update the eBPF rules map with the current rules
    pub fn update_rules_map(&self, rules: &[NetshieldRule]) -> anyhow::Result<()> {
        log::debug!("[Netshield] update_rules_map called on instance {:p}", self);
        let bpf_loaded = self.bpf.lock().unwrap().is_some();
        log::debug!("[Netshield] bpf loaded: {}", bpf_loaded);
        // Security check: validate rule count
        self.security_config
            .validate_rule_count(rules.len())
            .map_err(|e| anyhow::anyhow!("Rule validation failed: {}", e))?;

        if let Some(bpf) = &mut *self.bpf.lock().unwrap() {
            let mut rules_map: BpfHashMap<_, u32, SecureRule> = BpfHashMap::try_from(
                bpf.map_mut(RULES_MAP_NAME)
                    .ok_or_else(|| anyhow::anyhow!("{} not found", RULES_MAP_NAME))?,
            )?;

            // Clear the map first
            let keys: Vec<u32> = rules_map.keys().collect::<Result<_, _>>()?;
            for key in keys {
                rules_map.remove(&key)?;
            }

            // Insert each rule (convert to SecureRule)
            for (i, rule) in rules.iter().enumerate() {
                // Security check: validate rule before conversion
                if let Err(e) = Self::validate_rule(rule) {
                    log::warn!("Skipping invalid rule at index {}: {}", i, e);
                    continue;
                }

                // Convert NetshieldRule to SecureRule
                let secure_rule = match convert_to_secure_rule(rule) {
                    Ok(sr) => sr,
                    Err(e) => {
                        log::warn!("Failed to convert rule at index {}: {}", i, e);
                        continue;
                    }
                };

                rules_map.insert(i as u32, secure_rule, 0)?;
                log::debug!("Inserted rule {} into eBPF map: {:?}", i, secure_rule);
            }

            log::info!("Updated eBPF rules map with {} rules", rules.len());
        } else {
            log::warn!(
                "eBPF not loaded (bpf is None) in update_rules_map on instance {:p}",
                self
            );
        }
        Ok(())
    }

    /// Validate a single rule for security and correctness
    fn validate_rule(rule: &NetshieldRule) -> Result<(), String> {
        // Add rule validation logic here
        // For example: check for valid IP ranges, port ranges, etc.

        // Basic validation: ensure required fields are present
        if rule.source.is_none() && rule.destination.is_none() {
            return Err("Rule must specify at least source or destination".to_string());
        }

        // Port validation is handled by u16 type constraints (0-65535)

        Ok(())
    }

    /// Remove a rule from the eBPF rules map by index
    pub fn remove_rule_from_map(&self, index: u32) -> anyhow::Result<()> {
        if let Some(bpf) = &mut *self.bpf.lock().unwrap() {
            let mut rules_map: BpfHashMap<_, u32, SecureRule> = BpfHashMap::try_from(
                bpf.map_mut(RULES_MAP_NAME)
                    .ok_or_else(|| anyhow::anyhow!("{} not found", RULES_MAP_NAME))?,
            )?;
            rules_map.remove(&index)?;
        }
        Ok(())
    }

    /// Advanced constructor: load eBPF and attach to all interfaces, with custom eBPF path
    #[cfg(feature = "ebpf_enabled")]
    pub fn with_tc_and_ebpf_path(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
        rules_manager: Arc<RulesManager>,
        ebpf_path: Option<String>,
    ) -> anyhow::Result<Self> {
        // Check environment variable to force disable eBPF
        if std::env::var("FORTEXA_DISABLE_EBPF").is_ok() {
            log::warn!("eBPF disabled via FORTEXA_DISABLE_EBPF environment variable");
            return Ok(Self::new(rules_path, security_config, rules_manager));
        }

        let mut security_config = security_config;
        let bpf_path = if let Some(ref path) = ebpf_path {
            if !security_config.allowed_ebpf_paths.contains(path) {
                security_config.allowed_ebpf_paths.push(path.clone());
            }
            path.as_str()
        } else {
            option_env!("NETSHIELD_EBPF_PATH").unwrap_or("/usr/lib/fortexa/netshield_tc_secure.o")
        };

        match Self::with_tc_secure_and_path(
            rules_path.clone(),
            security_config.clone(),
            rules_manager.clone(),
            bpf_path,
        ) {
            Ok(module) => {
                log::info!("Successfully initialized Netshield with eBPF/TC");
                Ok(module)
            }
            Err(e) => {
                log::warn!(
                    "Failed to initialize eBPF/TC: {}. Falling back to basic mode.",
                    e
                );
                log::warn!("Firewall will start but eBPF filtering will not be active.");
                log::warn!(
                    "Ensure the eBPF program is correctly built and placed at: {}",
                    bpf_path
                );
                // Fall back to basic constructor without eBPF
                Ok(Self::new(rules_path, security_config, rules_manager))
            }
        }
    }

    #[cfg(feature = "ebpf_enabled")]
    fn with_tc_secure_and_path(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
        rules_manager: Arc<RulesManager>,
        bpf_path: &str,
    ) -> anyhow::Result<Self> {
        // Security check: validate eBPF path
        if !security_config.is_ebpf_path_allowed(bpf_path) {
            return Err(anyhow::anyhow!("eBPF path not allowed: {}", bpf_path));
        }
        // Security check: verify file exists and is readable
        if !std::path::Path::new(bpf_path).exists() {
            return Err(anyhow::anyhow!("eBPF file not found: {}", bpf_path));
        }
        let mut bpf = Ebpf::load_file(bpf_path)
            .map_err(|e| anyhow::anyhow!("Failed to load eBPF program: {}", e))?;
        let mut attached_links = Vec::new();
        let mut successful_attachments = 0;
        for iface in get_if_addrs()? {
            let name = iface.name.clone();
            log::debug!(
                "Processing interface: {} (is_loopback: {})",
                name,
                iface.is_loopback()
            );
            if !security_config.is_interface_allowed(&name) {
                log::debug!(
                    "Skipping interface {} (not allowed by security policy)",
                    name
                );
                continue;
            }
            if iface.is_loopback() && security_config.skip_loopback {
                log::debug!("Skipping loopback interface {}", name);
                continue;
            }
            match Self::attach_tc_to_interface(&mut bpf, &name) {
                Ok(links) => {
                    attached_links.extend(links);
                    successful_attachments += 1;
                    log::info!("Successfully attached TC to interface {}", name);
                }
                Err(e) => {
                    log::warn!("Failed to attach TC to interface {}: {}", name, e);
                }
            }
        }
        if successful_attachments == 0 {
            return Err(anyhow::anyhow!(
                "Failed to attach TC to any network interface"
            ));
        }
        log::info!("TC attached to {} interfaces", successful_attachments);
        Ok(Self {
            rules_path,
            bpf: Mutex::new(Some(bpf)),
            attached_links: Mutex::new(attached_links),
            security_config,
            rules_manager,
        })
    }

    /// Sync all rules from RulesManager to the eBPF map
    pub fn sync_rules_to_ebpf(&self) -> anyhow::Result<()> {
        let rules = self.rules_manager.list_rules()?;
        let netshield_rules: Vec<NetshieldRule> =
            rules.iter().map(convert_to_netshield_rule).collect();
        self.update_rules_map(&netshield_rules)
    }
}

impl Module for NetshieldModule {
    fn init(&self) -> Result<()> {
        let mut module = NetshieldModule::new(
            self.rules_path.clone(),
            self.security_config.clone(),
            self.rules_manager.clone(),
        );
        crate::modules::netshield::apply_all_rules(&mut module).map_err(anyhow::Error::msg)?;
        Ok(())
    }

    fn apply_rules(&self, _rules: &[crate::core::rules::Rule]) -> Result<()> {
        // Not used for netshield (iptables only)
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub mod filter;

pub use filter::{
    Action, Direction, NetshieldRule, add_rule, apply_all_rules, delete_rule, get_groups, get_rule,
    get_rules, get_rules_by_group, update_rule,
};

// Helper to convert core::rules::Rule to NetshieldRule
fn convert_to_netshield_rule(rule: &crate::core::rules::Rule) -> NetshieldRule {
    NetshieldRule {
        id: rule.id.clone(),
        name: rule.name.clone(),
        description: rule.description.clone(),
        direction: match rule.direction {
            crate::core::rules::Direction::Incoming => Direction::Incoming,
            crate::core::rules::Direction::Outgoing => Direction::Outgoing,
            crate::core::rules::Direction::Both => Direction::Both,
        },
        source: rule.source.clone(),
        destination: rule.destination.clone(),
        source_port: if rule.source_port_network != 0 {
            Some(rule.source_port_network)
        } else {
            None
        },
        destination_port: if rule.destination_port_network != 0 {
            Some(rule.destination_port_network)
        } else {
            None
        },
        protocol: rule.protocol.clone(),
        action: match rule.action {
            crate::core::rules::Action::Block => Action::Block,
            crate::core::rules::Action::Allow => Action::Allow,
            crate::core::rules::Action::Log => Action::Log,
        },
        enabled: rule.enabled,
        priority: rule.priority,
        parameters: rule.parameters.clone(),
        group: None,
    }
}

// Helper to convert NetshieldRule to SecureRule for eBPF
fn convert_to_secure_rule(rule: &NetshieldRule) -> Result<SecureRule, String> {
    let mut secure_rule = SecureRule::default();

    // Convert source IP
    if let Some(source) = &rule.source {
        let ip_addr = source
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("Invalid source IP '{}': {}", source, e))?;
        secure_rule.source_ip = u32::from(ip_addr); // Store in host byte order
        log::debug!(
            "Converted source IP '{}' to host bytes: 0x{:08x}",
            source,
            secure_rule.source_ip
        );
    }

    // Convert destination IP
    if let Some(destination) = &rule.destination {
        let ip_addr = destination
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("Invalid destination IP '{}': {}", destination, e))?;
        let ip_as_u32 = u32::from(ip_addr);
        secure_rule.destination_ip = ip_as_u32; // Store in host byte order
        log::debug!(
            "Converted destination IP '{}' to host bytes: 0x{:08x}, decimal={}",
            destination,
            ip_as_u32,
            ip_as_u32
        );
    }

    // Set ports (already in correct byte order)
    secure_rule.source_port = rule.source_port.unwrap_or(0);
    secure_rule.destination_port = rule.destination_port.unwrap_or(0);

    // Convert protocol
    secure_rule.protocol = match rule.protocol.as_deref() {
        Some("tcp") => 6,
        Some("udp") => 17,
        Some("icmp") => 1,
        _ => 0, // Any protocol
    };

    // Convert action
    secure_rule.action = match rule.action {
        Action::Allow => 0,
        Action::Block => 1,
        Action::Log => 1, // Treat log as drop for now
    };

    // Set enabled flag
    secure_rule.enabled = rule.enabled;

    log::debug!(
        "Created SecureRule: magic=0x{:08x}, src_ip=0x{:08x}, dst_ip=0x{:08x}, protocol={}, action={}, enabled={}",
        secure_rule.magic,
        secure_rule.source_ip,
        secure_rule.destination_ip,
        secure_rule.protocol,
        secure_rule.action,
        secure_rule.enabled
    );

    Ok(secure_rule)
}
