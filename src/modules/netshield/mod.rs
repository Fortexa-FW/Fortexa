//! netshield: eBPF/XDP-based network filtering for Fortexa
//!
//! This module provides network filtering using eBPF/XDP in Rust.
//!
//! The NetshieldModule struct initializes the netshield module.

use crate::core::rules::RulesManager;
use crate::modules::Module;
use anyhow::Result;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::xdp::XdpLinkId;
use aya::{Ebpf, programs::Xdp};
use bincode::config;
use std::convert::TryInto;
use std::sync::Arc;
use std::sync::Mutex;

#[cfg(feature = "ebpf_enabled")]
use if_addrs::get_if_addrs;

mod constants;
pub mod security;
use constants::{MAX_RULE_SIZE, NETSHIELD_PROGRAM_NAME, RULES_MAP_NAME};
use security::NetshieldSecurityConfig;

pub struct NetshieldModule {
    pub rules_path: String,
    pub bpf: Mutex<Option<Ebpf>>,
    pub attached_links: Mutex<Vec<XdpLinkId>>,
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
    pub fn with_xdp(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
        rules_manager: Arc<RulesManager>,
    ) -> anyhow::Result<Self> {
        Self::with_xdp_secure(rules_path, security_config, rules_manager)
    }

    /// Secure XDP constructor with explicit security configuration
    #[cfg(feature = "ebpf_enabled")]
    pub fn with_xdp_secure(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
        rules_manager: Arc<RulesManager>,
    ) -> anyhow::Result<Self> {
        // Use embedded eBPF path from build script, fallback to default
        let bpf_path = option_env!("NETSHIELD_EBPF_PATH").unwrap_or("./netshield_xdp.o");

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

            // Try to attach XDP program
            match Self::attach_xdp_to_interface(&mut bpf, &name) {
                Ok(link_id) => {
                    attached_links.push(link_id);
                    successful_attachments += 1;
                    log::info!("Successfully attached XDP to interface {}", name);
                }
                Err(e) => {
                    log::warn!("Failed to attach XDP to interface {}: {}", name, e);
                    // Continue with other interfaces rather than failing completely
                }
            }
        }

        if successful_attachments == 0 {
            return Err(anyhow::anyhow!(
                "Failed to attach XDP to any network interface"
            ));
        }

        log::info!("XDP attached to {} interfaces", successful_attachments);

        Ok(Self {
            rules_path,
            bpf: Mutex::new(Some(bpf)),
            attached_links: Mutex::new(attached_links),
            security_config,
            rules_manager,
        })
    }

    /// Helper function to attach XDP to a single interface
    #[cfg(feature = "ebpf_enabled")]
    fn attach_xdp_to_interface(bpf: &mut Ebpf, interface_name: &str) -> anyhow::Result<XdpLinkId> {
        let program: &mut Xdp = bpf
            .program_mut(NETSHIELD_PROGRAM_NAME)
            .ok_or_else(|| anyhow::anyhow!("eBPF program '{}' not found", NETSHIELD_PROGRAM_NAME))?
            .try_into()?;

        program
            .load()
            .map_err(|e| anyhow::anyhow!("Failed to load XDP program: {}", e))?;

        let link_id = program
            .attach(interface_name, aya::programs::XdpFlags::default())
            .map_err(|e| anyhow::anyhow!("Failed to attach XDP to {}: {}", interface_name, e))?;

        Ok(link_id)
    }

    /// Fallback constructor when eBPF is not available
    #[cfg(not(feature = "ebpf_enabled"))]
    pub fn with_xdp(
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

    /// Detach XDP from all interfaces (call on shutdown)
    pub fn detach_all(self) -> anyhow::Result<()> {
        let bpf_path = option_env!("NETSHIELD_EBPF_PATH").unwrap_or("./netshield_xdp.o");

        let attached_links = self.attached_links.into_inner().unwrap();
        for link_id in attached_links {
            let mut bpf = Ebpf::load_file(bpf_path)?;
            let program: &mut Xdp = bpf
                .program_mut(NETSHIELD_PROGRAM_NAME)
                .unwrap()
                .try_into()?;
            program.detach(link_id)?;
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
            let mut rules_map: BpfHashMap<_, u32, [u8; MAX_RULE_SIZE]> = BpfHashMap::try_from(
                bpf.map_mut(RULES_MAP_NAME)
                    .ok_or_else(|| anyhow::anyhow!("{} not found", RULES_MAP_NAME))?,
            )?;

            // Clear the map first
            let keys: Vec<u32> = rules_map.keys().collect::<Result<_, _>>()?;
            for key in keys {
                rules_map.remove(&key)?;
            }

            // Insert each rule (serialize to [u8; MAX_RULE_SIZE])
            for (i, rule) in rules.iter().enumerate() {
                // Security check: validate rule before serialization
                if let Err(e) = Self::validate_rule(rule) {
                    log::warn!("Skipping invalid rule at index {}: {}", i, e);
                    continue;
                }

                let mut data = [0u8; MAX_RULE_SIZE];
                let config = config::standard();
                let encoded: Vec<u8> = bincode::encode_to_vec(rule, config)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize rule: {}", e))?;

                if encoded.len() > MAX_RULE_SIZE {
                    log::warn!(
                        "Rule at index {} too large ({} bytes), skipping",
                        i,
                        encoded.len()
                    );
                    continue;
                }

                let len = encoded.len().min(MAX_RULE_SIZE);
                data[..len].copy_from_slice(&encoded[..len]);
                rules_map.insert(i as u32, data, 0)?;
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
            let mut rules_map: BpfHashMap<_, u32, [u8; MAX_RULE_SIZE]> = BpfHashMap::try_from(
                bpf.map_mut(RULES_MAP_NAME)
                    .ok_or_else(|| anyhow::anyhow!("{} not found", RULES_MAP_NAME))?,
            )?;
            rules_map.remove(&index)?;
        }
        Ok(())
    }

    /// Advanced constructor: load eBPF and attach to all interfaces, with custom eBPF path
    #[cfg(feature = "ebpf_enabled")]
    pub fn with_xdp_and_ebpf_path(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
        rules_manager: Arc<RulesManager>,
        ebpf_path: Option<String>,
    ) -> anyhow::Result<Self> {
        let mut security_config = security_config;
        let bpf_path = if let Some(ref path) = ebpf_path {
            if !security_config.allowed_ebpf_paths.contains(path) {
                security_config.allowed_ebpf_paths.push(path.clone());
            }
            path.as_str()
        } else {
            option_env!("NETSHIELD_EBPF_PATH").unwrap_or("./netshield_xdp.o")
        };
        Self::with_xdp_secure_and_path(rules_path, security_config, rules_manager, bpf_path)
    }

    #[cfg(feature = "ebpf_enabled")]
    fn with_xdp_secure_and_path(
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
            match Self::attach_xdp_to_interface(&mut bpf, &name) {
                Ok(link_id) => {
                    attached_links.push(link_id);
                    successful_attachments += 1;
                    log::info!("Successfully attached XDP to interface {}", name);
                }
                Err(e) => {
                    log::warn!("Failed to attach XDP to interface {}: {}", name, e);
                }
            }
        }
        if successful_attachments == 0 {
            return Err(anyhow::anyhow!(
                "Failed to attach XDP to any network interface"
            ));
        }
        log::info!("XDP attached to {} interfaces", successful_attachments);
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
        },
        source: if rule.source_ip != 0 {
            Some(std::net::Ipv4Addr::from(rule.source_ip).to_string())
        } else {
            None
        },
        destination: if rule.destination_ip != 0 {
            Some(std::net::Ipv4Addr::from(rule.destination_ip).to_string())
        } else {
            None
        },
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
        protocol: None, // or convert protocol_number to string if needed
        action: match rule.action {
            crate::core::rules::Action::Block => Action::Block,
            crate::core::rules::Action::Allow => Action::Allow,
            crate::core::rules::Action::Log => Action::Log,
        },
        enabled: rule.enabled == 1,
        priority: rule.priority,
        parameters: rule.parameters.clone(),
        group: None,
    }
}
