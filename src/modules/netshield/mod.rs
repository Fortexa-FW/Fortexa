//! netshield: eBPF/XDP-based network filtering for Fortexa
//!
//! This module provides network filtering using eBPF/XDP in Rust.
//!
//! The NetshieldModule struct initializes the netshield module.

use crate::modules::Module;
use anyhow::Result;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::xdp::XdpLinkId;
use aya::{Ebpf, programs::Xdp};
use bincode::config;
use std::convert::TryInto;
use std::sync::Mutex;

#[cfg(feature = "ebpf_enabled")]
use if_addrs::get_if_addrs;

mod constants;
mod security;
use constants::{MAX_RULE_SIZE, NETSHIELD_PROGRAM_NAME, RULES_MAP_NAME};
use security::NetshieldSecurityConfig;

pub struct NetshieldModule {
    pub rules_path: String,
    pub bpf: Mutex<Option<Ebpf>>,
    pub attached_links: Mutex<Vec<XdpLinkId>>,
    pub security_config: NetshieldSecurityConfig,
}

impl NetshieldModule {
    /// Basic constructor (for legacy/tests)
    pub fn new() -> Self {
        NetshieldModule {
            rules_path: "/var/lib/fortexa/netshield_rules.json".to_string(),
            bpf: Mutex::new(None),
            attached_links: Mutex::new(Vec::new()),
            security_config: NetshieldSecurityConfig::default(),
        }
    }

    /// Constructor with custom security configuration
    pub fn with_security_config(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
    ) -> Self {
        NetshieldModule {
            rules_path,
            bpf: Mutex::new(None),
            attached_links: Mutex::new(Vec::new()),
            security_config,
        }
    }

    /// Advanced constructor: load eBPF and attach to all interfaces
    #[cfg(feature = "ebpf_enabled")]
    pub fn with_xdp(rules_path: String) -> anyhow::Result<Self> {
        Self::with_xdp_secure(rules_path, NetshieldSecurityConfig::default())
    }

    /// Secure XDP constructor with explicit security configuration
    #[cfg(feature = "ebpf_enabled")]
    pub fn with_xdp_secure(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
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
    pub fn with_xdp(rules_path: String) -> anyhow::Result<Self> {
        Self::with_xdp_secure(rules_path, NetshieldSecurityConfig::default())
    }

    #[cfg(not(feature = "ebpf_enabled"))]
    pub fn with_xdp_secure(
        rules_path: String,
        security_config: NetshieldSecurityConfig,
    ) -> anyhow::Result<Self> {
        log::warn!("eBPF not available on this platform, falling back to basic mode");
        Ok(Self {
            rules_path,
            bpf: Mutex::new(None),
            attached_links: Mutex::new(Vec::new()),
            security_config,
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
            log::warn!("eBPF not loaded, rules update skipped");
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
}

impl Default for NetshieldModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for NetshieldModule {
    fn init(&self) -> Result<()> {
        let mut module = NetshieldModule::new();
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
