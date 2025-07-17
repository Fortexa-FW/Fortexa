//! Alternative approach: embed pre-compiled eBPF object file

use crate::modules::Module;
use anyhow::Result;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::xdp::XdpLinkId;
use aya::{Ebpf, programs::Xdp};
use bincode::config;
use if_addrs::get_if_addrs;
use std::convert::TryInto;
use std::sync::Mutex;

mod constants;
use constants::{NETSHIELD_PROGRAM_NAME, RULES_MAP_NAME, MAX_RULE_SIZE};

// Embed the eBPF object file at compile time (if available)
#[cfg(feature = "ebpf_enabled")]
const EMBEDDED_EBPF: &[u8] = include_bytes!(env!("NETSHIELD_EBPF_PATH"));

pub struct NetshieldModule {
    pub rules_path: String,
    pub bpf: Mutex<Option<Ebpf>>,
    pub attached_links: Mutex<Vec<XdpLinkId>>,
}

impl NetshieldModule {
    /// Basic constructor (for legacy/tests)
    pub fn new() -> Self {
        NetshieldModule {
            rules_path: "/var/lib/fortexa/netshield_rules.json".to_string(),
            bpf: Mutex::new(None),
            attached_links: Mutex::new(Vec::new()),
        }
    }

    /// Advanced constructor: load eBPF and attach to all interfaces
    #[cfg(feature = "ebpf_enabled")]
    pub fn with_xdp(rules_path: String) -> anyhow::Result<Self> {
        // Load from embedded bytes (most portable)
        let mut bpf = Ebpf::load(EMBEDDED_EBPF)?;
        
        let mut attached_links = Vec::new();
        for iface in get_if_addrs()? {
            let name = iface.name.clone();
            if iface.is_loopback() {
                continue;
            }
            let program: &mut Xdp = bpf.program_mut(NETSHIELD_PROGRAM_NAME).unwrap().try_into()?;
            program.load()?;
            let link_id = program.attach(&name, aya::programs::XdpFlags::default())?;
            attached_links.push(link_id);
        }
        Ok(Self {
            rules_path,
            bpf: Mutex::new(Some(bpf)),
            attached_links: Mutex::new(attached_links),
        })
    }

    /// Fallback constructor when eBPF is not available
    #[cfg(not(feature = "ebpf_enabled"))]
    pub fn with_xdp(rules_path: String) -> anyhow::Result<Self> {
        log::warn!("eBPF not available on this platform, falling back to basic mode");
        Ok(Self {
            rules_path,
            bpf: Mutex::new(None),
            attached_links: Mutex::new(Vec::new()),
        })
    }

    /// Alternative constructor: load from file path (for development)
    #[cfg(feature = "ebpf_enabled")]
    pub fn with_xdp_file(bpf_path: &str, rules_path: String) -> anyhow::Result<Self> {
        let mut bpf = Ebpf::load_file(bpf_path)?;
        let mut attached_links = Vec::new();
        for iface in get_if_addrs()? {
            let name = iface.name.clone();
            if iface.is_loopback() {
                continue;
            }
            let program: &mut Xdp = bpf.program_mut(NETSHIELD_PROGRAM_NAME).unwrap().try_into()?;
            program.load()?;
            let link_id = program.attach(&name, aya::programs::XdpFlags::default())?;
            attached_links.push(link_id);
        }
        Ok(Self {
            rules_path,
            bpf: Mutex::new(Some(bpf)),
            attached_links: Mutex::new(attached_links),
        })
    }

    /// Detach XDP from all interfaces (call on shutdown)
    #[cfg(feature = "ebpf_enabled")]
    pub fn detach_all(self) -> anyhow::Result<()> {
        let attached_links = self.attached_links.into_inner().unwrap();
        for link_id in attached_links {
            let mut bpf = Ebpf::load(EMBEDDED_EBPF)?;
            let program: &mut Xdp = bpf.program_mut(NETSHIELD_PROGRAM_NAME).unwrap().try_into()?;
            program.detach(link_id)?;
        }
        Ok(())
    }

    #[cfg(not(feature = "ebpf_enabled"))]
    pub fn detach_all(self) -> anyhow::Result<()> {
        Ok(()) // No-op when eBPF is not enabled
    }

    /// Update the eBPF rules map with the current rules
    pub fn update_rules_map(&self, rules: &[NetshieldRule]) -> anyhow::Result<()> {
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
                let mut data = [0u8; MAX_RULE_SIZE];
                let config = config::standard();
                let encoded: Vec<u8> = bincode::encode_to_vec(rule, config)?;
                let len = encoded.len().min(MAX_RULE_SIZE);
                data[..len].copy_from_slice(&encoded[..len]);
                rules_map.insert(i as u32, data, 0)?;
            }
        }
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
        // Not used for netshield (eBPF only)
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
