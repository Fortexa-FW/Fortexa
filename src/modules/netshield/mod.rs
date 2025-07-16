//! netshield: eBPF/XDP-based network filtering for Fortexa
//!
//! This module provides network filtering using eBPF/XDP in Rust.
//!
//! The NetshieldModule struct initializes the netshield module.

use crate::modules::Module;
use anyhow::Result;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::xdp::XdpLinkId;
use aya::{Bpf, programs::Xdp};
use bincode::config;
use if_addrs::get_if_addrs;
use std::convert::TryInto;
use std::sync::Mutex;

pub struct NetshieldModule {
    pub bpf: Mutex<Option<Bpf>>,
    pub attached_links: Mutex<Vec<XdpLinkId>>,
}

impl NetshieldModule {
    /// Basic constructor (for legacy/tests)
    pub fn new() -> Self {
        NetshieldModule {
            bpf: Mutex::new(None),
            attached_links: Mutex::new(Vec::new()),
        }
    }

    /// Advanced constructor: load eBPF and attach to all interfaces
    pub fn with_xdp(bpf_path: &str) -> anyhow::Result<Self> {
        let mut bpf = Bpf::load_file(bpf_path)?;
        let mut attached_links = Vec::new();
        for iface in get_if_addrs()? {
            let name = iface.name.clone();
            if iface.is_loopback() {
                continue;
            }
            let program: &mut Xdp = bpf.program_mut("netshield_xdp").unwrap().try_into()?;
            program.load()?;
            let link_id = program.attach(&name, aya::programs::XdpFlags::default())?;
            attached_links.push(link_id);
        }
        Ok(Self {
            bpf: Mutex::new(Some(bpf)),
            attached_links: Mutex::new(attached_links),
        })
    }

    /// Detach XDP from all interfaces (call on shutdown)
    pub fn detach_all(self, bpf_path: &str) -> anyhow::Result<()> {
        let attached_links = self.attached_links.into_inner().unwrap();
        for link_id in attached_links {
            let mut bpf = Bpf::load_file(bpf_path)?;
            let program: &mut Xdp = bpf.program_mut("netshield_xdp").unwrap().try_into()?;
            program.detach(link_id)?;
        }
        Ok(())
    }

    /// Update the eBPF rules map with the current rules
    pub fn update_rules_map(&self, rules: &[NetshieldRule]) -> anyhow::Result<()> {
        if let Some(bpf) = &mut *self.bpf.lock().unwrap() {
            let mut rules_map: BpfHashMap<_, u32, [u8; 256]> = BpfHashMap::try_from(
                bpf.map_mut("rules_map")
                    .ok_or_else(|| anyhow::anyhow!("rules_map not found"))?,
            )?;
            // Clear the map first
            let keys: Vec<u32> = rules_map.keys().collect::<Result<_, _>>()?;
            for key in keys {
                rules_map.remove(&key)?;
            }
            // Insert each rule (serialize to [u8; 256])
            for (i, rule) in rules.iter().enumerate() {
                let mut data = [0u8; 256];
                let config = config::standard();
                let encoded: Vec<u8> = bincode::encode_to_vec(rule, config)?;
                let len = encoded.len().min(256);
                data[..len].copy_from_slice(&encoded[..len]);
                rules_map.insert(i as u32, data, 0)?;
            }
        }
        Ok(())
    }

    /// Remove a rule from the eBPF rules map by index
    pub fn remove_rule_from_map(&self, index: u32) -> anyhow::Result<()> {
        if let Some(bpf) = &mut *self.bpf.lock().unwrap() {
            let mut rules_map: BpfHashMap<_, u32, [u8; 256]> = BpfHashMap::try_from(
                bpf.map_mut("rules_map")
                    .ok_or_else(|| anyhow::anyhow!("rules_map not found"))?,
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
        crate::modules::netshield::apply_all_rules(self).map_err(anyhow::Error::msg)?;
        Ok(())
    }

    fn apply_rules(&self, _rules: &[crate::core::rules::Rule]) -> Result<()> {
        // Not used for netshield (iptables only)
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub mod filter;

pub use filter::{
    Action, Direction, NetshieldRule, add_rule, apply_all_rules, delete_rule, get_groups, get_rule,
    get_rules, get_rules_by_group, update_rule,
};
