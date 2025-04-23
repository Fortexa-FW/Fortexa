use crate::rules::FirewallRuleSet;
use log::{debug, error, info, warn};
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::{
    Packet, ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket,
    udp::UdpPacket,
};
use std::sync::Arc;
use std::thread;
use tokio::sync::Mutex;

pub fn run(rules: Arc<Mutex<FirewallRuleSet>>) {
    let interfaces = datalink::interfaces()
        .into_iter()
        .filter(|iface| !iface.is_loopback() && iface.is_up())
        .collect::<Vec<_>>();

    for iface in interfaces {
        let rules = Arc::clone(&rules);
        let iface_name = iface.name.clone();

        // Spawn a thread for each interface
        thread::spawn(move || {
            monitor_interface(iface, rules, iface_name);
        });
    }
    // Block main thread so daemon doesn't exit
    loop {
        std::thread::park();
    }
}

fn monitor_interface(
    interface: NetworkInterface,
    rules: Arc<Mutex<FirewallRuleSet>>,
    iface_name: String,
) {
    match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_tx, mut rx)) => {
            info!("[Firewall Daemon] Monitoring on: {}", iface_name);
            loop {
                let current_rules = rules.blocking_lock().clone();
                if let Ok(packet) = rx.next() {
                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        let payload = ethernet.payload();
                        if let Some(ipv4) = Ipv4Packet::new(payload) {
                            // Log INPUT traffic
                            if current_rules
                                .input
                                .blocked_ips
                                .iter()
                                .any(|network| network.contains(ipv4.get_source()))
                            {
                                debug!(
                                    "[{}][BLOCKED INPUT] From: {}",
                                    iface_name,
                                    ipv4.get_source()
                                );
                            }

                            // Log OUTPUT traffic
                            if current_rules
                                .output
                                .blocked_ips
                                .iter()
                                .any(|network| network.contains(ipv4.get_destination()))
                            {
                                debug!(
                                    "[{}][BLOCKED OUTPUT] To: {}",
                                    iface_name,
                                    ipv4.get_destination()
                                );
                            }

                            match ipv4.get_next_level_protocol() {
                                // TCP Port Checks
                                IpNextHeaderProtocols::Tcp => {
                                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                        let dst_port = tcp.get_destination();
                                        if current_rules.input.blocked_ports.contains(&dst_port) {
                                            debug!(
                                                "[{}][BLOCKED INPUT PORT] TCP/{}",
                                                iface_name, dst_port
                                            );
                                        }
                                        if current_rules.output.blocked_ports.contains(&dst_port) {
                                            debug!(
                                                "[{}][BLOCKED OUTPUT PORT] TCP/{}",
                                                iface_name, dst_port
                                            );
                                        }
                                    }
                                }
                                // UDP Port Checks (NEW)
                                IpNextHeaderProtocols::Udp => {
                                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                        let dst_port = udp.get_destination();
                                        if current_rules.input.blocked_ports.contains(&dst_port) {
                                            debug!(
                                                "[{}][BLOCKED INPUT PORT] UDP/{}",
                                                iface_name, dst_port
                                            );
                                        }
                                        if current_rules.output.blocked_ports.contains(&dst_port) {
                                            debug!(
                                                "[{}][BLOCKED OUTPUT PORT] UDP/{}",
                                                iface_name, dst_port
                                            );
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        Ok(_) => {
            warn!("[Firewall Daemon] Unknown channel type for {}", iface_name);
        }
        Err(e) => {
            error!(
                "[Firewall Daemon] Could not create channel on {}: {}",
                iface_name, e
            );
        }
    }
}
