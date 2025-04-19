use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, Packet};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::rules::FirewallRuleSet;
use log::{info, error, debug, warn};

pub fn run(rules: Arc<Mutex<FirewallRuleSet>>) {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| !iface.is_loopback() && iface.is_up())
        .expect("No suitable interface found");

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to create datalink channel"),
    };

    info!("[Firewall Daemon] Monitoring on: {}", interface.name);

    loop {
        let current_rules = rules.blocking_lock().clone();

        if let Ok(packet) = rx.next() {
            if let Some(ethernet) = EthernetPacket::new(packet) {
                let payload = ethernet.payload();
                if let Some(ipv4) = Ipv4Packet::new(payload) {
                    // Log INPUT traffic
                    if current_rules.input.blocked_ips.contains(&ipv4.get_source()) {
                        debug!("[BLOCKED INPUT] From: {}", ipv4.get_source());
                    }

                    // Log OUTPUT traffic
                    if current_rules.output.blocked_ips.contains(&ipv4.get_destination()) {
                        debug!("[BLOCKED OUTPUT] To: {}", ipv4.get_destination());
                    }

                    match ipv4.get_next_level_protocol() {
                        // TCP Port Checks
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                let dst_port = tcp.get_destination();
                                if current_rules.input.blocked_ports.contains(&dst_port) {
                                    debug!("[BLOCKED INPUT PORT] TCP/{}", dst_port);
                                }
                                if current_rules.output.blocked_ports.contains(&dst_port) {
                                    debug!("[BLOCKED OUTPUT PORT] TCP/{}", dst_port);
                                }
                            }
                        }
                        // UDP Port Checks (NEW)
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                let dst_port = udp.get_destination();
                                if current_rules.input.blocked_ports.contains(&dst_port) {
                                    debug!("[BLOCKED INPUT PORT] UDP/{}", dst_port);
                                }
                                if current_rules.output.blocked_ports.contains(&dst_port) {
                                    debug!("[BLOCKED OUTPUT PORT] UDP/{}", dst_port);
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
