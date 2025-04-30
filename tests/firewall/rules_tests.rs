use fortexa::firewall::rules_core::RulesManager;
use ipnetwork::Ipv4Network;
use std::str::FromStr;

#[tokio::test]
async fn test_rules_initialization() {
    // Test rules manager initialization
    let rules = RulesManager::new();
    assert!(rules.is_ok(), "Rules manager should initialize successfully");
}

#[tokio::test]
async fn test_rules_operations() {
    let rules = RulesManager::new().unwrap();
    
    // Get a reference to the iptables rules set
    let iptables_rules = rules.get_iptables_rules();
    
    // Create a modified version of the rules
    let mut modified_rules = iptables_rules.clone();
    
    // Note the initial state - don't assume it's empty
    let initial_blocked_ips_count = modified_rules.input.blocked_ips.len();
    let initial_blocked_ports_count = modified_rules.input.blocked_ports.len();
    
    // Create IP network for testing
    let test_ip = Ipv4Network::from_str("192.168.1.1/32").unwrap();
    let test_port = 8080u16;
    
    // Check if the IP already exists before adding it
    let ip_already_present = modified_rules.input.blocked_ips.contains(&test_ip);
    
    // Add a blocked IP
    modified_rules.input.blocked_ips.insert(test_ip);
    assert!(modified_rules.input.blocked_ips.contains(&test_ip), "IP should be in blocked list");
    
    // Count should increase only if the IP wasn't already there
    let expected_ip_count = if ip_already_present {
        initial_blocked_ips_count
    } else {
        initial_blocked_ips_count + 1
    };
    assert_eq!(modified_rules.input.blocked_ips.len(), expected_ip_count, 
               "Blocked IPs count should be {} after insertion", expected_ip_count);
    
    // Check if the port already exists before adding it
    let port_already_present = modified_rules.input.blocked_ports.contains(&test_port);
    
    // Add a blocked port
    modified_rules.input.blocked_ports.insert(test_port);
    assert!(modified_rules.input.blocked_ports.contains(&test_port), "Port should be in blocked list");
    
    // Count should increase only if the port wasn't already there
    let expected_port_count = if port_already_present {
        initial_blocked_ports_count
    } else {
        initial_blocked_ports_count + 1
    };
    assert_eq!(modified_rules.input.blocked_ports.len(), expected_port_count,
               "Blocked ports count should be {} after insertion", expected_port_count);
    
    // Add a whitelisted IP
    let whitelist_ip = Ipv4Network::from_str("10.0.0.1/32").unwrap();
    modified_rules.input.whitelisted_ips.insert(whitelist_ip);
    assert!(modified_rules.input.whitelisted_ips.contains(&whitelist_ip), "IP should be in whitelist");
    
    // Add a whitelisted port
    let whitelist_port = 443u16;
    modified_rules.input.whitelisted_ports.insert(whitelist_port);
    assert!(modified_rules.input.whitelisted_ports.contains(&whitelist_port), "Port should be in whitelist");
    
    // Remove rules
    modified_rules.input.blocked_ips.remove(&test_ip);
    assert!(!modified_rules.input.blocked_ips.contains(&test_ip), "IP should be removed from blocked list");
    
    modified_rules.input.blocked_ports.remove(&test_port);
    assert!(!modified_rules.input.blocked_ports.contains(&test_port), "Port should be removed from blocked list");
    
    // Test output rules operations
    let output_ip = Ipv4Network::from_str("172.16.0.1/32").unwrap();
    
    modified_rules.output.blocked_ips.insert(output_ip);
    assert!(modified_rules.output.blocked_ips.contains(&output_ip), "IP should be in output blocked list");
    
    // Test removing all rules from a category
    modified_rules.output.blocked_ips.clear();
    assert!(modified_rules.output.blocked_ips.is_empty(), "Output blocked IPs should be empty after clear");
    assert_eq!(modified_rules.output.blocked_ips.len(), 0, 
               "Expected 0 IPs after clear, got {}", modified_rules.output.blocked_ips.len());
} 