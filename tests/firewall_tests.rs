use fortexa::{
    firewall::iptables::{FirewallError, FirewallManager, IPTablesInterface, MockIPTablesInterface},
    rules::{FirewallDirectionRules, FirewallRuleSet}
};
use ipnetwork::Ipv4Network;
use mockall::predicate::*;
use mockall::Sequence;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

// Helper to create mock IPTables interface (removed #[test] attribute)
fn create_mock_iptables() -> MockIPTablesInterface {
    let mut mock = Arc::new(Mutex::new(MockIPTablesInterface::new(false)));
    
    // Set default expectations for chain operations
    mock.expect_new_chain()
        .returning(|_, _| Ok(()));
    
    mock.expect_insert()
        .returning(|_, _, _, _| Ok(()));
    
    mock.expect_append()
        .returning(|_, _, _| Ok(()));
    
    mock.expect_delete_chain()
        .returning(|_, _| Ok(()));
    
    mock
}

fn sample_rules() -> FirewallRuleSet {
    FirewallRuleSet {
        input: FirewallDirectionRules {
            blocked_ips: [Ipv4Network::from_str("192.168.1.100/32").unwrap()].into(),
            blocked_ports: [22].into(),
            whitelisted_ips: [Ipv4Network::from_str("10.0.0.5/32").unwrap()].into(),
            whitelisted_ports: [443].into(),
        },
        output: FirewallDirectionRules::default(),
    }
}

#[test]
fn test_create_firewall_manager_success() {
    let mock_ipt = create_mock_iptables();
    let manager = FirewallManager::new("filter", false, mock_ipt);
    assert!(manager.is_ok());
}

#[test]
fn test_sync_rules_orders_whitelist_first() {
    let mut mock_ipt = create_mock_iptables();
    let mut seq = Sequence::new();

    // Expect whitelist rule first
    mock_ipt.expect_append()
        .with(eq("filter"), eq("FORTEXA_INPUT"), eq("-s 10.0.0.5/32 -j ACCEPT"))
        .times(1)
        .in_sequence(&mut seq)
        .returning(|_, _, _| Ok(()));

    // Then block rule
    mock_ipt.expect_append()
        .with(eq("filter"), eq("FORTEXA_INPUT"), eq("-s 192.168.1.100/32 -j DROP"))
        .times(1)
        .in_sequence(&mut seq)
        .returning(|_, _, _| Ok(()));

    let manager = FirewallManager::new("filter", false, mock_ipt).unwrap();
    let rules = sample_rules();
    assert!(manager.sync_rules(&rules).is_ok());
}

#[test]
fn test_delete_rules_cleans_up_chains() {
    let mut mock_ipt = create_mock_iptables();
    
    mock_ipt.expect_delete_chain()
        .with(eq("filter"), eq("FORTEXA_INPUT"))
        .times(1)
        .returning(|_, _| Ok(()));
    
    mock_ipt.expect_delete_chain()
        .with(eq("filter"), eq("FORTEXA_OUTPUT"))
        .times(1)
        .returning(|_, _| Ok(()));

    let manager = FirewallManager::new("filter", false, mock_ipt).unwrap();
    assert!(manager.delete_rules().is_ok());
}

#[test]
fn test_sync_rules_propagates_errors() {
    let mut mock_ipt = create_mock_iptables();
    
    mock_ipt.expect_append()
        .returning(|_, _, _| Err("mock error".to_string()));

    let manager = FirewallManager::new("filter", false, mock_ipt).unwrap();
    let result = manager.sync_rules(&FirewallRuleSet::default());
    assert!(matches!(result, Err(FirewallError::ExecutionError(_))));
}

#[test]
fn test_blocked_ips_with_cidr() {
    let mut mock_ipt = create_mock_iptables();
    
    mock_ipt.expect_append()
        .with(eq("filter"), eq("FORTEXA_INPUT"), eq("-s 192.168.0.0/24 -j DROP"))
        .times(1)
        .returning(|_, _, _| Ok(()));

    let mut rules = FirewallRuleSet::default();
    rules.input.blocked_ips.insert(Ipv4Network::from_str("192.168.0.0/24").unwrap());
    
    let manager = FirewallManager::new("filter", false, mock_ipt).unwrap();
    assert!(manager.sync_rules(&rules).is_ok());
}

#[test]
fn test_whitelist_priority() {
    let mut mock_ipt = create_mock_iptables();
    
    // Should only see ACCEPT rule, no DROP
    mock_ipt.expect_append()
        .with(eq("filter"), eq("FORTEXA_INPUT"), eq("-s 192.168.1.100/32 -j ACCEPT"))
        .times(1)
        .returning(|_, _, _| Ok(()));

    mock_ipt.expect_append()
        .with(eq("filter"), eq("FORTEXA_INPUT"), eq("-s 192.168.1.100/32 -j DROP"))
        .times(0);

    let mut rules = FirewallRuleSet::default();
    let ip = Ipv4Network::from_str("192.168.1.100/32").unwrap();
    rules.input.whitelisted_ips.insert(ip.clone());
    rules.input.blocked_ips.insert(ip);
    
    let manager = FirewallManager::new("filter", false, mock_ipt).unwrap();
    assert!(manager.sync_rules(&rules).is_ok());
}

#[test]
fn test_invalid_table_initialization() {
    let mut mock_ipt = create_mock_iptables();
    
    mock_ipt.expect_new_chain()
        .returning(|_, _| Err("Invalid table".to_string()));

    let result = FirewallManager::new("invalid", false, mock_ipt);
    assert!(matches!(result, Err(FirewallError::ExecutionError(_))));
}
