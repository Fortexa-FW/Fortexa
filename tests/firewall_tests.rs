use fortexa::{
    firewall::iptables::{FirewallError, FirewallManager, IPTablesInterface, IPTablesWrapper},
    rules::{FirewallDirectionRules, FirewallRuleSet},
};
use ipnetwork::Ipv4Network;
use std::str::FromStr;

struct TestEnvironment {
    _chain: TestChain,
    manager: FirewallManager<IPTablesWrapper>,
}

impl TestEnvironment {
    fn new(table: &str, chain: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let test_chain = TestChain::new(table, chain)?;
        let ipt = IPTablesWrapper::new(false)?;
        let manager = FirewallManager::new(table, false, ipt)?.chain(chain)?;

        Ok(Self {
            _chain: test_chain,
            manager,
        })
    }
}

#[test]
#[ignore = "requires iptables access and root privileges"]
fn test_create_firewall_manager_success() -> Result<(), Box<dyn std::error::Error>> {
    let table = "filter";
    let chain = "fortexa_create_test";
    let _env = TestEnvironment::new(table, chain)?;
    Ok(())
}

#[test]
#[ignore = "requires iptables access and root privileges"]
fn test_sync_rules_orders_whitelist_first() -> Result<(), Box<dyn std::error::Error>> {
    let table = "filter";
    let chain = "fortexa_order_test";
    let env = TestEnvironment::new(table, chain)?;
    let rules = sample_rules();

    env.manager.sync_rules(&rules)?;

    let current_rules = env.manager.list_rules()?;
    let accept_pos = current_rules.iter().position(|r| r.contains("ACCEPT"));
    let drop_pos = current_rules.iter().position(|r| r.contains("DROP"));

    assert!(
        accept_pos < drop_pos,
        "Whitelist rules should come before block rules\n\
         Rules: {:?}",
        current_rules
    );

    Ok(())
}

#[test]
#[ignore = "requires iptables access and root privileges"]
fn test_delete_rules_cleans_up_chains() -> Result<(), Box<dyn std::error::Error>> {
    let table = "filter";
    let chain = "fortexa_cleanup_test";
    let env = TestEnvironment::new(table, chain)?;

    env.manager.delete_rules()?;

    let current_rules = env.manager.list_rules()?;
    assert!(
        current_rules.is_empty(),
        "Rules should be empty after deletion"
    );

    Ok(())
}

#[test]
#[ignore = "requires iptables access and root privileges"]
fn test_blocked_ips_with_cidr() -> Result<(), Box<dyn std::error::Error>> {
    let table = "filter";
    let chain = "fortexa_cidr_test";
    let env = TestEnvironment::new(table, chain)?;

    let mut rules = FirewallRuleSet::default();
    rules
        .input
        .blocked_ips
        .insert(Ipv4Network::from_str("192.168.0.0/24")?);

    env.manager.sync_rules(&rules)?;

    let current_rules = env.manager.list_rules()?;
    assert!(
        current_rules.iter().any(|r| r.contains("192.168.0.0/24")),
        "Should find CIDR rule in: {:?}",
        current_rules
    );

    Ok(())
}

#[test]
#[ignore = "requires iptables access and root privileges"]
fn test_whitelist_priority() -> Result<(), Box<dyn std::error::Error>> {
    let table = "filter";
    let chain = "fortexa_priority_test";
    let env = TestEnvironment::new(table, chain)?;

    let mut rules = FirewallRuleSet::default();
    let ip = Ipv4Network::from_str("192.168.1.100/32")?;
    rules.input.whitelisted_ips.insert(ip.clone());
    rules.input.blocked_ips.insert(ip);

    env.manager.sync_rules(&rules)?;

    let current_rules = env.manager.list_rules()?;
    let accept_count = current_rules
        .iter()
        .filter(|r| r.contains("ACCEPT"))
        .count();
    let drop_count = current_rules.iter().filter(|r| r.contains("DROP")).count();

    assert_eq!(accept_count, 1, "Should have exactly one ACCEPT rule");
    assert_eq!(
        drop_count, 0,
        "Should have no DROP rules for whitelisted IP"
    );

    Ok(())
}

#[test]
#[ignore = "requires iptables access and root privileges"]
fn test_invalid_table_initialization() {
    let result = FirewallManager::new("invalid_table", false, IPTablesWrapper::new(false).unwrap());
    assert!(
        matches!(result, Err(FirewallError::ExecutionError(_))),
        "Should fail with invalid table"
    );
}

// Reuse TestChain implementation from previous answer
// Reuse sample_rules() implementation from original code
