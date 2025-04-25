use fortexa::{
    firewall::iptables::{FirewallManager, IPTablesInterface, IPTablesWrapper},
    rules::FirewallRuleSet
};
use fortexa::api::api_server;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

#[test]
#[ignore = "requires iptables access and root privileges"]
fn integration_test_rule_lifecycle() {
    // 1. Initialize with real IPTables wrapper
    let table = "filter";
    let ipt = IPTablesWrapper::new(false)
        .expect("Should create IPTables wrapper");
    
    // 2. Create firewall manager
    let manager = FirewallManager::new(table, false, ipt)
        .expect("Should initialize firewall manager");

    // 3. Test rule lifecycle
    let rules = FirewallRuleSet::default();
    manager.sync_rules(&rules)
        .expect("Should sync empty rules");
    
    // 4. Cleanup
    manager.delete_rules()
        .expect("Should clean up rules");
}


#[tokio::test]
async fn test_api_server_startup() {
    // 1. Create mock dependencies
    let ipt = IPTablesWrapper::new(false)
        .expect("Should create IPTables wrapper");
    let manager = FirewallManager::new("filter", false, ipt)
        .expect("Should create firewall manager");
    
    let firewall = std::sync::Arc::new(tokio::sync::Mutex::new(manager));
    let rules = std::sync::Arc::new(tokio::sync::Mutex::new(FirewallRuleSet::default()));

    // 2. Test server startup with timeout
    let api_router = api_server::router(
        firewall.clone(),
        rules.clone()
    );

    let mut api_handle = tokio::spawn(async move {
        api_server::run(api_router).await;
    });

    // Wait for server to start or timeout after 1s
    let result = timeout(Duration::from_millis(100), &mut api_handle).await;
    
    // 3. Cleanup
    api_handle.abort();
    assert!(result.is_err(), "Server should stay running until aborted");
}
