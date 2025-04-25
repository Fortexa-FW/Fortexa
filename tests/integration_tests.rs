use fortexa::api::api_server;
use fortexa::{
    firewall::iptables::{FirewallManager, IPTablesInterface, IPTablesWrapper},
    rules::FirewallRuleSet,
};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

// Helper to manage test chains
struct TestChain {
    ipt: IPTablesWrapper,
    chain: String,
    table: String,
}

impl TestChain {
    fn new(table: &str, chain: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let ipt = IPTablesWrapper::new(false)?;
        ipt.new_chain(table, chain)?;
        Ok(Self {
            ipt,
            chain: chain.to_string(),
            table: table.to_string(),
        })
    }
}

impl Drop for TestChain {
    fn drop(&mut self) {
        let _ = self.ipt.flush_chain(&self.table, &self.chain);
        let _ = self.ipt.delete_chain(&self.table, &self.chain);
    }
}

#[test]
#[ignore = "requires iptables access and root privileges"]
fn integration_test_rule_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let table = "filter";
    let chain = "fortexa_test";
    let _test_chain = TestChain::new(table, chain)?;

    let ipt = IPTablesWrapper::new(false)?;
    let manager = FirewallManager::new(table, false, ipt).chain(chain)?;

    // Test empty rule sync
    let rules = FirewallRuleSet::default();
    manager.sync_rules(&rules)?;

    // Verify chain is empty
    let current_rules = manager.list_rules()?;
    assert!(current_rules.is_empty(), "Rules should be empty after sync");

    // Test rule deletion
    manager.delete_rules()?;
    let current_rules = manager.list_rules()?;
    assert!(
        current_rules.is_empty(),
        "Rules should remain empty after deletion"
    );

    Ok(())
}

#[tokio::test]
async fn test_api_server_startup() -> Result<(), Box<dyn std::error::Error>> {
    let table = "filter";
    let chain = "fortexa_api_test";
    let _test_chain = TestChain::new(table, chain)?;

    let ipt = IPTablesWrapper::new(false)?;
    let manager = FirewallManager::new(table, false, ipt).chain(chain)?;

    let firewall = Arc::new(Mutex::new(manager));
    let rules = Arc::new(Mutex::new(FirewallRuleSet::default()));

    // Use random port
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let api_router = api_server::router(firewall.clone(), rules.clone());

    let server =
        tokio::spawn(async move { api_server::run_with_listener(listener, api_router).await });

    // Verify server is listening
    let mut attempts = 0;
    loop {
        if TcpStream::connect(addr).is_ok() || attempts >= 5 {
            break;
        }
        attempts += 1;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    assert!(
        TcpStream::connect(addr).is_ok(),
        "Server should be listening on {addr}"
    );

    server.abort();
    let _ = server.await;
    Ok(())
}
