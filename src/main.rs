use anyhow::Result;
use fortexa::core::engine::Engine;
use fortexa::services::rest::RestService;
use log::info;

const DEFAULT_CONFIG_PATH: &str = "/etc/fortexa/config.toml";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("Fortexa Firewall starting...");

    // Initialize the engine
    let engine = Engine::new(DEFAULT_CONFIG_PATH)?;

    // Register all modules
    engine.register_all_modules()?;

    // Apply rules from rules.json to iptables at startup
    engine.apply_rules()?;

    // Start services in foreground
    run_services(engine).await?;

    Ok(())
}

async fn run_services(engine: Engine) -> Result<()> {
    // Start the REST API service
    let rest_service = RestService::new(engine.clone());
    let rest_handle =
        tokio::spawn(async move { rest_service.run(Box::pin(std::future::pending())).await });

    // Wait for the services to exit
    let _ = rest_handle.await?;

    Ok(())
}
