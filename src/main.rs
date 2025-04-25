use fortexa::run;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        // Proper error handling
        eprintln!("Critical firewall error: {}", e);
        std::process::exit(1);
    }
}
