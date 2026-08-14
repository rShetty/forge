use clap::{Parser, Subcommand};
use forge::config::Config;

#[derive(Parser)]
#[command(name = "forge")]
#[command(about = "Agent supply chain security — code signing, SBOM, vulnerability scanning")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    Init,
    GenerateKeys,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "forge=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            let config = Config::default();
            let toml = toml::to_string_pretty(&config)?;
            std::fs::write("config.toml", toml)?;
            println!("Created config.toml");
        }
        Commands::Serve { config } => {
            let config = Config::load(&config).unwrap_or_default();
            forge::api::server::run(config).await?;
        }
        Commands::GenerateKeys => {
            let kp = forge::signing::SigningEngine::generate_keypair();
            println!("Public key:  {}", kp.public_key);
            println!("Private key: {}", kp.private_key);
            println!("\nSave the private key securely — it will not be shown again.");
        }
    }

    Ok(())
}
