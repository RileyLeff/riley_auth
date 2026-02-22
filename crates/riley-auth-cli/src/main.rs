use std::path::PathBuf;

use clap::{Parser, Subcommand};

use riley_auth_core::jwt::Keys;

#[derive(Parser)]
#[command(name = "riley-auth", about = "OAuth-only identity service")]
struct Cli {
    /// Path to config file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the HTTP server
    Serve,
    /// Run database migrations
    Migrate,
    /// Generate RS256 keypair for JWT signing
    GenerateKeys {
        /// Output directory for key files
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
    /// Check config and database connectivity
    Validate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "riley_auth=info,tower_http=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    // generate-keys doesn't need config
    if let Command::GenerateKeys { output } = cli.command {
        riley_auth_core::jwt::generate_keypair(&output)?;
        return Ok(());
    }

    let config = riley_auth_core::config::resolve_config(cli.config.as_deref())?;

    match cli.command {
        Command::Serve => {
            let db = riley_auth_core::db::connect(&config.database).await?;
            riley_auth_core::db::migrate(&db).await?;
            tracing::info!("migrations complete");
            let keys = Keys::from_pem_files(
                &config.jwt.private_key_path,
                &config.jwt.public_key_path,
            )?;
            riley_auth_api::serve(config, db, keys).await?;
        }
        Command::Migrate => {
            let db = riley_auth_core::db::connect(&config.database).await?;
            riley_auth_core::db::migrate(&db).await?;
            tracing::info!("migrations complete");
        }
        Command::Validate => {
            tracing::info!("config loaded successfully");
            let db = riley_auth_core::db::connect(&config.database).await?;
            sqlx::query("SELECT 1").execute(&db).await?;
            tracing::info!("database connection successful");
            let _keys = Keys::from_pem_files(
                &config.jwt.private_key_path,
                &config.jwt.public_key_path,
            )?;
            tracing::info!("JWT keys loaded successfully");
        }
        Command::GenerateKeys { .. } => unreachable!(),
    }

    Ok(())
}
