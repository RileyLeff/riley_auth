use std::path::PathBuf;

use clap::{Parser, Subcommand};

use riley_auth_core::db;
use riley_auth_core::jwt::{self, Keys};

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
    /// List all users
    ListUsers,
    /// Promote a user to admin
    Promote {
        /// Username to promote
        username: String,
    },
    /// Demote a user back to regular user
    Demote {
        /// Username to demote
        username: String,
    },
    /// Revoke all refresh tokens for a user
    Revoke {
        /// Username whose tokens to revoke
        username: String,
    },
    /// Delete (anonymize) a user
    Delete {
        /// Username to delete
        username: String,
    },
    /// Register a new OAuth client
    RegisterClient {
        /// Client display name
        name: String,
        /// Allowed redirect URI(s)
        #[arg(required = true, num_args = 1..)]
        redirect_uris: Vec<String>,
        /// Skip consent screen for this client
        #[arg(long)]
        auto_approve: bool,
    },
    /// List registered OAuth clients
    ListClients,
    /// Remove an OAuth client
    RemoveClient {
        /// Client ID to remove
        client_id: String,
    },
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

    // generate-keys doesn't need config or db
    if let Command::GenerateKeys { output } = cli.command {
        jwt::generate_keypair(&output)?;
        return Ok(());
    }

    let config = riley_auth_core::config::resolve_config(cli.config.as_deref())?;
    let pool = db::connect(&config.database).await?;

    match cli.command {
        Command::Serve => {
            db::migrate(&pool).await?;
            tracing::info!("migrations complete");
            let keys = Keys::from_pem_files(
                &config.jwt.private_key_path,
                &config.jwt.public_key_path,
            )?;
            riley_auth_api::serve(config, pool, keys).await?;
        }
        Command::Migrate => {
            db::migrate(&pool).await?;
            tracing::info!("migrations complete");
        }
        Command::Validate => {
            tracing::info!("config loaded successfully");
            sqlx::query("SELECT 1").execute(&pool).await?;
            tracing::info!("database connection successful");
            let _keys = Keys::from_pem_files(
                &config.jwt.private_key_path,
                &config.jwt.public_key_path,
            )?;
            tracing::info!("JWT keys loaded successfully");
        }
        Command::ListUsers => {
            let users = db::list_users(&pool, 100, 0).await?;
            if users.is_empty() {
                println!("No users found.");
            } else {
                println!("{:<38} {:<24} {:<6} {}", "ID", "Username", "Role", "Created");
                println!("{}", "-".repeat(90));
                for user in &users {
                    println!(
                        "{:<38} {:<24} {:<6} {}",
                        user.id, user.username, user.role,
                        user.created_at.format("%Y-%m-%d %H:%M"),
                    );
                }
                println!("\n{} user(s)", users.len());
            }
        }
        Command::Promote { username } => {
            let user = db::find_user_by_username(&pool, &username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("user '{}' not found", username))?;
            match db::update_user_role(&pool, user.id, "admin").await? {
                db::RoleUpdateResult::Updated(_) => println!("{} promoted to admin", username),
                db::RoleUpdateResult::LastAdmin => unreachable!("promoting cannot hit last-admin guard"),
                db::RoleUpdateResult::NotFound => {
                    anyhow::bail!("user '{}' not found", username);
                }
            }
        }
        Command::Demote { username } => {
            let user = db::find_user_by_username(&pool, &username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("user '{}' not found", username))?;
            match db::update_user_role(&pool, user.id, "user").await? {
                db::RoleUpdateResult::Updated(_) => println!("{} demoted to user", username),
                db::RoleUpdateResult::LastAdmin => {
                    anyhow::bail!("cannot demote '{}' — they are the last admin", username);
                }
                db::RoleUpdateResult::NotFound => {
                    anyhow::bail!("user '{}' not found", username);
                }
            }
        }
        Command::Revoke { username } => {
            let user = db::find_user_by_username(&pool, &username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("user '{}' not found", username))?;
            db::delete_all_refresh_tokens(&pool, user.id).await?;
            println!("All refresh tokens revoked for {}", username);
        }
        Command::Delete { username } => {
            let user = db::find_user_by_username(&pool, &username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("user '{}' not found", username))?;
            let deleted = db::soft_delete_user(&pool, user.id).await?;
            if !deleted {
                anyhow::bail!("user '{}' was already deleted", username);
            }
            println!("User {} deleted (anonymized)", username);
        }
        Command::RegisterClient { name, redirect_uris, auto_approve } => {
            // Generate client_id and client_secret
            let mut id_bytes = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut id_bytes);
            let client_id = hex::encode(id_bytes);

            let mut secret_bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret_bytes);
            let client_secret = hex::encode(secret_bytes);
            let secret_hash = jwt::hash_token(&client_secret);

            let client = db::create_client(
                &pool,
                &name,
                &client_id,
                &secret_hash,
                &redirect_uris,
                auto_approve,
            )
            .await?;

            println!("Client registered:");
            println!("  ID:            {}", client.id);
            println!("  Name:          {}", client.name);
            println!("  Client ID:     {}", client_id);
            println!("  Client Secret: {}", client_secret);
            println!("  Redirect URIs: {:?}", client.redirect_uris);
            println!("  Auto-approve:  {}", client.auto_approve);
            println!("\nSave the client secret — it cannot be retrieved later.");
        }
        Command::ListClients => {
            let clients = db::list_clients(&pool).await?;
            if clients.is_empty() {
                println!("No clients registered.");
            } else {
                println!("{:<38} {:<24} {:<34} {}", "ID", "Name", "Client ID", "Auto-approve");
                println!("{}", "-".repeat(100));
                for client in &clients {
                    println!(
                        "{:<38} {:<24} {:<34} {}",
                        client.id, client.name, client.client_id, client.auto_approve,
                    );
                }
                println!("\n{} client(s)", clients.len());
            }
        }
        Command::RemoveClient { client_id } => {
            let client = db::find_client_by_client_id(&pool, &client_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("client '{}' not found", client_id))?;
            db::delete_client(&pool, client.id).await?;
            println!("Client '{}' ({}) removed", client.name, client_id);
        }
        Command::GenerateKeys { .. } => unreachable!(),
    }

    Ok(())
}
