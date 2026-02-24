use std::path::PathBuf;

use clap::{Parser, Subcommand};

use riley_auth_core::config::{validate_scope_name, SigningAlgorithm};
use riley_auth_core::db;
use riley_auth_core::jwt::{self, KeySet};
use riley_auth_core::webhooks;

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
    /// Generate keypair for JWT signing
    GenerateKeys {
        /// Output directory for key files
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        /// Signing algorithm (es256 or rs256)
        #[arg(short, long, default_value = "es256")]
        algorithm: String,
        /// RSA key size in bits (only used with rs256)
        #[arg(long)]
        key_size: Option<u32>,
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
        /// Allowed scopes for this client (e.g. read:profile write:profile)
        #[arg(long, num_args = 0..)]
        scopes: Vec<String>,
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
    /// List registered webhooks
    ListWebhooks,
    /// Register a new webhook
    RegisterWebhook {
        /// URL to deliver events to
        url: String,
        /// Event types to subscribe to (e.g. user.created user.deleted)
        #[arg(required = true, num_args = 1..)]
        events: Vec<String>,
        /// Optional client ID to scope webhook to
        #[arg(long)]
        client_id: Option<uuid::Uuid>,
    },
    /// Remove a webhook
    RemoveWebhook {
        /// Webhook ID to remove
        id: uuid::Uuid,
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
    if let Command::GenerateKeys { output, algorithm, key_size } = cli.command {
        let alg = match algorithm.to_lowercase().as_str() {
            "es256" => SigningAlgorithm::ES256,
            "rs256" => SigningAlgorithm::RS256,
            other => anyhow::bail!("unsupported algorithm '{}' (expected es256 or rs256)", other),
        };
        jwt::generate_keypair_with_algorithm(&output, alg, key_size)?;
        return Ok(());
    }

    let config = riley_auth_core::config::resolve_config(cli.config.as_deref())?;
    let pool = db::connect(&config.database).await?;

    match cli.command {
        Command::Serve => {
            db::migrate(&pool).await?;
            tracing::info!("migrations complete");
            let keys = KeySet::from_configs(&config.jwt.resolved_keys()?)?;
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
            let _keys = KeySet::from_configs(&config.jwt.resolved_keys()?)?;
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
            // Dispatch back-channel logout BEFORE deleting tokens
            dispatch_backchannel_logout_cli(&config, &pool, user.id).await;
            db::delete_all_refresh_tokens(&pool, user.id).await?;
            println!("All refresh tokens revoked for {}", username);
        }
        Command::Delete { username } => {
            let user = db::find_user_by_username(&pool, &username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("user '{}' not found", username))?;
            // Dispatch back-channel logout BEFORE soft delete (which deletes tokens)
            dispatch_backchannel_logout_cli(&config, &pool, user.id).await;
            match db::soft_delete_user(&pool, user.id).await? {
                db::DeleteUserResult::Deleted => println!("User {} deleted (anonymized)", username),
                db::DeleteUserResult::LastAdmin => {
                    anyhow::bail!("cannot delete '{}' — they are the last admin", username);
                }
                db::DeleteUserResult::NotFound => {
                    anyhow::bail!("user '{}' was already deleted", username);
                }
            }
        }
        Command::RegisterClient { name, redirect_uris, scopes, auto_approve } => {
            // Validate redirect_uris
            for uri in &redirect_uris {
                let parsed = url::Url::parse(uri)
                    .map_err(|_| anyhow::anyhow!("invalid redirect_uri: {}", uri))?;
                match parsed.scheme() {
                    "https" => {}
                    "http" if matches!(parsed.host_str(), Some("localhost") | Some("127.0.0.1")) => {}
                    scheme => {
                        anyhow::bail!(
                            "redirect_uri must use https (or http://localhost for development), got {}://",
                            scheme
                        );
                    }
                }
            }

            // Validate scopes: format + existence in config definitions
            let defined_names: Vec<&str> = config.scopes.definitions.iter()
                .map(|d| d.name.as_str())
                .collect();
            for scope in &scopes {
                validate_scope_name(scope)
                    .map_err(|e| anyhow::anyhow!("invalid scope name '{}': {}", scope, e))?;
                if !defined_names.contains(&scope.as_str()) {
                    anyhow::bail!("undefined scope '{}' — not found in config scopes.definitions", scope);
                }
            }

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
                &scopes,
                auto_approve,
            )
            .await?;

            println!("Client registered:");
            println!("  ID:             {}", client.id);
            println!("  Name:           {}", client.name);
            println!("  Client ID:      {}", client_id);
            println!("  Client Secret:  {}", client_secret);
            println!("  Redirect URIs:  {:?}", client.redirect_uris);
            println!("  Allowed Scopes: {:?}", client.allowed_scopes);
            println!("  Auto-approve:   {}", client.auto_approve);
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
        Command::ListWebhooks => {
            let hooks = db::list_webhooks(&pool).await?;
            if hooks.is_empty() {
                println!("No webhooks registered.");
            } else {
                println!("{:<38} {:<40} {:<8} {}", "ID", "URL", "Active", "Events");
                println!("{}", "-".repeat(100));
                for hook in &hooks {
                    println!(
                        "{:<38} {:<40} {:<8} {}",
                        hook.id,
                        if hook.url.len() > 38 { &hook.url[..hook.url.floor_char_boundary(38)] } else { &hook.url },
                        hook.active,
                        hook.events.join(", "),
                    );
                }
                println!("\n{} webhook(s)", hooks.len());
            }
        }
        Command::RegisterWebhook { url, events, client_id } => {
            // Validate URL scheme (same rules as the API endpoint)
            let parsed_url = url::Url::parse(&url)
                .map_err(|_| anyhow::anyhow!("invalid webhook URL"))?;
            match parsed_url.scheme() {
                "https" | "http" => {}
                _ => anyhow::bail!("webhook URL must use https:// or http://"),
            }
            for event in &events {
                if !webhooks::is_valid_event_type(event) {
                    anyhow::bail!("unknown event type: {}", event);
                }
            }

            let mut secret_bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret_bytes);
            let secret = hex::encode(secret_bytes);

            let hook = db::create_webhook(&pool, client_id, &url, &events, &secret).await?;

            println!("Webhook registered:");
            println!("  ID:     {}", hook.id);
            println!("  URL:    {}", hook.url);
            println!("  Events: {:?}", hook.events);
            println!("  Secret: {}", secret);
            println!("\nSave the secret — it cannot be retrieved later.");
        }
        Command::RemoveWebhook { id } => {
            let deleted = db::delete_webhook(&pool, id).await?;
            if deleted {
                println!("Webhook {} removed", id);
            } else {
                anyhow::bail!("webhook {} not found", id);
            }
        }
        Command::GenerateKeys { .. } => unreachable!(),
    }

    Ok(())
}

/// Best-effort backchannel logout dispatch for CLI commands.
/// Loads JWT keys and builds an HTTP client, then dispatches.
/// Warns and continues if keys are unavailable (e.g., CLI on a box without signing keys).
async fn dispatch_backchannel_logout_cli(
    config: &riley_auth_core::config::Config,
    pool: &sqlx::PgPool,
    user_id: uuid::Uuid,
) {
    let key_configs = match config.jwt.resolved_keys() {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("skipping backchannel logout (cannot resolve JWT key config: {e})");
            return;
        }
    };
    let keys = match KeySet::from_configs(&key_configs) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("skipping backchannel logout (cannot load JWT keys: {e})");
            return;
        }
    };
    let http_client = webhooks::build_webhook_client(config.webhooks.allow_private_ips);
    webhooks::dispatch_backchannel_logout(pool, &keys, config, &http_client, user_id).await;
}
