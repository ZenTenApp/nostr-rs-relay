//! Configuration file and settings management
use crate::payment::Processor;
use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(unused)]
pub struct Info {
    pub relay_url: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub pubkey: Option<String>,
    pub contact: Option<String>,
    pub favicon: Option<String>,
    pub relay_icon: Option<String>,
    pub relay_page: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Database {
    pub data_directory: String,
    pub engine: String,
    pub in_memory: bool,
    pub min_conn: u32,
    pub max_conn: u32,
    pub connection: String,
    pub connection_write: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Grpc {
    pub event_admission_server: Option<String>,
    pub restricts_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Network {
    pub port: u16,
    pub address: String,
    pub remote_ip_header: Option<String>, // retrieve client IP from this HTTP header if present
    pub ping_interval_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Options {
    pub reject_future_seconds: Option<usize>, // if defined, reject any events with a timestamp more than X seconds in the future
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Retention {
    // TODO: implement
    pub max_events: Option<usize>,                // max events
    pub max_bytes: Option<usize>,                 // max size
    pub persist_days: Option<usize>,              // oldest message
    pub whitelist_addresses: Option<Vec<String>>, // whitelisted addresses (never delete)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Limits {
    pub messages_per_sec: Option<u32>, // Artificially slow down event writing to limit disk consumption (averaged over 1 minute)
    pub subscriptions_per_min: Option<u32>, // Artificially slow down request (db query) creation to prevent abuse (averaged over 1 minute)
    pub db_conns_per_client: Option<u32>, // How many concurrent database queries (not subscriptions) may a client have?
    pub max_blocking_threads: usize,
    pub max_event_bytes: Option<usize>, // Maximum size of an EVENT message
    pub max_ws_message_bytes: Option<usize>,
    pub max_ws_frame_bytes: Option<usize>,
    pub broadcast_buffer: usize, // events to buffer for subscribers (prevents slow readers from consuming memory)
    pub event_persist_buffer: usize, // events to buffer for database commits (block senders if database writes are too slow)
    pub event_kind_blacklist: Option<Vec<u64>>,
    pub event_kind_allowlist: Option<Vec<u64>>,
    pub limit_scrapers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Authorization {
    pub pubkey_whitelist: Option<Vec<String>>, // If present, only allow these pubkeys to publish events
    pub nip42_auth: bool,                      // if true enables NIP-42 authentication
    pub nip42_dms: bool, // if true send DMs only to their authenticated recipients
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct PayToRelay {
    pub enabled: bool,
    pub admission_cost: u64, // Cost to have pubkey whitelisted
    pub cost_per_event: u64, // Cost author to pay per event
    pub node_url: String,
    pub api_secret: String,
    pub terms_message: String,
    pub sign_ups: bool,       // allow new users to sign up to relay
    pub direct_message: bool, // Send direct message to user with invoice and terms
    pub secret_key: Option<String>,
    pub processor: Processor,
    pub rune_path: Option<String>, // To access clightning API
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Diagnostics {
    pub tracing: bool, // enables tokio console-subscriber
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum VerifiedUsersMode {
    Enabled,
    Passive,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct VerifiedUsers {
    pub mode: VerifiedUsersMode, // Mode of operation: "enabled" (enforce) or "passive" (check only). If none, this is simply disabled.
    pub domain_whitelist: Option<Vec<String>>, // If present, only allow verified users from these domains can publish events
    pub domain_blacklist: Option<Vec<String>>, // If present, allow all verified users from any domain except these
    pub verify_expiration: Option<String>, // how long a verification is cached for before no longer being used
    pub verify_update_frequency: Option<String>, // how often to attempt to update verification
    pub verify_expiration_duration: Option<Duration>, // internal result of parsing verify_expiration
    pub verify_update_frequency_duration: Option<Duration>, // internal result of parsing verify_update_frequency
    pub max_consecutive_failures: usize, // maximum number of verification failures in a row, before ceasing future checks
}

impl VerifiedUsers {
    pub fn init(&mut self) {
        self.verify_expiration_duration = self.verify_expiration_duration();
        self.verify_update_frequency_duration = self.verify_update_duration();
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.mode == VerifiedUsersMode::Enabled
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.mode == VerifiedUsersMode::Enabled || self.mode == VerifiedUsersMode::Passive
    }

    #[must_use]
    pub fn is_passive(&self) -> bool {
        self.mode == VerifiedUsersMode::Passive
    }

    #[must_use]
    pub fn verify_expiration_duration(&self) -> Option<Duration> {
        self.verify_expiration
            .as_ref()
            .and_then(|x| parse_duration::parse(x).ok())
    }

    #[must_use]
    pub fn verify_update_duration(&self) -> Option<Duration> {
        self.verify_update_frequency
            .as_ref()
            .and_then(|x| parse_duration::parse(x).ok())
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.verify_expiration_duration().is_some() && self.verify_update_duration().is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Logging {
    pub folder_path: Option<String>,
    pub file_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct KindFiltersConfig {
    pub config_file: Option<String>,
}

impl Default for KindFiltersConfig {
    fn default() -> Self {
        KindFiltersConfig {
            config_file: None,
        }
    }
}

/// Access rule for write/read permissions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessRule {
    /// Allow all ("*")
    All,
    /// Deny all ("none")
    None,
    /// Allow/deny specific identifiers (pubkeys or special identifiers)
    List(Vec<String>),
}

impl AccessRule {
    /// Parse access rule from JSON value
    pub fn from_json_value(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::String(s) => {
                if s == "*" {
                    AccessRule::All
                } else if s == "none" {
                    AccessRule::None
                } else {
                    AccessRule::List(vec![s.clone()])
                }
            }
            serde_json::Value::Array(arr) => {
                let list: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                AccessRule::List(list)
            }
            _ => AccessRule::None,
        }
    }
}

/// Tag requirement specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagRequirement {
    /// Tag not required ("none")
    None,
    /// Tag required with any value
    Required,
    /// Tag required with hex-encoded value
    RequiredHex,
}

impl TagRequirement {
    /// Parse tag requirement from string
    pub fn from_str(s: &str) -> Self {
        match s {
            "none" => TagRequirement::None,
            "hex" => TagRequirement::RequiredHex,
            _ => TagRequirement::Required,
        }
    }
}

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Events per minute
    pub events_per_minute: u32,
}

impl RateLimitConfig {
    /// Parse rate limit from string ("none" or "N/min" format)
    pub fn from_str(s: &str) -> Option<Self> {
        if s == "none" {
            return None;
        }
        // Parse format like "10/min" or "10/minute"
        if let Some(slash_pos) = s.find('/') {
            let num_str = &s[..slash_pos].trim();
            if let Ok(num) = num_str.parse::<u32>() {
                return Some(RateLimitConfig {
                    events_per_minute: num,
                });
            }
        }
        None
    }
}

/// Expiration configuration
#[derive(Debug, Clone)]
pub struct ExpirationConfig {
    /// Duration after which events expire, or None for "never"
    pub duration: Option<Duration>,
}

impl ExpirationConfig {
    /// Parse expiration from string ("never", "1h", "30m", etc.)
    pub fn from_str(s: &str) -> Self {
        if s == "never" {
            ExpirationConfig { duration: None }
        } else {
            ExpirationConfig {
                duration: parse_duration::parse(s).ok(),
            }
        }
    }
}

/// Per-kind filter configuration
#[derive(Debug, Clone)]
pub struct KindFilterConfig {
    pub description: Option<String>,
    pub write_deny: AccessRule,
    pub write_allow: AccessRule,
    pub read_deny: AccessRule,
    pub read_allow: AccessRule,
    pub max_size: Option<usize>,
    pub rate_limit: Option<RateLimitConfig>,
    pub expiration: ExpirationConfig,
    pub d_tag: TagRequirement,
    pub p_tag: TagRequirement,
}

/// Kind filters configuration container
#[derive(Debug, Clone)]
pub struct KindFilters {
    pub config_file: Option<String>,
    pub filters: HashMap<u64, KindFilterConfig>,
}

impl KindFilters {
    /// Create empty kind filters
    pub fn new() -> Self {
        KindFilters {
            config_file: None,
            filters: HashMap::new(),
        }
    }

    /// Load kind filters from JSON file
    pub fn load_from_file(file_path: &str) -> Result<Self, String> {
        use std::fs;
        let contents = fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read kind filters file {}: {}", file_path, e))?;
        let json: serde_json::Value = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse JSON: {}", e))?;

        let mut filters = HashMap::new();

        // Get the list of kinds
        let kinds: &Vec<serde_json::Value> = json
            .get("kinds")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "Missing 'kinds' array in JSON".to_string())?;

        for kind_value in kinds {
            let kind_str = kind_value
                .as_str()
                .ok_or_else(|| "Kind must be a string".to_string())?;
            let kind: u64 = kind_str
                .parse()
                .map_err(|_| format!("Invalid kind number: {}", kind_str))?;

            let kind_config = json
                .get(kind_str)
                .ok_or_else(|| format!("Missing configuration for kind {}", kind_str))?;

            let config = KindFilterConfig::from_json_value(kind_config)?;
            filters.insert(kind, config);
        }

        Ok(KindFilters {
            config_file: Some(file_path.to_string()),
            filters,
        })
    }
}

impl Default for KindFilters {
    fn default() -> Self {
        KindFilters::new()
    }
}

impl KindFilterConfig {
    /// Parse kind filter config from JSON value
    fn from_json_value(value: &serde_json::Value) -> Result<Self, String> {
        let obj = value
            .as_object()
            .ok_or_else(|| "Kind filter config must be an object".to_string())?;

        let description = obj
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let write_deny: AccessRule = obj
            .get("write_deny")
            .map(AccessRule::from_json_value)
            .unwrap_or_else(|| AccessRule::None);

        let write_allow: AccessRule = obj
            .get("write_allow")
            .map(AccessRule::from_json_value)
            .unwrap_or_else(|| AccessRule::All);

        let read_deny: AccessRule = obj
            .get("read_deny")
            .map(AccessRule::from_json_value)
            .unwrap_or_else(|| AccessRule::None);

        let read_allow: AccessRule = obj
            .get("read_allow")
            .map(AccessRule::from_json_value)
            .unwrap_or_else(|| AccessRule::All);

        let max_size: Option<usize> = obj
            .get("max_size")
            .and_then(|v| v.as_str())
            .and_then(parse_size_string);

        let rate_limit: Option<RateLimitConfig> = obj
            .get("rate_limit")
            .and_then(|v| v.as_str())
            .and_then(|s| RateLimitConfig::from_str(s));

        let expiration: ExpirationConfig = obj
            .get("expiration")
            .and_then(|v| v.as_str())
            .map(|s| ExpirationConfig::from_str(s))
            .unwrap_or_else(|| ExpirationConfig::from_str("never"));

        let d_tag: TagRequirement = obj
            .get("d_tag")
            .and_then(|v| v.as_str())
            .map(|s| TagRequirement::from_str(s))
            .unwrap_or_else(|| TagRequirement::None);

        let p_tag: TagRequirement = obj
            .get("p_tag")
            .and_then(|v| v.as_str())
            .map(|s| TagRequirement::from_str(s))
            .unwrap_or_else(|| TagRequirement::None);

        Ok(KindFilterConfig {
            description,
            write_deny,
            write_allow,
            read_deny,
            read_allow,
            max_size,
            rate_limit,
            expiration,
            d_tag,
            p_tag,
        })
    }
}

/// Parse size string like "1MB", "512KB" to bytes
fn parse_size_string(s: &str) -> Option<usize> {
    let s: String = s.trim().to_uppercase();
    if s.ends_with("KB") {
        let num_str: &str = &s[..s.len() - 2];
        num_str.parse::<usize>().ok().map(|n: usize| n * 1024)
    } else if s.ends_with("MB") {
        let num_str: &str = &s[..s.len() - 2];
        num_str.parse::<usize>().ok().map(|n: usize| n * 1024 * 1024)
    } else if s.ends_with("GB") {
        let num_str: &str = &s[..s.len() - 2];
        num_str.parse::<usize>().ok().map(|n: usize| n * 1024 * 1024 * 1024)
    } else if s.ends_with('B') {
        let num_str: &str = &s[..s.len() - 1];
        num_str.parse::<usize>().ok()
    } else {
        // Try parsing as plain number (assume bytes)
        s.parse::<usize>().ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Settings {
    pub info: Info,
    pub diagnostics: Diagnostics,
    pub database: Database,
    pub grpc: Grpc,
    pub network: Network,
    pub limits: Limits,
    pub authorization: Authorization,
    pub pay_to_relay: PayToRelay,
    pub verified_users: VerifiedUsers,
    pub retention: Retention,
    pub options: Options,
    pub logging: Logging,
    pub kind_filters_config: KindFiltersConfig,
    #[serde(skip)]
    pub kind_filters: KindFilters,
}

impl Settings {
    pub fn new(config_file_name: &Option<String>) -> Result<Self, ConfigError> {
        let default_settings = Self::default();
        // attempt to construct settings with file
        let from_file = Self::new_from_default(&default_settings, config_file_name);
        match from_file {
            Err(e) => {
                // pass up the parse error if the config file was specified,
                // otherwise use the default config (with a warning).
                if config_file_name.is_some() {
                    Err(e)
                } else {
                    eprintln!("Error reading config file ({:?})", e);
                    eprintln!("WARNING: Default configuration settings will be used");
                    Ok(default_settings)
                }
            }
            ok => ok,
        }
    }

    fn new_from_default(
        default: &Settings,
        config_file_name: &Option<String>,
    ) -> Result<Self, ConfigError> {
        let default_config_file_name = "config.toml".to_string();
        let config: &String = match config_file_name {
            Some(value) => value,
            None => &default_config_file_name,
        };
        let builder = Config::builder();
        let config: Config = builder
            // use defaults
            .add_source(Config::try_from(default)?)
            // override with file contents
            .add_source(File::with_name(config))
            .build()?;
        let mut settings: Settings = config.try_deserialize()?;
        
        // Load kind filters if configured
        if let Some(config_file) = &settings.kind_filters_config.config_file {
            match KindFilters::load_from_file(config_file) {
                Ok(kind_filters) => {
                    settings.kind_filters = kind_filters;
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load kind filters from {}: {}", config_file, e);
                    settings.kind_filters = KindFilters::new();
                }
            }
        } else {
            settings.kind_filters = KindFilters::new();
        }
        
        // ensure connection pool size is logical
        assert!(
            settings.database.min_conn <= settings.database.max_conn,
            "Database min_conn setting ({}) cannot exceed max_conn ({})",
            settings.database.min_conn,
            settings.database.max_conn
        );
        // ensure durations parse
        assert!(
            settings.verified_users.is_valid(),
            "VerifiedUsers time settings could not be parsed"
        );
        // initialize durations for verified users
        settings.verified_users.init();

        // Validate pay to relay settings
        if settings.pay_to_relay.enabled {
            if settings.pay_to_relay.processor == Processor::ClnRest {
                assert!(settings
                    .pay_to_relay
                    .rune_path
                    .as_ref()
                    .is_some_and(|path| path != "<rune path>"));
            } else if settings.pay_to_relay.processor == Processor::LNBits {
                assert_ne!(settings.pay_to_relay.api_secret, "");
            }
            // Should check that url is valid
            assert_ne!(settings.pay_to_relay.node_url, "");
            assert_ne!(settings.pay_to_relay.terms_message, "");

            if settings.pay_to_relay.direct_message {
                assert!(settings
                    .pay_to_relay
                    .secret_key
                    .as_ref()
                    .is_some_and(|key| key != "<nostr nsec>"));
            }
        }

        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            info: Info {
                relay_url: None,
                name: Some("Unnamed nostr-rs-relay".to_owned()),
                description: None,
                pubkey: None,
                contact: None,
                favicon: None,
                relay_icon: None,
                relay_page: None,
            },
            diagnostics: Diagnostics { tracing: false },
            database: Database {
                data_directory: ".".to_owned(),
                engine: "sqlite".to_owned(),
                in_memory: false,
                min_conn: 4,
                max_conn: 8,
                connection: "".to_owned(),
                connection_write: None,
            },
            grpc: Grpc {
                event_admission_server: None,
                restricts_write: false,
            },
            network: Network {
                port: 8080,
                ping_interval_seconds: 300,
                address: "0.0.0.0".to_owned(),
                remote_ip_header: None,
            },
            limits: Limits {
                messages_per_sec: None,
                subscriptions_per_min: None,
                db_conns_per_client: None,
                max_blocking_threads: 16,
                max_event_bytes: Some(2 << 17),      // 128K
                max_ws_message_bytes: Some(2 << 17), // 128K
                max_ws_frame_bytes: Some(2 << 17),   // 128K
                broadcast_buffer: 16384,
                event_persist_buffer: 4096,
                event_kind_blacklist: None,
                event_kind_allowlist: None,
                limit_scrapers: false,
            },
            authorization: Authorization {
                pubkey_whitelist: None, // Allow any address to publish
                nip42_auth: false,      // Disable NIP-42 authentication
                nip42_dms: false,       // Send DMs to everybody
            },
            pay_to_relay: PayToRelay {
                enabled: false,
                admission_cost: 4200,
                cost_per_event: 0,
                terms_message: "".to_string(),
                node_url: "".to_string(),
                api_secret: "".to_string(),
                rune_path: None,
                sign_ups: false,
                direct_message: false,
                secret_key: None,
                processor: Processor::LNBits,
            },
            verified_users: VerifiedUsers {
                mode: VerifiedUsersMode::Disabled,
                domain_whitelist: None,
                domain_blacklist: None,
                verify_expiration: Some("1 week".to_owned()),
                verify_update_frequency: Some("1 day".to_owned()),
                verify_expiration_duration: None,
                verify_update_frequency_duration: None,
                max_consecutive_failures: 20,
            },
            retention: Retention {
                max_events: None,          // max events
                max_bytes: None,           // max size
                persist_days: None,        // oldest message
                whitelist_addresses: None, // whitelisted addresses (never delete)
            },
            options: Options {
                reject_future_seconds: None, // Reject events in the future if defined
            },
            logging: Logging {
                folder_path: None,
                file_prefix: None,
            },
            kind_filters: KindFilters::new(),
            kind_filters_config: KindFiltersConfig {
                config_file: None,
            },
        }
    }
}
