//! Event persistence and querying
use crate::config::{RateScope, Settings};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::kind_filters::{
    check_kind_allowed, check_write_read_config, resolve_error_message, validate_d_tag,
    validate_expiration_window, validate_p_tag, validate_required_tags, ErrorPlaceholders,
    KindDenyReason,
};
use crate::nauthz;
use crate::notice::Notice;
use crate::payment::PaymentMessage;
use crate::repo::postgres::{PostgresPool, PostgresRepo};
use crate::repo::sqlite::SqliteRepo;
use crate::repo::NostrRepo;
use crate::server::NostrMetrics;
use governor::clock::Clock;
use governor::{Quota, RateLimiter};
use log::LevelFilter;
use nostr::key::FromPkStr;
use nostr::key::Keys;
use r2d2;
use sqlx::pool::PoolOptions;
use sqlx::postgres::PgConnectOptions;
use sqlx::ConnectOptions;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

pub type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
pub type PooledConnection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

/// Events submitted from a client, with a return channel for notices
pub struct SubmittedEvent {
    pub event: Event,
    pub notice_tx: tokio::sync::mpsc::Sender<Notice>,
    pub source_ip: String,
    pub origin: Option<String>,
    pub user_agent: Option<String>,
    pub auth_pubkey: Option<Vec<u8>>,
}

/// Database file
pub const DB_FILE: &str = "nostr.db";

/// Build repo
/// # Panics
///
/// Will panic if the pool could not be created.
pub async fn build_repo(settings: &Settings, metrics: NostrMetrics) -> Arc<dyn NostrRepo> {
    match settings.database.engine.as_str() {
        "sqlite" => Arc::new(build_sqlite_pool(settings, metrics).await),
        "postgres" => Arc::new(build_postgres_pool(settings, metrics).await),
        _ => panic!("Unknown database engine"),
    }
}

async fn build_sqlite_pool(settings: &Settings, metrics: NostrMetrics) -> SqliteRepo {
    let repo = SqliteRepo::new(settings, metrics);
    repo.start().await.ok();
    repo.migrate_up().await.ok();
    repo
}

async fn build_postgres_pool(settings: &Settings, metrics: NostrMetrics) -> PostgresRepo {
    let mut options: PgConnectOptions = settings.database.connection.as_str().parse().unwrap();
    options.log_statements(LevelFilter::Debug);
    options.log_slow_statements(LevelFilter::Warn, Duration::from_secs(60));

    let pool: PostgresPool = PoolOptions::new()
        .max_connections(settings.database.max_conn)
        .min_connections(settings.database.min_conn)
        .idle_timeout(Duration::from_secs(60))
        .connect_with(options)
        .await
        .unwrap();

    let write_pool: PostgresPool = match &settings.database.connection_write {
        Some(cfg_write) => {
            let mut options_write: PgConnectOptions = cfg_write.as_str().parse().unwrap();
            options_write.log_statements(LevelFilter::Debug);
            options_write.log_slow_statements(LevelFilter::Warn, Duration::from_secs(60));

            PoolOptions::new()
                .max_connections(settings.database.max_conn)
                .min_connections(settings.database.min_conn)
                .idle_timeout(Duration::from_secs(60))
                .connect_with(options_write)
                .await
                .unwrap()
        }
        None => pool.clone(),
    };

    let repo = PostgresRepo::new(pool, write_pool, metrics);

    // Panic on migration failure
    let version = repo.migrate_up().await.unwrap();
    info!("Postgres migration completed, at v{}", version);
    // startup scheduled tasks
    repo.start().await.ok();
    repo
}

/// A simple sliding-window rate limiter keyed by arbitrary string
/// (npub, IP, or "" for a global bucket).
struct SlidingWindowLimiter {
    window_secs: u64,
    max_events: u32,
    buckets: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl SlidingWindowLimiter {
    fn new(window_secs: u64, max_events: u32) -> Self {
        SlidingWindowLimiter {
            window_secs,
            max_events,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Attempt to record an event under `key`. Returns true if within limit.
    fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);
        let q = buckets.entry(key.to_string()).or_default();
        while q
            .front()
            .map(|t| now.duration_since(*t) >= window)
            .unwrap_or(false)
        {
            q.pop_front();
        }
        if (q.len() as u32) < self.max_events {
            q.push_back(now);
            true
        } else {
            false
        }
    }
}

/// A configured rate-limit rule bound to its limiter, for a specific kind.
struct BoundRateRule {
    scope: RateScope,
    limiter: SlidingWindowLimiter,
}

/// Spawn a database writer that persists events to the `SQLite` store.
pub async fn db_writer(
    repo: Arc<dyn NostrRepo>,
    settings: Settings,
    mut event_rx: tokio::sync::mpsc::Receiver<SubmittedEvent>,
    bcast_tx: tokio::sync::broadcast::Sender<Event>,
    metadata_tx: tokio::sync::broadcast::Sender<Event>,
    payment_tx: tokio::sync::broadcast::Sender<PaymentMessage>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    // are we performing NIP-05 checking?
    let nip05_active = settings.verified_users.is_active();
    // are we requriing NIP-05 user verification?
    let nip05_enabled = settings.verified_users.is_enabled();

    let pay_to_relay_enabled = settings.pay_to_relay.enabled;
    let cost_per_event = settings.pay_to_relay.cost_per_event;
    debug!("Pay to relay: {}", pay_to_relay_enabled);

    //upgrade_db(&mut pool.get()?)?;

    // Make a copy of the whitelist
    let whitelist = &settings.authorization.pubkey_whitelist.clone();

    // get rate limit settings
    let rps_setting = settings.limits.messages_per_sec;
    let mut most_recent_rate_limit = Instant::now();
    let mut lim_opt = None;
    let clock = governor::clock::QuantaClock::default();
    if let Some(rps) = rps_setting {
        if rps > 0 {
            info!("Enabling rate limits for event creation ({}/sec)", rps);
            let quota = core::num::NonZeroU32::new(rps * 60).unwrap();
            lim_opt = Some(RateLimiter::direct(Quota::per_minute(quota)));
        }
    }

    // Create per-kind rate limiters
    let mut kind_rate_limiters: HashMap<u64, RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::QuantaClock, governor::middleware::NoOpMiddleware<governor::clock::QuantaInstant>>> = HashMap::new();
    for (kind, filter_config) in &settings.kind_filters.filters {
        if let Some(rate_limit) = &filter_config.rate_limit {
            let quota: std::num::NonZero<u32> = core::num::NonZeroU32::new(rate_limit.events_per_minute).unwrap();
            let limiter = RateLimiter::direct(Quota::per_minute(quota));
            kind_rate_limiters.insert(*kind, limiter);
            info!(
                "Enabling per-kind rate limit for kind {}: {}/min",
                kind, rate_limit.events_per_minute
            );
        }
    }

    // Build keyed sliding-window rate limiters (per 1h/1d, per npub/ip) from
    // the richer `rate_limits` rules.
    let mut kind_sliding_limiters: HashMap<u64, Vec<BoundRateRule>> = HashMap::new();
    for (kind, filter_config) in &settings.kind_filters.filters {
        for rule in &filter_config.rate_limits {
            let bound = BoundRateRule {
                scope: rule.scope,
                limiter: SlidingWindowLimiter::new(rule.window.as_secs(), rule.limit),
            };
            kind_sliding_limiters.entry(*kind).or_default().push(bound);
            info!(
                "Enabling per-kind sliding rate limit for kind {}: {}/{}sec keyed by {:?}",
                kind, rule.limit, rule.window.as_secs(), rule.scope
            );
        }
    }

    // create a client if GRPC is enabled.
    // Check with externalized event admitter service, if one is defined.
    let mut grpc_client = if let Some(svr) = settings.grpc.event_admission_server {
        Some(nauthz::EventAuthzService::connect(&svr).await)
    } else {
        None
    };

    //let gprc_client = settings.grpc.event_admission_server.map(|s| {
    //        event_admitter_connect(&s);
    //    });

    loop {
        if shutdown.try_recv().is_ok() {
            info!("shutting down database writer");
            break;
        }
        // call blocking read on channel
        let next_event = event_rx.recv().await;
        // if the channel has closed, we will never get work
        if next_event.is_none() {
            break;
        }
        // track if an event write occurred; this is used to
        // update the rate limiter
        let mut event_write = false;
        let subm_event = next_event.unwrap();
        let event = subm_event.event;
        let notice_tx = subm_event.notice_tx;

        // Check that event kind isn't blacklisted
        let kinds_blacklist = &settings.limits.event_kind_blacklist.clone();
        if let Some(event_kind_blacklist) = kinds_blacklist {
            if event_kind_blacklist.contains(&event.kind) {
                debug!(
                    "rejecting event: {}, blacklisted kind: {}",
                    &event.get_event_id_prefix(),
                    &event.kind
                );
                notice_tx
                    .try_send(Notice::blocked(event.id, "event kind is blocked by relay"))
                    .ok();
                continue;
            }
        }

        // Check that event kind isn't allowlisted
        let kinds_allowlist = &settings.limits.event_kind_allowlist.clone();
        if let Some(event_kind_allowlist) = kinds_allowlist {
            if !event_kind_allowlist.contains(&event.kind) {
                debug!(
                    "rejecting event: {}, allowlist kind: {}",
                    &event.get_event_id_prefix(),
                    &event.kind
                );
                notice_tx
                    .try_send(Notice::blocked(event.id, "event kind is blocked by relay"))
                    .ok();
                continue;
            }
        }

        // Set to none until balance is got from db
        // Will stay none if user in whitelisted and does not have to pay to post
        // When pay to relay is enabled the whitelist is not a list of who can post
        // It is a list of who can post for free
        let mut user_balance: Option<u64> = None;
        if !pay_to_relay_enabled {
            // check if this event is authorized.
            if let Some(allowed_addrs) = whitelist {
                // TODO: incorporate delegated pubkeys
                // if the event address is not in allowed_addrs.
                if !allowed_addrs.contains(&event.pubkey) {
                    debug!(
                        "rejecting event: {}, unauthorized author",
                        event.get_event_id_prefix()
                    );
                    notice_tx
                        .try_send(Notice::blocked(
                            event.id,
                            "pubkey is not allowed to publish to this relay",
                        ))
                        .ok();
                    continue;
                }
            }
        } else {
            // If the user is on whitelist there is no need to check if the user is admitted or has balance to post
            if whitelist.is_none()
                || (whitelist.is_some() && !whitelist.as_ref().unwrap().contains(&event.pubkey))
            {
                let key = Keys::from_pk_str(&event.pubkey).unwrap();
                match repo.get_account_balance(&key).await {
                    Ok((user_admitted, balance)) => {
                        // Checks to make sure user is admitted
                        if !user_admitted {
                            debug!("user: {}, is not admitted", &event.pubkey);

                            // If the user is in DB but not admitted
                            // Send meeage to payment thread to check if outstanding invoice has been paid
                            payment_tx
                                .send(PaymentMessage::CheckAccount(event.pubkey))
                                .ok();
                            notice_tx
                                .try_send(Notice::blocked(event.id, "User is not admitted"))
                                .ok();
                            continue;
                        }

                        // Checks that user has enough balance to post
                        // TODO: this should send an invoice to user to top up
                        if balance < cost_per_event {
                            debug!("user: {}, does not have a balance", &event.pubkey,);
                            notice_tx
                                .try_send(Notice::blocked(event.id, "Insufficient balance"))
                                .ok();
                            continue;
                        }
                        user_balance = Some(balance);
                        debug!("User balance: {:?}", user_balance);
                    }
                    Err(
                        Error::SqlError(rusqlite::Error::QueryReturnedNoRows)
                        | Error::SqlxError(sqlx::Error::RowNotFound),
                    ) => {
                        // User does not exist
                        info!("Unregistered user");
                        if settings.pay_to_relay.sign_ups && settings.pay_to_relay.direct_message {
                            payment_tx
                                .send(PaymentMessage::NewAccount(event.pubkey))
                                .ok();
                        }
                        let msg = "Pubkey not registered";
                        notice_tx.try_send(Notice::error(event.id, msg)).ok();
                        continue;
                    }
                    Err(err) => {
                        warn!("Error checking admission status: {:?}", err);
                        let msg = "relay experienced an error checking your admission status";
                        notice_tx.try_send(Notice::error(event.id, msg)).ok();
                        // Other error
                        continue;
                    }
                }
            }
        }

        // get a validation result for use in verification and GPRC
        let validation = if nip05_active {
            Some(repo.get_latest_user_verification(&event.pubkey).await)
        } else {
            None
        };

        // check for  NIP-05 verification
        if nip05_enabled && validation.is_some() {
            match validation.as_ref().unwrap() {
                Ok(uv) => {
                    if uv.is_valid(&settings.verified_users) {
                        info!(
                            "new event from verified author ({:?},{:?})",
                            uv.name.to_string(),
                            event.get_author_prefix()
                        );
                    } else {
                        info!(
                            "rejecting event, author ({:?} / {:?}) verification invalid (expired/wrong domain)",
                            uv.name.to_string(),
                            event.get_author_prefix()
                        );
                        notice_tx
                            .try_send(Notice::blocked(
                                event.id,
                                "NIP-05 verification is no longer valid (expired/wrong domain)",
                            ))
                            .ok();
                        continue;
                    }
                }
                Err(
                    Error::SqlError(rusqlite::Error::QueryReturnedNoRows)
                    | Error::SqlxError(sqlx::Error::RowNotFound),
                ) => {
                    debug!(
                        "no verification records found for pubkey: {:?}",
                        event.get_author_prefix()
                    );
                    notice_tx
                        .try_send(Notice::blocked(
                            event.id,
                            "NIP-05 verification needed to publish events",
                        ))
                        .ok();
                    continue;
                }
                Err(e) => {
                    warn!("checking nip05 verification status failed: {:?}", e);
                    continue;
                }
            }
        }

        // nip05 address
        let nip05_address: Option<crate::nip05::Nip05Name> =
            validation.and_then(|x| x.ok().map(|y| y.name));

        // Convert auth_pubkey from Vec<u8> to hex string if available (before GRPC call)
        let auth_pubkey_hex = subm_event
            .auth_pubkey
            .as_ref()
            .map(|pk| hex::encode(pk));
        let auth_pubkey_str = auth_pubkey_hex.as_deref();

        // GRPC check
        if let Some(ref mut c) = grpc_client {
            trace!("checking if grpc permits");
            let grpc_start = Instant::now();
            let decision_res = c
                .admit_event(
                    &event,
                    &subm_event.source_ip,
                    subm_event.origin,
                    subm_event.user_agent,
                    nip05_address,
                    subm_event.auth_pubkey,
                )
                .await;
            match decision_res {
                Ok(decision) => {
                    if !decision.permitted() {
                        // GPRC returned a decision to reject this event
                        info!(
                            "GRPC rejected event: {:?} (kind: {}) from: {:?} in: {:?} (IP: {:?})",
                            event.get_event_id_prefix(),
                            event.kind,
                            event.get_author_prefix(),
                            grpc_start.elapsed(),
                            subm_event.source_ip
                        );
                        notice_tx
                            .try_send(Notice::blocked(
                                event.id,
                                &decision.message().unwrap_or_default(),
                            ))
                            .ok();
                        continue;
                    }
                }
                Err(e) => {
                    warn!("GRPC server error: {:?}", e);
                }
            }
        }

        // Check kind whitelist/blacklist first
        if let Err(deny_reason) = check_kind_allowed(event.kind, &settings.kind_filters) {
            let (key, default) = match deny_reason {
                KindDenyReason::NotInWhitelist => (
                    "not_in_whitelist",
                    "blocked: kind {kind} is not in the kind whitelist",
                ),
                KindDenyReason::Blacklisted => (
                    "blacklisted",
                    "blocked: kind {kind} is blacklisted",
                ),
            };
            let placeholders = ErrorPlaceholders {
                kind: Some(event.kind),
                ..Default::default()
            };
            let msg = resolve_error_message(
                default,
                None,
                settings.kind_filters.errors.get(key).map(String::as_str),
                &placeholders,
            );
            debug!(
                "rejecting event: {} (kind: {}), reason: {}",
                event.get_event_id_prefix(),
                event.kind,
                msg
            );
            notice_tx
                .try_send(Notice::from_reason(event.id, &msg))
                .ok();
            continue;
        }

        // Kind filter write check
        if let Some(filter_config) = settings.kind_filters.filters.get(&event.kind) {
            // Get server pubkey from settings if available
            let server_pubkey = settings.info.pubkey.as_deref();
            let kind_errors = &filter_config.errors;
            let global_errors = &settings.kind_filters.errors;
            let kind_ph = ErrorPlaceholders {
                kind: Some(event.kind),
                ..Default::default()
            };

            // Check write access using new structure
            if let Some(ref write_config) = filter_config.write {
                let write_allowed = check_write_read_config(
                    write_config,
                    &event,
                    auth_pubkey_str,
                    server_pubkey,
                    false, // is_read = false for write
                );

                if !write_allowed {
                    let msg = resolve_error_message(
                        "restricted: pubkey is not allowed to write this kind",
                        write_config
                            .error
                            .as_deref()
                            .or_else(|| kind_errors.get("write").map(String::as_str)),
                        global_errors.get("write").map(String::as_str),
                        &kind_ph,
                    );
                    debug!(
                        "rejecting event: {} (kind: {}), reason: {}",
                        event.get_event_id_prefix(),
                        event.kind,
                        msg
                    );
                    notice_tx
                        .try_send(Notice::from_reason(event.id, &msg))
                        .ok();
                    continue;
                }
            }

            // Require NIP-42 authentication for publishing this kind
            if filter_config.require_auth && auth_pubkey_str.is_none() {
                let msg = resolve_error_message(
                    "auth-required: authentication required to publish this kind",
                    kind_errors.get("auth_required").map(String::as_str),
                    global_errors.get("auth_required").map(String::as_str),
                    &kind_ph,
                );
                debug!(
                    "rejecting event: {} (kind: {}), reason: {}",
                    event.get_event_id_prefix(),
                    event.kind,
                    msg
                );
                notice_tx
                    .try_send(Notice::from_reason(event.id, &msg))
                    .ok();
                continue;
            }

            // Check size limit
            if let Some(max_size) = filter_config.max_size {
                let event_json = serde_json::to_string(&event).unwrap_or_default();
                if event_json.len() > max_size {
                    let placeholders = ErrorPlaceholders {
                        kind: Some(event.kind),
                        size: Some(event_json.len()),
                        limit: Some(max_size),
                        ..Default::default()
                    };
                    let msg = resolve_error_message(
                        "blocked: event exceeds size limit ({size} > {limit})",
                        kind_errors.get("max_size").map(String::as_str),
                        global_errors.get("max_size").map(String::as_str),
                        &placeholders,
                    );
                    debug!(
                        "rejecting event: {} (kind: {}), size {} exceeds limit {}",
                        event.get_event_id_prefix(),
                        event.kind,
                        event_json.len(),
                        max_size
                    );
                    notice_tx
                        .try_send(Notice::from_reason(event.id, &msg))
                        .ok();
                    continue;
                }
            }

            // Check tag requirements
            if !validate_d_tag(&event, &filter_config.d_tag) {
                let msg = resolve_error_message(
                    "invalid: missing d tag",
                    kind_errors.get("d_tag").map(String::as_str),
                    global_errors.get("d_tag").map(String::as_str),
                    &kind_ph,
                );
                debug!(
                    "rejecting event: {} (kind: {}), reason: {}",
                    event.get_event_id_prefix(),
                    event.kind,
                    msg
                );
                notice_tx
                    .try_send(Notice::from_reason(event.id, &msg))
                    .ok();
                continue;
            }

            if !validate_p_tag(&event, &filter_config.p_tag) {
                let msg = resolve_error_message(
                    "invalid: p tag requirement not met",
                    kind_errors.get("p_tag").map(String::as_str),
                    global_errors.get("p_tag").map(String::as_str),
                    &kind_ph,
                );
                debug!(
                    "rejecting event: {} (kind: {}), reason: {}",
                    event.get_event_id_prefix(),
                    event.kind,
                    msg
                );
                notice_tx
                    .try_send(Notice::from_reason(event.id, &msg))
                    .ok();
                continue;
            }

            if let Err(detail) = validate_required_tags(&event, &filter_config.required_tags) {
                // detail is "missing required tag: {tag}" — extract tag for placeholder
                let tag = detail
                    .strip_prefix("missing required tag: ")
                    .unwrap_or("")
                    .to_string();
                let placeholders = ErrorPlaceholders {
                    kind: Some(event.kind),
                    tag: if tag.is_empty() { None } else { Some(tag) },
                    ..Default::default()
                };
                let msg = resolve_error_message(
                    "invalid: missing required tag: {tag}",
                    kind_errors.get("missing_tag").map(String::as_str),
                    global_errors.get("missing_tag").map(String::as_str),
                    &placeholders,
                );
                debug!(
                    "rejecting event: {} (kind: {}), reason: {}",
                    event.get_event_id_prefix(),
                    event.kind,
                    msg
                );
                notice_tx
                    .try_send(Notice::from_reason(event.id, &msg))
                    .ok();
                continue;
            }

            // Check tag size restrictions
            if let Some(tl) = filter_config.tag_limits {
                let mut tag_err: Option<String> = None;
                if tl.max_tags > 0 && event.tags.len() > tl.max_tags {
                    tag_err = Some(format!("too many tags: {} > {}", event.tags.len(), tl.max_tags));
                } else {
                    for tag in &event.tags {
                        if let Some(name) = tag.first() {
                            if tl.max_tag_name_chars > 0 && name.chars().count() > tl.max_tag_name_chars {
                                tag_err = Some(format!("tag name exceeds {} chars", tl.max_tag_name_chars));
                                break;
                            }
                        }
                        for val in tag.iter().skip(1) {
                            if tl.max_tag_value_chars > 0 && val.chars().count() > tl.max_tag_value_chars {
                                tag_err = Some(format!("tag value exceeds {} chars", tl.max_tag_value_chars));
                                break;
                            }
                        }
                        if tag_err.is_some() {
                            break;
                        }
                    }
                }
                if let Some(detail) = tag_err {
                    let placeholders = ErrorPlaceholders {
                        kind: Some(event.kind),
                        detail: Some(detail.clone()),
                        ..Default::default()
                    };
                    let msg = resolve_error_message(
                        "invalid: {detail}",
                        kind_errors.get("tag_limits").map(String::as_str),
                        global_errors.get("tag_limits").map(String::as_str),
                        &placeholders,
                    );
                    debug!(
                        "rejecting event: {} (kind: {}), reason: {}",
                        event.get_event_id_prefix(),
                        event.kind,
                        msg
                    );
                    notice_tx
                        .try_send(Notice::from_reason(event.id, &msg))
                        .ok();
                    continue;
                }
            }

            // Check expiration
            if let Some(expiration_duration) = filter_config.expiration.duration {
                // Check if event has expired based on created_at + expiration duration
                let now = crate::utils::unix_time();
                let expiration_time = event.created_at + expiration_duration.as_secs();
                if now > expiration_time {
                    let msg = resolve_error_message(
                        "blocked: event has expired",
                        kind_errors.get("expired").map(String::as_str),
                        global_errors.get("expired").map(String::as_str),
                        &kind_ph,
                    );
                    debug!(
                        "rejecting event: {} (kind: {}), reason: {}",
                        event.get_event_id_prefix(),
                        event.kind,
                        msg
                    );
                    notice_tx
                        .try_send(Notice::from_reason(event.id, &msg))
                        .ok();
                    continue;
                }
            }

            // Check max_expiration: reject if the event's NIP-40 expiration tag is set
            // further in the future than the configured maximum allowed window, or is
            // present but not a valid numeric timestamp.
            if let Some(max_exp_duration) = filter_config.max_expiration.duration {
                if let Err(detail) = validate_expiration_window(&event, max_exp_duration) {
                    let (key, default) = if detail.contains("valid timestamp") {
                        (
                            "expiration_invalid",
                            "invalid: expiration tag is not a valid timestamp",
                        )
                    } else {
                        (
                            "expiration",
                            "blocked: expiration exceeds max_expiry_duration",
                        )
                    };
                    let msg = resolve_error_message(
                        default,
                        kind_errors.get(key).map(String::as_str),
                        global_errors.get(key).map(String::as_str),
                        &kind_ph,
                    );
                    debug!(
                        "rejecting event: {} (kind: {}), reason: {}",
                        event.get_event_id_prefix(),
                        event.kind,
                        msg
                    );
                    notice_tx
                        .try_send(Notice::from_reason(event.id, &msg))
                        .ok();
                    continue;
                }
            }

            // Check per-kind rate limit (legacy global per-minute)
            if let Some(rate_limiter) = kind_rate_limiters.get(&event.kind) {
                if rate_limiter.check().is_err() {
                    let msg = resolve_error_message(
                        "rate-limited: rate limit exceeded for this kind",
                        kind_errors.get("rate_limited").map(String::as_str),
                        global_errors.get("rate_limited").map(String::as_str),
                        &kind_ph,
                    );
                    debug!(
                        "rejecting event: {} (kind: {}), reason: {}",
                        event.get_event_id_prefix(),
                        event.kind,
                        msg
                    );
                    notice_tx
                        .try_send(Notice::from_reason(event.id, &msg))
                        .ok();
                    continue;
                }
            }

            // Check keyed sliding-window rate limits (per 1h/1d, per npub/ip)
            if let Some(bound_rules) = kind_sliding_limiters.get(&event.kind) {
                let mut exceeded = false;
                for rule in bound_rules {
                    let key = match rule.scope {
                        RateScope::Global => String::new(),
                        RateScope::Npub => event.pubkey.clone(),
                        RateScope::Ip => subm_event.source_ip.clone(),
                    };
                    if !rule.limiter.check(&key) {
                        exceeded = true;
                        break;
                    }
                }
                if exceeded {
                    let msg = resolve_error_message(
                        "rate-limited: rate limit exceeded for this kind",
                        kind_errors.get("rate_limited").map(String::as_str),
                        global_errors.get("rate_limited").map(String::as_str),
                        &kind_ph,
                    );
                    debug!(
                        "rejecting event: {} (kind: {}), reason: {}",
                        event.get_event_id_prefix(),
                        event.kind,
                        msg
                    );
                    notice_tx
                        .try_send(Notice::from_reason(event.id, &msg))
                        .ok();
                    continue;
                }
            }
        }

        // send any metadata events to the NIP-05 verifier
        if nip05_active && event.is_kind_metadata() {
            // we are sending this prior to even deciding if we
            // persist it.  this allows the nip05 module to
            // inspect it, update if necessary, or persist a new
            // event and broadcast it itself.
            metadata_tx.send(event.clone()).ok();
        }

        // TODO: cache recent list of authors to remove a DB call.
        let start = Instant::now();
        if event.is_ephemeral() {
            bcast_tx.send(event.clone()).ok();
            debug!(
                "published ephemeral event: {:?} from: {:?} in: {:?}",
                event.get_event_id_prefix(),
                event.get_author_prefix(),
                start.elapsed()
            );
            event_write = true;

            // send OK message
            notice_tx.try_send(Notice::saved(event.id)).ok();
        } else {
            match repo.write_event(&event).await {
                Ok(updated) => {
                    if updated == 0 {
                        trace!("ignoring duplicate or deleted event");
                        notice_tx.try_send(Notice::duplicate(event.id)).ok();
                    } else {
                        info!(
                            "persisted event: {:?} (kind: {}) from: {:?} in: {:?} (IP: {:?})",
                            event.get_event_id_prefix(),
                            event.kind,
                            event.get_author_prefix(),
                            start.elapsed(),
                            subm_event.source_ip,
                        );
                        event_write = true;
                        // send this out to all clients
                        bcast_tx.send(event.clone()).ok();
                        notice_tx.try_send(Notice::saved(event.id)).ok();
                    }
                }
                Err(err) => {
                    warn!("event insert failed: {:?}", err);
                    let msg = "relay experienced an error trying to publish the latest event";
                    notice_tx.try_send(Notice::error(event.id, msg)).ok();
                }
            }
        }

        // use rate limit, if defined, and if an event was actually written.
        if event_write {
            // If pay to relay is diabaled or the cost per event is 0
            // No need to update user balance
            if pay_to_relay_enabled && cost_per_event > 0 {
                // If the user balance is some, user was not on whitelist
                // Their balance should be reduced by the cost per event
                if let Some(_balance) = user_balance {
                    let pubkey = Keys::from_pk_str(&event.pubkey)?;
                    repo.update_account_balance(&pubkey, false, cost_per_event)
                        .await?;
                }
            }
            if let Some(ref lim) = lim_opt {
                if let Err(n) = lim.check() {
                    let wait_for = n.wait_time_from(clock.now());
                    // check if we have recently logged rate
                    // limits, but print out a message only once
                    // per second.
                    if most_recent_rate_limit.elapsed().as_secs() > 10 {
                        warn!(
                            "rate limit reached for event creation (sleep for {:?}) (suppressing future messages for 10 seconds)",
                            wait_for
                        );
                        // reset last rate limit message
                        most_recent_rate_limit = Instant::now();
                    }
                    // block event writes, allowing them to queue up
                    thread::sleep(wait_for);
                    continue;
                }
            }
        }
    }
    info!("database connection closed");
    Ok(())
}

/// Serialized event associated with a specific subscription request.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct QueryResult {
    /// Subscription identifier
    pub sub_id: String,
    /// Serialized event
    pub event: String,
}

#[cfg(test)]
mod kind_rate_limit_tests {
    use super::*;

    #[test]
    fn sliding_window_allows_up_to_limit() {
        let lim = SlidingWindowLimiter::new(3600, 3);
        assert!(lim.check("npub1"));
        assert!(lim.check("npub1"));
        assert!(lim.check("npub1"));
        assert!(!lim.check("npub1")); // over limit
    }

    #[test]
    fn sliding_window_keys_are_independent() {
        let lim = SlidingWindowLimiter::new(3600, 2);
        assert!(lim.check("alice"));
        assert!(lim.check("alice"));
        assert!(!lim.check("alice"));
        assert!(lim.check("bob")); // different key unaffected
    }

    #[test]
    fn sliding_window_global_key_shares_bucket() {
        let lim = SlidingWindowLimiter::new(60, 2);
        assert!(lim.check(""));
        assert!(lim.check(""));
        assert!(!lim.check(""));
    }

    #[test]
    fn sliding_window_resets_after_window() {
        let lim = SlidingWindowLimiter::new(1, 2); // 1 second window
        assert!(lim.check("k"));
        assert!(lim.check("k"));
        assert!(!lim.check("k"));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(lim.check("k")); // window expired
    }
}
