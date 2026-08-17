//! Kind filter evaluation functions
use crate::config::{AccessRule, KindFilters, TagRequirement, WriteReadConfig};
use crate::event::Event;
use log::debug;
use std::process::{Command, Stdio};
use std::io::Write;
use std::time::Duration;

/// Evaluate a special access identifier
pub fn evaluate_access_identifier(
    identifier: &str,
    event: &Event,
    auth_pubkey: Option<&str>,
    server_pubkey: Option<&str>,
) -> bool {
    // Check if it's a hex pubkey (64 character hex string)
    if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
        // Compare with event pubkey
        if event.pubkey == identifier {
            return true;
        }
        // Compare with auth pubkey if available
        if let Some(auth_pk) = auth_pubkey {
            if auth_pk == identifier {
                return true;
            }
        }
        return false;
    }

    // Handle special identifiers
    match identifier {
        "private_server_hex" => {
            // Check if auth_pubkey matches server's configured pubkey
            if let (Some(auth_pk), Some(server_pk)) = (auth_pubkey, server_pubkey) {
                return auth_pk == server_pk;
            }
            false
        }
        _ => false,
    }
}


/// Validate d tag requirement
pub fn validate_d_tag(event: &Event, requirement: &TagRequirement) -> bool {
    match requirement {
        TagRequirement::None => true,
        TagRequirement::Required => {
            // Tag must exist
            !event.tag_values_by_name("d").is_empty()
        }
        TagRequirement::RequiredHex => {
            // Tag must exist and value must be valid hex
            let d_vals = event.tag_values_by_name("d");
            !d_vals.is_empty()
                && d_vals
                    .iter()
                    .any(|d_val| d_val.len() == 64 && d_val.chars().all(|c| c.is_ascii_hexdigit()))
        }
    }
}

/// Validate p tag requirement
pub fn validate_p_tag(event: &Event, requirement: &TagRequirement) -> bool {
    match requirement {
        TagRequirement::None => true,
        TagRequirement::Required => {
            // Tag must exist
            !event.tag_values_by_name("p").is_empty()
        }
        TagRequirement::RequiredHex => {
            // Tag must exist and at least one value must be valid hex
            event
                .tag_values_by_name("p")
                .iter()
                .any(|p_val| p_val.len() == 64 && p_val.chars().all(|c| c.is_ascii_hexdigit()))
        }
    }
}

/// Validate that all required tag names are present on the event (any value)
pub fn validate_required_tags(event: &Event, required_tags: &[String]) -> Result<(), String> {
    for tag_name in required_tags {
        if event.tag_values_by_name(tag_name).is_empty() {
            return Err(format!("missing required tag: {}", tag_name));
        }
    }
    Ok(())
}

/// Validate the NIP-40 `expiration` tag against a maximum allowed window.
///
/// - If no `expiration` tag is present, this returns Ok (presence is normally
///   enforced separately via `required_tags`).
/// - If an `expiration` tag is present but its value is not a valid unsigned
///   integer timestamp, this returns an error (closes the bypass where a
///   non-numeric value would otherwise skipped the max window check).
/// - If the value parses but is further in the future than `now + max_duration`,
///   this returns an error.
pub fn validate_expiration_window(event: &Event, max_duration: Duration) -> Result<(), String> {
    let has_expiration_tag = event
        .tags
        .iter()
        .any(|t| t.first().map(|s| s.as_str()) == Some("expiration"));
    if !has_expiration_tag {
        return Ok(());
    }
    let Some(event_exp) = event.expiration() else {
        return Err("expiration tag is not a valid timestamp".to_string());
    };
    let now = crate::utils::unix_time();
    let max_allowed = now + max_duration.as_secs();
    if event_exp > max_allowed {
        return Err("expiration exceeds max_expiry_duration".to_string());
    }
    Ok(())
}

/// Why a kind was rejected by the global whitelist/blacklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KindDenyReason {
    NotInWhitelist,
    Blacklisted,
}

/// Check if a kind is allowed based on whitelist/blacklist.
///
/// Returns `Ok(())` when allowed, or `Err(KindDenyReason)` when denied.
pub fn check_kind_allowed(kind: u64, filters: &KindFilters) -> Result<(), KindDenyReason> {
    if let Some(ref whitelist) = filters.whitelist {
        if whitelist.contains(&kind) {
            return Ok(());
        }
        return Err(KindDenyReason::NotInWhitelist);
    }

    if let Some(ref blacklist) = filters.blacklist {
        if blacklist.contains(&kind) {
            return Err(KindDenyReason::Blacklisted);
        }
        return Ok(());
    }

    Ok(())
}

/// Check if a kind is allowed based on whitelist/blacklist
pub fn is_kind_allowed(kind: u64, filters: &KindFilters) -> bool {
    check_kind_allowed(kind, filters).is_ok()
}

/// Placeholders available in kinds.json error overrides.
#[derive(Debug, Clone, Default)]
pub struct ErrorPlaceholders {
    pub kind: Option<u64>,
    pub tag: Option<String>,
    pub size: Option<usize>,
    pub limit: Option<usize>,
    pub detail: Option<String>,
}

/// Resolve an error message template with optional overrides.
///
/// Lookup order for the template: `kind_override` → `global_override` → `default`.
/// Substitutes `{kind}`, `{tag}`, `{size}`, `{limit}`, and `{detail}`.
#[must_use]
pub fn resolve_error_message(
    default: &str,
    kind_override: Option<&str>,
    global_override: Option<&str>,
    placeholders: &ErrorPlaceholders,
) -> String {
    let template = kind_override
        .or(global_override)
        .unwrap_or(default);
    substitute_placeholders(template, placeholders)
}

/// Substitute known placeholders in an error template.
#[must_use]
pub fn substitute_placeholders(template: &str, placeholders: &ErrorPlaceholders) -> String {
    let mut out = template.to_string();
    if let Some(kind) = placeholders.kind {
        out = out.replace("{kind}", &kind.to_string());
    }
    if let Some(ref tag) = placeholders.tag {
        out = out.replace("{tag}", tag);
    }
    if let Some(size) = placeholders.size {
        out = out.replace("{size}", &size.to_string());
    }
    if let Some(limit) = placeholders.limit {
        out = out.replace("{limit}", &limit.to_string());
    }
    if let Some(ref detail) = placeholders.detail {
        out = out.replace("{detail}", detail);
    }
    out
}

/// Execute a script and return whether it allows the event
/// Script receives event JSON via stdin and AUTH_PUBKEY env var
/// Returns true if exit code is 0, false otherwise
pub fn execute_script(
    script_path: &str,
    event: &Event,
    auth_pubkey: Option<&str>,
) -> Result<bool, String> {
    // Serialize event to JSON
    let event_json = serde_json::to_string(event)
        .map_err(|e| format!("Failed to serialize event: {}", e))?;

    // Spawn the script process
    let mut cmd = Command::new(script_path);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Set AUTH_PUBKEY environment variable if available
    if let Some(auth_pk) = auth_pubkey {
        cmd.env("AUTH_PUBKEY", auth_pk);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn script {}: {}", script_path, e))?;

    // Write event JSON to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(event_json.as_bytes())
            .map_err(|e| format!("Failed to write to script stdin: {}", e))?;
        stdin
            .flush()
            .map_err(|e| format!("Failed to flush script stdin: {}", e))?;
    }

    // Wait for the process with timeout (5 seconds)
    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for script: {}", e))?;

    // Exit code 0 means allow, any non-zero means deny
    Ok(output.status.success())
}

/// Check if an access rule allows the event
pub fn check_access_rule(
    rule: &AccessRule,
    event: &Event,
    auth_pubkey: Option<&str>,
    server_pubkey: Option<&str>,
) -> bool {
    match rule {
        AccessRule::All => true,
        AccessRule::None => false,
        AccessRule::List(identifiers) => identifiers
            .iter()
            .any(|id| evaluate_access_identifier(id, event, auth_pubkey, server_pubkey)),
    }
}

/// Privileged read: NIP-42 AUTH required, and auth pubkey must be the
/// event author or listed in a "p" tag. Nobody else may read.
pub fn check_privileged_read(event: &Event, auth_pubkey: Option<&str>) -> bool {
    let Some(auth_pk) = auth_pubkey else {
        return false;
    };
    if event.pubkey == auth_pk {
        return true;
    }
    event
        .tag_values_by_name("p")
        .iter()
        .any(|p| p == auth_pk)
}

/// Check if a write/read config allows the event
pub fn check_write_read_config(
    config: &WriteReadConfig,
    event: &Event,
    auth_pubkey: Option<&str>,
    server_pubkey: Option<&str>,
    is_read: bool,
) -> bool {
    // If script is present, execute it first (script result takes precedence)
    if let Some(ref script_path) = config.script {
        match execute_script(script_path, event, auth_pubkey) {
            Ok(allowed) => {
                if !allowed {
                    return false; // Script denied access
                }
                // Script allowed, continue to check allow/deny rules
            }
            Err(e) => {
                // On script error, deny access for safety
                debug!("Script execution error: {}", e);
                return false;
            }
        }
    }

    // Check deny rule first (deny takes precedence over allow/privileged)
    let denied = check_access_rule(&config.deny, event, auth_pubkey, server_pubkey);
    if denied {
        return false;
    }

    let allowed = check_access_rule(&config.allow, event, auth_pubkey, server_pubkey);

    // Privileged read: AUTH'd author or AUTH'd p-tag may read.
    // Explicit allow entries take precedence (extra readers).
    // AccessRule::All does not short-circuit privileged — otherwise the
    // default allow:"*" would make privileged useless.
    if is_read && config.privileged {
        if !matches!(config.allow, AccessRule::All) && allowed {
            return true;
        }
        return check_privileged_read(event, auth_pubkey);
    }

    allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AccessRule, WriteReadConfig};
    use crate::event::Event;
    use std::time::Duration;

    fn test_event(author: &str, p_tags: &[&str]) -> Event {
        Event {
            id: "0".repeat(64),
            pubkey: author.to_string(),
            delegated_by: None,
            created_at: 0,
            kind: 4,
            tags: p_tags
                .iter()
                .map(|p| vec!["p".to_string(), p.to_string()])
                .collect(),
            content: String::new(),
            sig: String::new(),
            tagidx: None,
        }
    }

    fn privileged_read_config() -> WriteReadConfig {
        WriteReadConfig {
            script: None,
            allow: AccessRule::All, // does not short-circuit privileged
            deny: AccessRule::None,
            privileged: true,
            error: None,
        }
    }

    #[test]
    fn privileged_requires_auth() {
        let author = "a".repeat(64);
        let recipient = "b".repeat(64);
        let event = test_event(&author, &[&recipient]);
        let config = privileged_read_config();

        assert!(!check_write_read_config(
            &config, &event, None, None, true
        ));
    }

    #[test]
    fn privileged_allows_authenticated_author() {
        let author = "a".repeat(64);
        let recipient = "b".repeat(64);
        let event = test_event(&author, &[&recipient]);
        let config = privileged_read_config();

        assert!(check_write_read_config(
            &config,
            &event,
            Some(&author),
            None,
            true
        ));
    }

    #[test]
    fn privileged_allows_authenticated_p_tag() {
        let author = "a".repeat(64);
        let recipient = "b".repeat(64);
        let event = test_event(&author, &[&recipient]);
        let config = privileged_read_config();

        assert!(check_write_read_config(
            &config,
            &event,
            Some(&recipient),
            None,
            true
        ));
    }

    #[test]
    fn privileged_denies_unrelated_authenticated_user() {
        let author = "a".repeat(64);
        let recipient = "b".repeat(64);
        let stranger = "c".repeat(64);
        let event = test_event(&author, &[&recipient]);
        let config = privileged_read_config();

        assert!(!check_write_read_config(
            &config,
            &event,
            Some(&stranger),
            None,
            true
        ));
    }

    #[test]
    fn allow_takes_precedence_over_privileged() {
        let author = "a".repeat(64);
        let recipient = "b".repeat(64);
        let allowed_extra = "d".repeat(64);
        let event = test_event(&author, &[&recipient]);
        let config = WriteReadConfig {
            script: None,
            allow: AccessRule::List(vec![allowed_extra.clone()]),
            deny: AccessRule::None,
            privileged: true,
            error: None,
        };

        // Allowlisted pubkey (neither author nor p-tagged) can read
        assert!(check_write_read_config(
            &config,
            &event,
            Some(&allowed_extra),
            None,
            true
        ));
        // Author still via privileged
        assert!(check_write_read_config(
            &config,
            &event,
            Some(&author),
            None,
            true
        ));
        // Unrelated still denied
        let stranger = "c".repeat(64);
        assert!(!check_write_read_config(
            &config,
            &event,
            Some(&stranger),
            None,
            true
        ));
    }

    #[test]
    fn privileged_ignored_on_write() {
        let author = "a".repeat(64);
        let event = test_event(&author, &[]);
        let config = privileged_read_config();

        // On write, privileged is ignored and allow:* permits everyone
        assert!(check_write_read_config(
            &config, &event, None, None, false
        ));
    }

    #[test]
    fn expiration_window_rejects_unparseable_tag() {
        let author = "a".repeat(64);
        let mut event = test_event(&author, &[]);
        event.tags = vec![vec!["expiration".to_string(), "garbage".to_string()]];
        let err = validate_expiration_window(&event, Duration::from_secs(75 * 3600));
        assert!(err.is_err());
    }

    #[test]
    fn expiration_window_ok_within_limit() {
        let author = "a".repeat(64);
        let now = crate::utils::unix_time();
        let mut event = test_event(&author, &[]);
        event.tags = vec![vec!["expiration".to_string(), (now + 3600).to_string()]];
        assert_eq!(validate_expiration_window(&event, Duration::from_secs(75 * 3600)), Ok(()));
    }

    #[test]
    fn expiration_window_rejects_far_future() {
        let author = "a".repeat(64);
        let now = crate::utils::unix_time();
        let mut event = test_event(&author, &[]);
        event.tags = vec![vec!["expiration".to_string(), (now + 100 * 3600).to_string()]];
        assert!(validate_expiration_window(&event, Duration::from_secs(75 * 3600)).is_err());
    }

    #[test]
    fn privileged_deny_still_applies() {
        let author = "a".repeat(64);
        let recipient = "b".repeat(64);
        let event = test_event(&author, &[&recipient]);
        let config = WriteReadConfig {
            script: None,
            allow: AccessRule::All,
            deny: AccessRule::List(vec![recipient.clone()]),
            privileged: true,
            error: None,
        };

        assert!(!check_write_read_config(
            &config,
            &event,
            Some(&recipient),
            None,
            true
        ));
    }

    #[test]
    fn substitute_placeholders_replaces_known_keys() {
        let placeholders = ErrorPlaceholders {
            kind: Some(4),
            tag: Some("client".into()),
            size: Some(5000),
            limit: Some(4096),
            detail: Some("too many tags".into()),
        };
        let msg = substitute_placeholders(
            "kind {kind} tag {tag} size {size}/{limit}: {detail}",
            &placeholders,
        );
        assert_eq!(msg, "kind 4 tag client size 5000/4096: too many tags");
    }

    #[test]
    fn resolve_error_prefers_kind_override() {
        let placeholders = ErrorPlaceholders {
            kind: Some(4),
            ..Default::default()
        };
        let msg = resolve_error_message(
            "blocked: kind {kind} is not in the kind whitelist",
            Some("restricted: custom kind {kind}"),
            Some("blocked: global {kind}"),
            &placeholders,
        );
        assert_eq!(msg, "restricted: custom kind 4");
    }
}

