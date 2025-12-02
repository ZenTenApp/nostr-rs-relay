//! Kind filter evaluation functions
use crate::config::{AccessRule, KindFilters, TagRequirement, WriteReadConfig};
use crate::event::Event;
use log::debug;
use std::process::{Command, Stdio};
use std::io::Write;

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

/// Check if a kind is allowed based on whitelist/blacklist
pub fn is_kind_allowed(kind: u64, filters: &KindFilters) -> bool {
    // If whitelist is present, only allow whitelisted kinds
    if let Some(ref whitelist) = filters.whitelist {
        return whitelist.contains(&kind);
    }
    
    // If only blacklist is present, deny blacklisted kinds
    if let Some(ref blacklist) = filters.blacklist {
        return !blacklist.contains(&kind);
    }
    
    // If neither is present, allow all
    true
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

/// Check if an access rule allows the event, with privileged support
pub fn check_access_rule(
    rule: &AccessRule,
    event: &Event,
    auth_pubkey: Option<&str>,
    server_pubkey: Option<&str>,
    privileged: bool,
) -> bool {
    match rule {
        AccessRule::All => true,
        AccessRule::None => false,
        AccessRule::List(identifiers) => {
            // Check if any identifier matches
            let identifier_match = identifiers
                .iter()
                .any(|id| evaluate_access_identifier(id, event, auth_pubkey, server_pubkey));
            
            // If privileged is true, also check if auth_pubkey is in event's "p" tags
            if privileged && !identifier_match {
                if let Some(auth_pk) = auth_pubkey {
                    let p_tags = event.tag_values_by_name("p");
                    return p_tags.contains(&auth_pk.to_string());
                }
            }
            
            identifier_match
        }
    }
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

    // Check deny rule first (deny takes precedence over allow)
    let denied = check_access_rule(
        &config.deny,
        event,
        auth_pubkey,
        server_pubkey,
        false, // deny doesn't use privileged
    );
    if denied {
        return false;
    }

    // Check allow rule with privileged support for read operations
    let privileged = is_read && config.privileged;
    check_access_rule(
        &config.allow,
        event,
        auth_pubkey,
        server_pubkey,
        privileged,
    )
}

