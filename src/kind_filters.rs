//! Kind filter evaluation functions
use crate::config::{AccessRule, TagRequirement};
use crate::event::Event;

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
        "parties_involved" => {
            // Check if auth_pubkey is in event's "p" tags
            if let Some(auth_pk) = auth_pubkey {
                let p_tags = event.tag_values_by_name("p");
                return p_tags.contains(&auth_pk.to_string());
            }
            false
        }
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
        AccessRule::List(identifiers) => {
            // Check if any identifier matches
            identifiers
                .iter()
                .any(|id| evaluate_access_identifier(id, event, auth_pubkey, server_pubkey))
        }
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

