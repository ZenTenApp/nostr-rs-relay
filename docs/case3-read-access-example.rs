//! Example implementation for Case 3: Read access restrictions
//! 
//! This shows how to modify the relay code to restrict read access
//! to certain kinds based on creator and receiver identity.
//! 
//! This code would be added/modified in src/server.rs

use crate::conn::ClientConn;
use crate::event::Event;
use crate::config::Settings;

/// Determine if the given pubkey is a "receiver" of this event
/// 
/// The definition of "receiver" varies by event kind:
/// - DMs (kind 4, 44, 1059): "p" tag contains recipient
/// - Mentions (kind 1): "p" tags contain mentioned users  
/// - Replies (kind 1): Original author (from "e" tag's referenced event)
/// - Custom kinds: Depends on tag structure
fn is_receiver(event: &Event, pubkey: &str) -> bool {
    match event.kind {
        4 | 44 | 1059 => {
            // DMs: check "p" tag for recipient
            event.tag_values_by_name("p").contains(&pubkey.to_string())
        }
        1 => {
            // Text notes: check "p" tags for mentions
            // Could also check "e" tag for reply-to author
            event.tag_values_by_name("p").contains(&pubkey.to_string())
        }
        6 => {
            // Reposts: check "p" tag of original author
            event.tag_values_by_name("p").contains(&pubkey.to_string())
        }
        _ => {
            // For other kinds, check "p" tag as default
            // You may want to customize this based on your event structure
            event.tag_values_by_name("p").contains(&pubkey.to_string())
        }
    }
}

/// Enhanced version of allowed_to_send that supports restricted read kinds
/// 
/// This function is called:
/// 1. When sending query results to clients (line 1203 in server.rs)
/// 2. When sending real-time events to clients (line 1222 in server.rs)
fn allowed_to_send(event_str: &str, conn: &ClientConn, settings: &Settings) -> bool {
    // Parse the event
    let event: Event = match serde_json::from_str(event_str) {
        Ok(e) => e,
        Err(_) => return false,
    };
    
    // Get authenticated pubkey if available
    let auth_pubkey = conn.auth_pubkey();
    
    // Check if this kind requires restricted read access
    if let Some(restricted_kinds) = &settings.authorization.restricted_read_kinds {
        if restricted_kinds.contains(&event.kind) {
            // This kind requires authentication and participant check
            match auth_pubkey {
                Some(auth_pk) => {
                    // Check if authenticated user is creator
                    if auth_pk == &event.pubkey {
                        return true; // Creator can always read
                    }
                    
                    // Check if authenticated user is a "receiver"
                    if is_receiver(&event, auth_pk) {
                        return true;
                    }
                    
                    // Not creator or receiver - deny access
                    return false;
                }
                None => {
                    // Not authenticated, deny access to restricted kinds
                    return false;
                }
            }
        }
    }
    
    // Existing DM filtering logic (keep this for backward compatibility)
    if settings.authorization.nip42_dms {
        if event.kind == 4 || event.kind == 44 || event.kind == 1059 {
            match (auth_pubkey, event.tag_values_by_name("p").first()) {
                (Some(auth_pubkey), Some(recipient_pubkey)) => {
                    return recipient_pubkey == auth_pubkey || &event.pubkey == auth_pubkey;
                }
                (_, _) => return false,
            }
        } else {
            return true;
        }
    }
    
    // Default: allow
    true
}

// Example configuration addition to src/config.rs:
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// #[allow(unused)]
// pub struct Authorization {
//     pub pubkey_whitelist: Option<Vec<String>>,
//     pub nip42_auth: bool,
//     pub nip42_dms: bool,
//     pub restricted_read_kinds: Option<Vec<u64>>,  // NEW: Kinds that require auth to read
// }

// Example config.toml addition:
//
// [authorization]
// # Kinds that require authentication and participant check for reading
// # Only the creator and receivers (identified by tags) can read these events
// restricted_read_kinds = [4, 44, 1059, 30000]

