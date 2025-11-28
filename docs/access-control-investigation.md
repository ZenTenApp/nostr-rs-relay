# Access Control Investigation

This document investigates three access control cases and how they can be implemented in `nostr-rs-relay`.

## Case 1: Only Certain Approved npubs Can Write Certain Kinds

### Current State
The relay already supports external authorization via gRPC. The `EventAdmit` RPC receives:
- Event pubkey (as bytes)
- Event kind
- Event tags
- Other metadata (IP, origin, user-agent, auth_pubkey, NIP-05)

### Implementation Approach

**Option A: External gRPC Service (Recommended)**

The gRPC service can check if a pubkey is allowed to write a specific kind. Example implementation:

```rust
// In your gRPC authorization service
async fn event_admit(
    &self,
    request: Request<EventRequest>,
) -> Result<Response<EventReply>, Status> {
    let req = request.into_inner();
    let event = req.event.unwrap();
    
    // Convert pubkey bytes to hex string
    let pubkey_hex = hex::encode(&event.pubkey);
    
    // Check if this pubkey is allowed to write this kind
    let allowed = self.is_pubkey_allowed_for_kind(&pubkey_hex, event.kind);
    
    let reply = if allowed {
        EventReply {
            decision: Decision::Permit as i32,
            message: None,
        }
    } else {
        EventReply {
            decision: Decision::Deny as i32,
            message: Some(format!(
                "Pubkey {} is not authorized to write kind {}",
                pubkey_hex.chars().take(16).collect::<String>(),
                event.kind
            )),
        }
    };
    
    Ok(Response::new(reply))
}
```

**Configuration needed:**
- Define mappings of `(pubkey, kind)` pairs that are allowed
- Store in database, config file, or in-memory structure

**Where it's checked:**
- In `src/db.rs` in the `db_writer` function, after NIP-05 validation and before event persistence
- See lines 343-382 in `src/db.rs`

### Current Flow
1. Event received from client
2. Basic validation (signature, timestamp)
3. Whitelist check (if enabled)
4. Pay-to-relay check (if enabled)
5. NIP-05 verification (if enabled)
6. **gRPC authorization check** ← Case 1 would be implemented here
7. Event persisted to database

## Case 2: Certain Kinds Require Certain Tags to be Included

### Current State
The gRPC service receives all event tags in the `EventRequest`. Tags are provided as `repeated TagEntry`, where each `TagEntry` contains `repeated string values`.

### Implementation Approach

**Option A: External gRPC Service (Recommended)**

Validate required tags in the gRPC authorization service:

```rust
async fn event_admit(
    &self,
    request: Request<EventRequest>,
) -> Result<Response<EventReply>, Status> {
    let req = request.into_inner();
    let event = req.event.unwrap();
    
    // Check if this kind requires specific tags
    if let Some(required_tags) = self.get_required_tags_for_kind(event.kind) {
        for (tag_name, required_values) in required_tags {
            // Find tags with this name
            let found_tag = event.tags.iter()
                .find(|tag| tag.values.len() > 0 && tag.values[0] == tag_name);
            
            match found_tag {
                Some(tag) => {
                    // Check if any of the required values are present
                    let has_required_value = required_values.iter()
                        .any(|req_val| tag.values.iter().skip(1).any(|v| v == req_val));
                    
                    if !has_required_value {
                        return Ok(Response::new(EventReply {
                            decision: Decision::Deny as i32,
                            message: Some(format!(
                                "Kind {} requires tag '{}' with one of these values: {:?}",
                                event.kind, tag_name, required_values
                            )),
                        }));
                    }
                }
                None => {
                    return Ok(Response::new(EventReply {
                        decision: Decision::Deny as i32,
                        message: Some(format!(
                            "Kind {} requires tag '{}'",
                            event.kind, tag_name
                        )),
                    }));
                }
            }
        }
    }
    
    // All required tags present
    Ok(Response::new(EventReply {
        decision: Decision::Permit as i32,
        message: None,
    }))
}
```

**Example configuration:**
```rust
// Example: Kind 30023 (long-form articles) requires "d" tag
// Example: Kind 4 (DMs) requires "p" tag with recipient pubkey
fn get_required_tags_for_kind(&self, kind: u64) -> Option<HashMap<String, Vec<String>>> {
    match kind {
        30023 => {
            let mut tags = HashMap::new();
            tags.insert("d".to_string(), vec![]); // "d" tag required, any value
            Some(tags)
        }
        4 => {
            let mut tags = HashMap::new();
            tags.insert("p".to_string(), vec![]); // "p" tag required
            Some(tags)
        }
        _ => None
    }
}
```

**Where it's checked:**
- Same location as Case 1: in the gRPC authorization check (lines 343-382 in `src/db.rs`)

## Case 3: Certain Kinds Can Only Be Read by Creator and "Receiver"

### Current State
Read access control is **limited**. The `allowed_to_send()` function in `src/server.rs` only filters DMs (kinds 4, 44, 1059) when `nip42_dms` is enabled. There's no general mechanism for restricting read access based on event kind and participant identity.

### Implementation Approach

**This requires code changes to the relay**, as there's currently no gRPC interface for read authorization.

### Current Read Flow
1. Client sends `REQ` message with subscription filters
2. Subscription registered in `ClientConn`
3. Database query executed (if `needs_historical_events()`)
4. Results sent to client via `allowed_to_send()` check
5. Real-time events also filtered through `allowed_to_send()`

### Implementation Strategy

**Option A: Extend `allowed_to_send()` function**

Modify the `allowed_to_send()` function in `src/server.rs` to handle additional kinds:

```rust
fn allowed_to_send(event_str: &str, conn: &conn::ClientConn, settings: &Settings) -> bool {
    // Parse the event
    let event: Event = match serde_json::from_str(event_str) {
        Ok(e) => e,
        Err(_) => return false,
    };
    
    // Get authenticated pubkey if available
    let auth_pubkey = conn.auth_pubkey();
    
    // Check if this kind requires restricted read access
    let restricted_kinds = settings.authorization.restricted_read_kinds.as_ref();
    if let Some(restricted) = restricted_kinds {
        if restricted.contains(&event.kind) {
            // This kind requires authentication and participant check
            match auth_pubkey {
                Some(auth_pk) => {
                    // Check if authenticated user is creator
                    if auth_pk == &event.pubkey {
                        return true; // Creator can always read
                    }
                    
                    // Check if authenticated user is a "receiver"
                    // This depends on the event kind and tag structure
                    if is_receiver(&event, auth_pk) {
                        return true;
                    }
                    
                    // Not creator or receiver
                    return false;
                }
                None => {
                    // Not authenticated, deny access
                    return false;
                }
            }
        }
    }
    
    // Existing DM filtering logic
    if settings.authorization.nip42_dms {
        if event.kind == 4 || event.kind == 44 || event.kind == 1059 {
            match (auth_pubkey, event.tag_values_by_name("p").first()) {
                (Some(auth_pubkey), Some(recipient_pubkey)) => {
                    return recipient_pubkey == auth_pubkey || &event.pubkey == auth_pubkey;
                }
                (_, _) => return false,
            }
        }
    }
    
    // Default: allow
    true
}

/// Determine if the given pubkey is a "receiver" of this event
fn is_receiver(event: &Event, pubkey: &str) -> bool {
    // This depends on the event kind and how "receiver" is defined
    // Common patterns:
    // - "p" tag for DMs and mentions
    // - "e" tag for replies (original author is receiver)
    // - Custom tags for other event types
    
    match event.kind {
        4 | 44 | 1059 => {
            // DMs: check "p" tag
            event.tag_values_by_name("p").contains(&pubkey.to_string())
        }
        1 => {
            // Text notes: check "p" tags for mentions
            event.tag_values_by_name("p").contains(&pubkey.to_string())
        }
        6 => {
            // Reposts: check "p" tag of original author
            event.tag_values_by_name("p").contains(&pubkey.to_string())
        }
        _ => {
            // For other kinds, check "p" tag as default
            event.tag_values_by_name("p").contains(&pubkey.to_string())
        }
    }
}
```

**Configuration needed:**

Add to `config.toml`:
```toml
[authorization]
# Kinds that require authentication and participant check for reading
restricted_read_kinds = [4, 44, 1059, 30000]  # Example: DMs and custom kind 30000
```

Add to `src/config.rs`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub pubkey_whitelist: Option<Vec<String>>,
    pub nip42_auth: bool,
    pub nip42_dms: bool,
    pub restricted_read_kinds: Option<Vec<u64>>,  // New field
}
```

**Where it's checked:**
- Line 1203 in `src/server.rs`: When sending query results to client
- Line 1222 in `src/server.rs`: When sending real-time events to client

**Option B: Add gRPC Read Authorization (Future Enhancement)**

This would require:
1. New gRPC RPC: `QueryAuthorize` or `EventRead`
2. Called before sending events to clients
3. Receives: event, authenticated pubkey, subscription filters
4. Returns: permit/deny decision

This is more flexible but requires more infrastructure.

### Considerations for Case 3

1. **Performance**: Read filtering happens for every event sent to every client. This could impact performance if many restricted events exist.

2. **Query Filtering**: Currently, database queries return all matching events, then they're filtered when sent. For better performance, you might want to filter at the database level, but this is more complex.

3. **Receiver Identification**: The definition of "receiver" varies by event kind:
   - DMs (kind 4): "p" tag contains recipient
   - Mentions (kind 1): "p" tags contain mentioned users
   - Replies (kind 1): Original author (from "e" tag's referenced event)
   - Custom kinds: Depends on tag structure

4. **Authentication Requirement**: Case 3 requires NIP-42 authentication to be enabled (`nip42_auth = true`).

## Summary

| Case | Implementation | Complexity | Requires Code Changes |
|------|---------------|------------|---------------------|
| 1. npub + kind restrictions | gRPC service | Low | No (external service) |
| 2. Required tags for kinds | gRPC service | Low | No (external service) |
| 3. Read access restrictions | Extend `allowed_to_send()` | Medium | Yes (relay code) |

## Next Steps

1. **For Cases 1 & 2**: Implement a gRPC authorization service using the example code above
2. **For Case 3**: 
   - Add `restricted_read_kinds` to config
   - Extend `allowed_to_send()` function
   - Implement `is_receiver()` helper
   - Test with various event kinds and tag structures

