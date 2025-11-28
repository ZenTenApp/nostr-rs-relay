# Access Control Implementation Summary

This document provides a quick reference for implementing the three access control cases.

## Quick Reference

| Case | Solution | Files to Modify | Complexity |
|------|----------|----------------|------------|
| **1. npub + kind restrictions** | gRPC service | External service only | Low |
| **2. Required tags for kinds** | gRPC service | External service only | Low |
| **3. Read access restrictions** | Relay code changes | `src/server.rs`, `src/config.rs`, `config.toml` | Medium |

## Case 1: Only Certain Approved npubs Can Write Certain Kinds

### Implementation
Use the advanced gRPC authorization service example: `examples/nauthz-advanced/`

### Configuration
1. Build and run the gRPC service:
   ```bash
   cd examples/nauthz-advanced
   cargo build --release
   ./target/release/nauthz-advanced
   ```

2. Configure relay in `config.toml`:
   ```toml
   [grpc]
   event_admission_server = "http://[::1]:50051"
   ```

3. Customize rules in `examples/nauthz-advanced/src/main.rs`:
   ```rust
   // Add pubkey:kind mappings
   allowed_pubkey_kinds.insert("pubkey_hex:kind_number".to_string());
   ```

### Where It's Enforced
- In `src/db.rs` lines 343-382 (gRPC authorization check)

## Case 2: Certain Kinds Require Certain Tags

### Implementation
Same as Case 1 - use the advanced gRPC authorization service.

### Configuration
Customize in `examples/nauthz-advanced/src/main.rs`:
```rust
// Add required tag rules
let mut kind_30023_tags = HashMap::new();
kind_30023_tags.insert("d".to_string(), vec![]); // "d" tag required, any value
required_tags.insert(30023, kind_30023_tags);
```

### Where It's Enforced
- Same location as Case 1: `src/db.rs` lines 343-382

## Case 3: Certain Kinds Can Only Be Read by Creator and Receiver

### Implementation
Requires modifying relay code. See `docs/case3-read-access-example.rs` for reference implementation.

### Steps to Implement

1. **Add config field** in `src/config.rs`:
   ```rust
   pub struct Authorization {
       // ... existing fields ...
       pub restricted_read_kinds: Option<Vec<u64>>,  // NEW
   }
   ```

2. **Update config.toml**:
   ```toml
   [authorization]
   restricted_read_kinds = [4, 44, 1059, 30000]  # Kinds requiring auth to read
   ```

3. **Modify `allowed_to_send()`** in `src/server.rs`:
   - See `docs/case3-read-access-example.rs` for the implementation
   - Add check for `restricted_read_kinds`
   - Implement `is_receiver()` helper function

4. **Ensure NIP-42 auth is enabled**:
   ```toml
   [authorization]
   nip42_auth = true  # Required for read restrictions
   ```

### Where It's Enforced
- `src/server.rs` line 1203: When sending query results
- `src/server.rs` line 1222: When sending real-time events

## Testing

### Test Case 1 & 2 (gRPC)
1. Start the gRPC service
2. Configure relay to use it
3. Try publishing events:
   - Unauthorized pubkey + kind → should be rejected
   - Missing required tags → should be rejected
   - Valid events → should be accepted

### Test Case 3 (Read Restrictions)
1. Enable `nip42_auth = true`
2. Configure `restricted_read_kinds`
3. Test scenarios:
   - Unauthenticated client queries restricted kind → should get no results
   - Authenticated as creator → should see events
   - Authenticated as receiver → should see events
   - Authenticated as unrelated user → should not see events

## Files Created/Modified

### New Files
- `docs/access-control-investigation.md` - Detailed investigation
- `docs/access-control-summary.md` - This file
- `docs/case3-read-access-example.rs` - Code example for Case 3
- `examples/nauthz-advanced/` - Advanced gRPC service example

### Files That May Need Modification
- `src/config.rs` - Add `restricted_read_kinds` field (Case 3)
- `src/server.rs` - Modify `allowed_to_send()` (Case 3)
- `config.toml` - Add configuration options

## Next Steps

1. **For Cases 1 & 2**: 
   - Review and customize `examples/nauthz-advanced/src/main.rs`
   - Build and deploy the gRPC service
   - Configure relay to use it

2. **For Case 3**:
   - Review `docs/case3-read-access-example.rs`
   - Implement changes in relay code
   - Test thoroughly with various event kinds and tag structures
   - Consider performance implications for high-traffic relays

## Notes

- Cases 1 & 2 can be implemented without modifying relay code
- Case 3 requires relay code changes
- All cases require NIP-42 authentication to be enabled for proper user identification
- The gRPC service uses a "fail open" policy - if the service is unavailable, events are permitted
- Read restrictions (Case 3) apply to both historical queries and real-time events

