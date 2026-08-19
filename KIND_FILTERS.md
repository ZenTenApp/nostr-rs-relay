# Kind Filters

Kind filters allow you to configure per-kind access control, rate limiting, expiration, and other rules for Nostr events.

## Configuration

Kind filters are configured via a JSON file specified in `config.toml` under `[kind_filters_config]`:

```toml
[kind_filters_config]
config_file = ".config/kinds.json"
```

## JSON Structure

The configuration file has two main sections:

1. **`kinds`** - Global kind whitelist/blacklist (optional)
2. **Per-kind sections** - Configuration for specific event kinds (keyed by kind number as string)

```json
{
  "kinds": {
    "whitelist": [1, 4, 30000],
    "blacklist": [70202]
  },
  "1": {
    "description": "Text notes",
    "write": { "allow": "*" },
    "read": { "allow": "*" },
    "max_size": "10MB",
    "expiration": "never",
    "rate_limit": "10/min"
  }
}
```

## Write/Read Sections

Each kind can have separate `write` and `read` configurations that control who can publish and who can query events of that kind.

### Write Configuration

Controls who can publish events of this kind to the relay.

```json
{
  "write": {
    "script": ".config/filter.sh",
    "allow": "*",
    "deny": "none"
  }
}
```

### Read Configuration

Controls who can query/retrieve events of this kind from the relay.

```json
{
  "read": {
    "allow": ["pubkey1", "pubkey2"],
    "deny": "none",
    "privileged": true
  }
}
```

### Access Rules

Both `write` and `read` support `allow` and `deny` rules:

- **`"allow": "*"` or `"allow": "all"`** - Allow everyone
- **`"allow": "none"`** - Allow no one
- **`"allow": ["pubkey1", "pubkey2"]`** - Allow specific pubkeys (64-character hex strings)
- **`"allow": "private_server_hex"`** - Special identifier that matches the server's configured pubkey

The same format applies to `deny`. Deny rules take precedence over allow rules.

**Evaluation order:**

1. Script execution (if present) - if script denies, access is denied
2. Deny rule check - if denied, access is denied
3. Allow rule check - explicit allow entries are granted first
4. If `privileged: true` on read - AUTH'd author or AUTH'd `p`-tag users (see below)
5. Otherwise access is denied

## Privileged Read Access

When `privileged: true` is set in the `read` configuration, these authenticated clients can receive the event:

1. An authenticated client whose pubkey is the **event author**
2. An authenticated client whose pubkey appears in a **`p` tag**

**`allow` takes precedence:** pubkeys listed in `allow` can also read, even if they are neither the author nor in a `p` tag.

`"allow": "*"` (the default when `allow` is omitted) does **not** override `privileged` — otherwise privileged would be useless. Use an explicit pubkey list to grant extra readers.

Everyone else is denied, including unauthenticated clients (unless granted via an explicit `allow` list match). NIP-42 auth must be enabled for author/`p`-tag access:

```toml
[authorization]
nip42_auth = true
```

This is useful for:

- **Direct Messages / private kinds** - Author and addressed parties only
- **Mentions** - Author and users listed in `p` tags
- **Custom event types** - Any event where access should be limited to participants, plus optional allowlisted readers

```json
{
  "4": {
    "description": "Direct messages",
    "read": {
      "allow": ["moderator_pubkey_hex"],
      "privileged": true
    }
  }
}
```

In this example:

- Authenticated author can read
- Authenticated users listed in `p` tags can read
- Users in `allow` can read (even if not author/`p`-tagged)
- All other users are denied

## Per-Kind Configuration

Each kind number (as a string) can have its own configuration section:

```json
{
  "1": {
    "description": "Text notes",
    "write": { "allow": "*" },
    "read": { "allow": "*" },
    "max_size": "10MB",
    "expiration": "10m",
    "rate_limit": "5/min",
    "d_tag": "none",
    "p_tag": "none",
    "required_tags": ["e"]
  }
}
```

### Available Options

- **`description`** (optional) - Human-readable description of the kind
- **`write`** (optional) - Write access configuration
- **`read`** (optional) - Read access configuration
- **`max_size`** (optional) - Maximum event size (see Max Size section)
- **`expiration`** (optional) - Server-side TTL; rejects events already past this age (see Expiration section)
- **`max_expiration`** (optional) - Maximum allowed NIP-40 expiration window; rejects events whose `expiration` tag is set too far in the future (see Max Expiration section)
- **`rate_limit`** (optional) - Rate limiting (see Rate Limiting section)
- **`require_auth`** (optional) - If `true`, NIP-42 authentication is required to publish (see Authenticated Writes section)
- **`rate_limits`** (optional) - List of keyed rate-limit rules per window/scope (see Keyed Rate Limiting section)
- **`tag_limits`** (optional) - Per-kind tag size restrictions (see Tag Restrictions section)
- **`d_tag`** (optional) - Requirement for `d` tag (see Tag Requirements section)
- **`p_tag`** (optional) - Requirement for `p` tag (see Tag Requirements section)
- **`required_tags`** (optional) - List of tag names that must be present (see Tag Requirements section)

## Expiration

Events can be automatically expired (deleted) after a specified duration. This helps manage storage and enforce time-based access policies.

**Format:** Duration string or `"never"`

Examples:

- `"never"` - Events never expire (default)
- `"10m"` - Expire after 10 minutes
- `"1h"` - Expire after 1 hour
- `"24h"` - Expire after 24 hours
- `"7d"` - Expire after 7 days
- `"30 days"` - Expire after 30 days

The configured `expiration` is a **server-side TTL**: the event is computed to expire at `created_at + expiration` and is rejected at publish time if that time has already passed, and excluded from read results once it has. Separately, an event's NIP-40 `expiration` tag value is honored on the read path too: an event whose `expiration` tag has passed is excluded from queries/delivery in addition to being filtered out by the stored `expires_at` column, so read results never include an expired event.

```json
{
  "1": {
    "expiration": "24h"
  }
}
```

## Max Expiration

Limit how far in the future a client is allowed to set the NIP-40 `expiration` tag on an incoming event. If the event's `expiration` tag value is further in the future than `now + max_expiration`, the event is **rejected at publish time**.

This is useful for preventing clients from publishing events that would be stored indefinitely (or for an unreasonably long time) by setting a very far-future expiration.

**Format:** Duration string or `"never"` (default — no limit enforced)

**Important notes:**

- This is **optional**. If absent or set to `"never"`, no limit is enforced.
- Only events that **have** a NIP-40 `expiration` tag are checked. Events with no expiration tag are **not** affected.
- If an `expiration` tag is present but its value is not a valid numeric timestamp, the event is rejected (`invalid: expiration tag is not a valid timestamp`). This prevents bypassing the window cap with a non-numeric value.
- Uses the same duration string format as `expiration`.

Examples:

- `"never"` - No limit (default)
- `"30d"` - Reject events whose expiration tag is more than 30 days from now
- `"7d"` - Reject events whose expiration tag is more than 7 days from now
- `"1h"` - Reject events whose expiration tag is more than 1 hour from now

```json
{
  "1": {
    "max_expiration": "30d"
  }
}
```

Rejection OK message: `blocked: expiration exceeds max_expiry_duration`

## Max Size

Limit the maximum size of events for a specific kind. Events exceeding this size will be rejected.

**Format:** Size string with unit (KB, MB, GB) or bytes

Examples:

- `"10MB"` - Maximum 10 megabytes
- `"512KB"` - Maximum 512 kilobytes
- `"1GB"` - Maximum 1 gigabyte
- `"1024"` - Maximum 1024 bytes (if no unit, assumes bytes)

```json
{
  "1": {
    "max_size": "10MB"
  }
}
```

## Script Paths

**Important:** Script paths in the JSON configuration must be relative to the root directory of the relay.

Scripts can be used for custom access control logic. They receive:

- **Event JSON** via stdin
- **`AUTH_PUBKEY`** environment variable (if user is authenticated)

Exit code 0 allows the event; any non-zero exit code denies it.

```json
{
  "write": {
    "script": ".config/filter.sh"
  }
}
```

Scripts are evaluated first, before allow/deny rules. If a script denies access, the event is rejected regardless of other rules.

## Rate Limiting

Limit the number of events that can be published per minute for a specific kind.

**Format:** `"N/min"` or `"N/minute"` or `"none"`

Examples:

- `"10/min"` - Maximum 10 events per minute
- `"5/minute"` - Maximum 5 events per minute
- `"none"` - No rate limiting

```json
{
  "1": {
    "rate_limit": "10/min"
  }
}

## Keyed Rate Limiting

Enforce multiple rate-limit rules per kind, with sliding windows and
per-key buckets. This is the richer rule format supporting hourly,
daily, per-pubkey, and per-IP limits simultaneously.

**Format:** array of rule objects:

- **`limit`** (required) - Maximum events allowed in the window
- **`window`** (required) - `"1m"` (minute), `"1h"` (hour), or `"1d"` (day)
- **`scope`** (required) - `"global"` (shared bucket for the kind),
  `"npub"` (keyed by event author pubkey), or `"ip"` (keyed by client IP)

Every configured rule must pass; if any rule is exceeded, the event is
rejected. Each rule is an independent sliding-window counter.

```json
{
  "4": {
    "rate_limits": [
      { "limit": 300,  "window": "1h", "scope": "npub" },
      { "limit": 1000, "window": "1d", "scope": "npub" },
      { "limit": 900,  "window": "1h", "scope": "ip" },
      { "limit": 2500, "window": "1d", "scope": "ip" }
    ]
  }
}
```

## Authenticated Writes

Require NIP-42 authentication before a client may publish events of a
kind. Set `require_auth: true` on the kind:

```json
{
  "4": {
    "require_auth": true
  }
}
```

When enabled, unauthenticated clients are rejected at publish time with
`authentication required to publish this kind`. Reads are also denied to
unauthenticated clients when `require_auth` is set. NIP-42 auth must be
enabled globally for this to work:

```toml
[authorization]
nip42_auth = true
```

## Tag Restrictions

Limit the number of tags and the size of tag names/values for a kind.
A value of `0` disables that dimension. This also caps the size of the
required `expiration` and `client` tags.

**Fields:**

- **`max_tags`** - Maximum number of tags on the event
- **`max_tag_name_chars`** - Max characters in each tag name (e.g. `p`)
- **`max_tag_value_chars`** - Max characters in each tag value

```json
{
  "4": {
    "tag_limits": {
      "max_tags": 32,
      "max_tag_name_chars": 32,
      "max_tag_value_chars": 128
    }
  }
}
```

## Tag Requirements

Require specific tags to be present in events of a kind.

### d_tag

Requirement for the `d` tag (used for parameterized replaceable events):

- `"none"` - No requirement (default)
- `"required"` - Tag must exist with any value
- `"hex"` - Tag must exist with a valid 64-character hex value

```json
{
  "30023": {
    "d_tag": "required"
  }
}
```

### p_tag

Requirement for the `p` tag (used for pubkey references):

- `"none"` - No requirement (default)
- `"required"` - Tag must exist with any value
- `"hex"` - Tag must exist with at least one valid 64-character hex value

```json
{
  "4": {
    "p_tag": "hex"
  }
}
```

### required_tags

List of arbitrary tag names that must be present on the event. Each listed tag must exist with at least one value; there is no hex or value validation.

```json
{
  "30023": {
    "required_tags": ["e", "title"]
  }
}
```

If a required tag is missing, the event is rejected with
`invalid: missing required tag: title`.

## Rejection OK Messages

When a kind-filter check rejects an event, the relay responds with a NIP-01
`["OK", id, false, "<prefix>: <detail>"]` message. Defaults follow orly-style
prefixes:

| Check | Default OK message |
| --- | --- |
| Kind not in whitelist | `blocked: kind {kind} is not in the kind whitelist` |
| Kind blacklisted | `blocked: kind {kind} is blacklisted` |
| Write allow/deny | `restricted: pubkey is not allowed to write this kind` |
| `require_auth` | `auth-required: authentication required to publish this kind` |
| `max_size` | `blocked: event exceeds size limit ({size} > {limit})` |
| `required_tags` | `invalid: missing required tag: {tag}` |
| `p_tag` | `invalid: p tag requirement not met` |
| `d_tag` | `invalid: missing d tag` |
| Invalid expiration tag | `invalid: expiration tag is not a valid timestamp` |
| `max_expiration` | `blocked: expiration exceeds max_expiry_duration` |
| Kind `expiration` elapsed | `blocked: event has expired` |
| Tag limits | `invalid: {detail}` |
| Rate limits | `rate-limited: rate limit exceeded for this kind` |

### Optional overrides

You can override any of these strings under `kinds.errors` (global) or a
per-kind `errors` object. `write.error` / `read.error` override write/read
denials for that section. Placeholders: `{kind}`, `{tag}`, `{size}`, `{limit}`,
`{detail}`. If the override already includes a NIP-01 prefix (`blocked:`,
`invalid:`, `auth-required:`, etc.), it is sent as-is.

```json
{
  "kinds": {
    "whitelist": [4],
    "errors": {
      "not_in_whitelist": "blocked: kind {kind} is not in the kind whitelist"
    }
  },
  "4": {
    "write": {
      "allow": "*",
      "error": "restricted: not allowed to write kind 4"
    },
    "errors": {
      "auth_required": "auth-required: authentication required to publish this kind",
      "max_size": "blocked: event exceeds size limit ({size} > {limit})",
      "missing_tag": "invalid: missing required tag: {tag}",
      "expiration": "blocked: expiration exceeds max_expiry_duration",
      "rate_limited": "rate-limited: rate limit exceeded for this kind"
    }
  }
}
```

Keys: `not_in_whitelist`, `blacklisted`, `write`, `auth_required`, `max_size`,
`missing_tag`, `p_tag`, `d_tag`, `expiration`, `expiration_invalid`, `expired`,
`rate_limited`, `tag_limits`.

## Global Kind Whitelist/Blacklist

At the top level, you can define a global whitelist or blacklist that applies before per-kind configurations:

```json
{
  "kinds": {
    "whitelist": [1, 4, 30000]
  }
}
```

- **`whitelist`** - Only these kinds are allowed; all others are rejected
- **`blacklist`** - These kinds are rejected; all others are allowed

If both are specified, `whitelist` takes precedence. If neither is specified, all kinds are allowed (subject to per-kind configurations).
