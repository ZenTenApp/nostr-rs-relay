//! NIP-01 OK / NOTICE envelope helpers.
//!
//! Rejection messages use the machine-readable prefix form `"<prefix>: <detail>"`.
//! Helpers here parse existing prefixes (so they are not doubled) and ensure a
//! fallback prefix when none is present.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventResultStatus {
    Saved,
    Duplicate,
    Invalid,
    Blocked,
    RateLimited,
    Error,
    Restricted,
    AuthRequired,
}

pub struct EventResult {
    pub id: String,
    pub msg: String,
    pub status: EventResultStatus,
}

pub enum Notice {
    Message(String),
    EventResult(EventResult),
    AuthChallenge(String),
}

impl EventResultStatus {
    #[must_use]
    pub fn to_bool(&self) -> bool {
        match self {
            Self::Duplicate | Self::Saved => true,
            Self::Invalid
            | Self::Blocked
            | Self::RateLimited
            | Self::Error
            | Self::Restricted
            | Self::AuthRequired => false,
        }
    }

    #[must_use]
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Saved => "saved",
            Self::Duplicate => "duplicate",
            Self::Invalid => "invalid",
            Self::Blocked => "blocked",
            Self::RateLimited => "rate-limited",
            Self::Error => "error",
            Self::Restricted => "restricted",
            Self::AuthRequired => "auth-required",
        }
    }

    /// Map a NIP-01 machine-readable prefix string to a status.
    #[must_use]
    pub fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "saved" => Some(Self::Saved),
            "duplicate" => Some(Self::Duplicate),
            "invalid" => Some(Self::Invalid),
            "blocked" => Some(Self::Blocked),
            "rate-limited" => Some(Self::RateLimited),
            "error" => Some(Self::Error),
            "restricted" => Some(Self::Restricted),
            "auth-required" => Some(Self::AuthRequired),
            "pow" => Some(Self::Invalid),
            "unsupported" => Some(Self::Error),
            _ => None,
        }
    }
}

/// Known NIP-01 OK/CLOSED prefixes (orly `reason.knownPrefixes`).
const KNOWN_PREFIXES: &[&str] = &[
    "auth-required",
    "pow",
    "duplicate",
    "blocked",
    "rate-limited",
    "invalid",
    "error",
    "unsupported",
    "restricted",
];

/// Split a NIP-01 reason into prefix and detail.
///
/// `found` is true only when `msg` starts with a known prefix followed by `": "`.
#[must_use]
pub fn parse_reason(msg: &str) -> (Option<&'static str>, &str, bool) {
    let Some(i) = msg.find(": ") else {
        return (None, msg, false);
    };
    if i == 0 {
        return (None, msg, false);
    }
    let prefix = &msg[..i];
    for known in KNOWN_PREFIXES {
        if *known == prefix {
            return (Some(*known), &msg[i + 2..], true);
        }
    }
    (None, msg, false)
}

/// Return `msg` unchanged if it already has a known NIP-01 prefix.
/// Empty `msg` becomes `"<fallback>: rejected"`. Otherwise prepend `fallback`.
#[must_use]
pub fn ensure_reason(msg: &str, fallback: EventResultStatus) -> String {
    let fallback_prefix = fallback.prefix();
    if msg.is_empty() {
        return format!("{fallback_prefix}: rejected");
    }
    let (_, _, found) = parse_reason(msg);
    if found {
        return msg.to_string();
    }
    format!("{fallback_prefix}: {msg}")
}

impl Notice {
    #[must_use]
    pub fn message(msg: String) -> Notice {
        Notice::Message(msg)
    }

    /// Build an EventResult, ensuring `msg` has the given status prefix without
    /// double-prefixing when a known prefix is already present.
    fn prefixed(id: String, msg: &str, status: EventResultStatus) -> Notice {
        let msg = ensure_reason(msg, status);
        let status = match parse_reason(&msg) {
            (Some(prefix), _, true) => EventResultStatus::from_prefix(prefix).unwrap_or(status),
            _ => status,
        };
        Notice::EventResult(EventResult { id, msg, status })
    }

    /// Send an OK rejection whose message already carries (or will get) a NIP-01
    /// prefix. Defaults to `blocked` when no known prefix is present.
    #[must_use]
    pub fn from_reason(id: String, msg: &str) -> Notice {
        let msg = ensure_reason(msg, EventResultStatus::Blocked);
        let status = match parse_reason(&msg) {
            (Some(prefix), _, true) => {
                EventResultStatus::from_prefix(prefix).unwrap_or(EventResultStatus::Blocked)
            }
            _ => EventResultStatus::Blocked,
        };
        Notice::EventResult(EventResult { id, msg, status })
    }

    #[must_use]
    pub fn invalid(id: String, msg: &str) -> Notice {
        Notice::prefixed(id, msg, EventResultStatus::Invalid)
    }

    #[must_use]
    pub fn blocked(id: String, msg: &str) -> Notice {
        Notice::prefixed(id, msg, EventResultStatus::Blocked)
    }

    #[must_use]
    pub fn rate_limited(id: String, msg: &str) -> Notice {
        Notice::prefixed(id, msg, EventResultStatus::RateLimited)
    }

    #[must_use]
    pub fn auth_required(id: String, msg: &str) -> Notice {
        Notice::prefixed(id, msg, EventResultStatus::AuthRequired)
    }

    #[must_use]
    pub fn duplicate(id: String) -> Notice {
        Notice::prefixed(id, "", EventResultStatus::Duplicate)
    }

    #[must_use]
    pub fn error(id: String, msg: &str) -> Notice {
        Notice::prefixed(id, msg, EventResultStatus::Error)
    }

    #[must_use]
    pub fn restricted(id: String, msg: &str) -> Notice {
        Notice::prefixed(id, msg, EventResultStatus::Restricted)
    }

    #[must_use]
    pub fn saved(id: String) -> Notice {
        Notice::EventResult(EventResult {
            id,
            msg: "".into(),
            status: EventResultStatus::Saved,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_prefix() {
        let (p, d, found) = parse_reason("invalid: missing required tag: e");
        assert!(found);
        assert_eq!(p, Some("invalid"));
        assert_eq!(d, "missing required tag: e");
    }

    #[test]
    fn parse_unknown_prefix() {
        let (p, d, found) = parse_reason("nope: something");
        assert!(!found);
        assert_eq!(p, None);
        assert_eq!(d, "nope: something");
    }

    #[test]
    fn ensure_does_not_double_prefix() {
        let msg = ensure_reason("invalid: missing required tag: e", EventResultStatus::Blocked);
        assert_eq!(msg, "invalid: missing required tag: e");
    }

    #[test]
    fn ensure_prepends_fallback() {
        let msg = ensure_reason("event has expired", EventResultStatus::Blocked);
        assert_eq!(msg, "blocked: event has expired");
    }

    #[test]
    fn ensure_empty() {
        let msg = ensure_reason("", EventResultStatus::Blocked);
        assert_eq!(msg, "blocked: rejected");
    }

    #[test]
    fn from_reason_uses_existing_prefix() {
        let n = Notice::from_reason("abc".into(), "auth-required: login first");
        match n {
            Notice::EventResult(r) => {
                assert_eq!(r.msg, "auth-required: login first");
                assert!(matches!(r.status, EventResultStatus::AuthRequired));
                assert!(!r.status.to_bool());
            }
            _ => panic!("expected EventResult"),
        }
    }

    #[test]
    fn blocked_does_not_double_prefix() {
        let n = Notice::blocked("abc".into(), "invalid: missing required tag: e");
        match n {
            Notice::EventResult(r) => {
                assert_eq!(r.msg, "invalid: missing required tag: e");
                assert!(matches!(r.status, EventResultStatus::Invalid));
            }
            _ => panic!("expected EventResult"),
        }
    }
}
