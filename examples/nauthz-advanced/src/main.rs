//! Advanced gRPC authorization service example
//! 
//! This example demonstrates:
//! 1. Restricting certain kinds to specific pubkeys
//! 2. Requiring certain tags for specific kinds
//! 
//! To use this, configure in config.toml:
//! [grpc]
//! event_admission_server = "http://[::1]:50051"

use std::collections::HashMap;
use std::collections::HashSet;
use tonic::{transport::Server, Request, Response, Status};

use nauthz_grpc::authorization_server::{Authorization, AuthorizationServer};
use nauthz_grpc::{Decision, EventReply, EventRequest};

pub mod nauthz_grpc {
    tonic::include_proto!("nauthz");
}

/// Authorization service with configurable rules
pub struct EventAuthz {
    /// Map of (pubkey, kind) -> allowed
    /// Key format: "pubkey_hex:kind"
    allowed_pubkey_kinds: HashSet<String>,
    
    /// Map of kind -> required tags
    /// Value is a map of tag_name -> required_values (empty vec means any value)
    required_tags: HashMap<u64, HashMap<String, Vec<String>>>,
}

impl EventAuthz {
    fn new() -> Self {
        let mut allowed_pubkey_kinds = HashSet::new();
        
        // Example: Only allow specific pubkeys to write kind 30000
        // Format: "pubkey_hex:kind"
        allowed_pubkey_kinds.insert("35d26e4690cbe1a898af61cc3515661eb5fa763b57bd0b42e45099c8b32fd50f:30000".to_string());
        allowed_pubkey_kinds.insert("887645fef0ce0c3c1218d2f5d8e6132a19304cdc57cd20281d082f38cfea0072:30000".to_string());
        
        // Example: Only allow specific pubkeys to write kind 30001
        allowed_pubkey_kinds.insert("35d26e4690cbe1a898af61cc3515661eb5fa763b57bd0b42e45099c8b32fd50f:30001".to_string());
        
        let mut required_tags = HashMap::new();
        
        // Example: Kind 30023 (long-form articles) requires "d" tag
        let mut kind_30023_tags = HashMap::new();
        kind_30023_tags.insert("d".to_string(), vec![]); // Empty vec = any value allowed
        required_tags.insert(30023, kind_30023_tags);
        
        // Example: Kind 30000 requires "p" tag with specific values
        let mut kind_30000_tags = HashMap::new();
        kind_30000_tags.insert("p".to_string(), vec!["recipient1".to_string(), "recipient2".to_string()]);
        required_tags.insert(30000, kind_30000_tags);
        
        // Example: Kind 4 (DMs) requires "p" tag (any value)
        let mut kind_4_tags = HashMap::new();
        kind_4_tags.insert("p".to_string(), vec![]);
        required_tags.insert(4, kind_4_tags);
        
        EventAuthz {
            allowed_pubkey_kinds,
            required_tags,
        }
    }
    
    /// Check if a pubkey is allowed to write a specific kind
    fn is_pubkey_allowed_for_kind(&self, pubkey_hex: &str, kind: u64) -> bool {
        let key = format!("{}:{}", pubkey_hex, kind);
        self.allowed_pubkey_kinds.contains(&key)
    }
    
    /// Check if event has all required tags for its kind
    fn has_required_tags(&self, event: &nauthz_grpc::Event) -> (bool, Option<String>) {
        if let Some(required) = self.required_tags.get(&event.kind) {
            for (tag_name, required_values) in required {
                // Find tags with this name
                let found_tag = event.tags.iter()
                    .find(|tag| tag.values.len() > 0 && tag.values[0] == *tag_name);
                
                match found_tag {
                    Some(tag) => {
                        if required_values.is_empty() {
                            // Any value is acceptable, tag just needs to exist
                            continue;
                        } else {
                            // Check if any of the required values are present
                            let has_required_value = required_values.iter()
                                .any(|req_val| tag.values.iter().skip(1).any(|v| v == req_val));
                            
                            if !has_required_value {
                                return (false, Some(format!(
                                    "Kind {} requires tag '{}' with one of these values: {:?}",
                                    event.kind, tag_name, required_values
                                )));
                            }
                        }
                    }
                    None => {
                        return (false, Some(format!(
                            "Kind {} requires tag '{}'",
                            event.kind, tag_name
                        )));
                    }
                }
            }
        }
        (true, None)
    }
}

#[tonic::async_trait]
impl Authorization for EventAuthz {
    async fn event_admit(
        &self,
        request: Request<EventRequest>,
    ) -> Result<Response<EventReply>, Status> {
        let req = request.into_inner();
        let event = match req.event {
            Some(e) => e,
            None => {
                return Ok(Response::new(EventReply {
                    decision: Decision::Deny as i32,
                    message: Some("Event data missing".to_string()),
                }));
            }
        };
        
        // Convert pubkey bytes to hex string
        let pubkey_hex = hex::encode(&event.pubkey);
        
        // CASE 1: Check if pubkey is allowed to write this kind
        if !self.is_pubkey_allowed_for_kind(&pubkey_hex, event.kind) {
            // Check if this kind has restrictions
            let has_restriction = self.allowed_pubkey_kinds.iter()
                .any(|key| key.ends_with(&format!(":{}", event.kind)));
            
            if has_restriction {
                return Ok(Response::new(EventReply {
                    decision: Decision::Deny as i32,
                    message: Some(format!(
                        "Pubkey {} is not authorized to write kind {}",
                        pubkey_hex.chars().take(16).collect::<String>(),
                        event.kind
                    )),
                }));
            }
            // If no restriction exists for this kind, allow it (default permit)
        }
        
        // CASE 2: Check if event has required tags for its kind
        let (has_tags, tag_error) = self.has_required_tags(&event);
        if !has_tags {
            return Ok(Response::new(EventReply {
                decision: Decision::Deny as i32,
                message: tag_error,
            }));
        }
        
        // All checks passed
        Ok(Response::new(EventReply {
            decision: Decision::Permit as i32,
            message: None,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();
    
    let checker = EventAuthz::new();
    println!("Advanced EventAuthz Server listening on {}", addr);
    println!("Rules configured:");
    println!("  - Pubkey+Kind restrictions: {} rules", checker.allowed_pubkey_kinds.len());
    println!("  - Required tag rules: {} kinds", checker.required_tags.len());
    
    Server::builder()
        .add_service(AuthorizationServer::new(checker))
        .serve(addr)
        .await?;
    
    Ok(())
}

