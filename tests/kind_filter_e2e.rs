// End-to-end tests for the kind-filter write path (kind whitelist,
// require_auth, required tags, max_size, max_expiration, tag limits).
use anyhow::Result;
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;
use futures::{SinkExt, StreamExt};
use nostr_rs_relay::config::{KindFilters, Settings};
use nostr_rs_relay::event::Event;
use nostr_rs_relay::utils::unix_time;
use secp256k1::rand;
use secp256k1::{KeyPair, Secp256k1, XOnlyPublicKey};
use std::io::Write;
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::WebSocketStream;
mod common;

// A temporary config file the relay will load at startup.
fn write_kind_config() -> Result<std::path::PathBuf> {
    let mut path = std::env::temp_dir();
    path.push("nostr_e2e_kinds.json");
    let json = r#"{
      "kinds": { "whitelist": [4] },
      "4": {
        "require_auth": true,
        "read": { "allow": "*", "privileged": true },
        "max_size": "4KB",
        "max_expiration": "75h",
        "p_tag": "hex",
        "required_tags": ["expiration", "client"],
        "tag_limits": { "max_tags": 32, "max_tag_name_chars": 32, "max_tag_value_chars": 128 },
        "rate_limits": [
          { "limit": 100, "window": "1h", "scope": "npub" },
          { "limit": 100, "window": "1h", "scope": "ip" }
        ]
      }
    }"#;
    let mut f = std::fs::File::create(&path)?;
    f.write_all(json.as_bytes())?;
    Ok(path)
}

fn settings_with_kind_filters() -> Result<Settings> {
    let mut settings = Settings::default();
    let path = write_kind_config()?;
    settings.kind_filters =
        KindFilters::load_from_file(&path.to_string_lossy()).map_err(anyhow::Error::msg)?;
    Ok(settings)
}

// Build a signed kind-4 DM event with the given tags.
fn dm_event(keys: &(KeyPair, XOnlyPublicKey), tags: Vec<Vec<String>>, content: &str) -> Event {
    let (key_pair, public_key) = keys;
    let secp = Secp256k1::new();
    let mut event = Event {
        id: "0".to_owned(),
        pubkey: public_key.to_hex(),
        delegated_by: None,
        created_at: unix_time(),
        kind: 4,
        tags,
        content: content.to_owned(),
        sig: "0".to_owned(),
        tagidx: None,
    };
    let c = event.to_canonical().unwrap();
    let digest: sha256::Hash = sha256::Hash::hash(c.as_bytes());
    let msg = secp256k1::Message::from_slice(digest.as_ref()).unwrap();
    let sig = secp.sign_schnorr(&msg, key_pair);
    event.id = format!("{digest:x}");
    event.sig = sig.to_hex();
    event
}

fn gen_keys() -> (KeyPair, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let key_pair = KeyPair::new(&secp, &mut rand::thread_rng());
    let public_key = XOnlyPublicKey::from_keypair(&key_pair);
    (key_pair, public_key)
}

// Publish a raw EVENT frame and return the parsed ["OK", id, accepted, msg].
async fn publish<S>(ws: &mut WebSocketStream<S>, event: &Event) -> Result<(String, bool, String)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let msg = format!("[\"EVENT\", {}]", serde_json::to_string(event)?);
    ws.send(msg.into()).await?;
    let frame = ws.next().await.expect("expected a reply").unwrap();
    let text = frame.into_text().unwrap().to_string();
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let id = v[1].as_str().unwrap_or("").to_string();
    let accepted = v[2].as_bool().unwrap_or(false);
    let msg = v[3].as_str().unwrap_or("").to_string();
    Ok((id, accepted, msg))
}

async fn shutdown(relay: &common::Relay) {
    loop {
        if relay.shutdown_tx.send(()).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[tokio::test]
async fn kind_filter_write_enforcement() -> Result<()> {
    let relay = common::start_relay_with_settings(settings_with_kind_filters()?)?;
    common::wait_for_healthy_relay(&relay).await?;
    let (mut ws, _res) = connect_async(format!("ws://localhost:{}", relay.port)).await?;
    let keys = gen_keys();
    let recipient = {
        let secp = Secp256k1::new();
        let kp = KeyPair::new(&secp, &mut rand::thread_rng());
        XOnlyPublicKey::from_keypair(&kp).to_hex()
    };
    let now = unix_time();

    // Drain the NIP-42 AUTH challenge sent on connect so publish() sees OK.
    {
        let frame = ws.next().await.expect("expected AUTH challenge").unwrap();
        let text = frame.into_text().unwrap().to_string();
        let v: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(v[0], "AUTH", "expected AUTH challenge on connect, got: {text}");
    }

    // 1. Kind 1 is not on the whitelist -> rejected.
    let mut ok1 = dm_event(&keys, vec![], "hello");
    ok1.kind = 1;
    // Re-sign after changing kind so we hit the whitelist check, not ID validation.
    {
        let secp = Secp256k1::new();
        let c = ok1.to_canonical().unwrap();
        let digest: sha256::Hash = sha256::Hash::hash(c.as_bytes());
        let msg = secp256k1::Message::from_slice(digest.as_ref()).unwrap();
        let sig = secp.sign_schnorr(&msg, &keys.0);
        ok1.id = format!("{digest:x}");
        ok1.sig = sig.to_hex();
    }
    let (_, accepted, msg) = publish(&mut ws, &ok1).await?;
    assert!(!accepted, "kind 1 should be rejected by whitelist; msg={msg}");
    assert_eq!(
        msg, "blocked: kind 1 is not in the kind whitelist",
        "whitelist rejection message; got={msg}"
    );

    // 2. Kind 4, unauthenticated -> rejected (require_auth).
    let noauth = dm_event(
        &keys,
        vec![
            vec!["p".into(), recipient.clone()],
            vec!["expiration".into(), (now + 3600).to_string()],
            vec!["client".into(), "test".into()],
        ],
        "secret msg",
    );
    let (_, accepted, msg) = publish(&mut ws, &noauth).await?;
    assert!(!accepted, "unauthenticated kind 4 should be rejected; msg={msg}");
    assert_eq!(
        msg, "auth-required: authentication required to publish this kind",
        "require_auth rejection message; got={msg}"
    );
    ws.close(None).await?;

    // Reconnect and AUTH so later checks exercise tag/size/expiration, not require_auth.
    let (mut ws, _res) = connect_async(format!("ws://localhost:{}", relay.port)).await?;
    let authed = authenticate(&mut ws, &keys).await?;
    assert_eq!(authed, keys.1.to_hex());

    // 3. Missing required tag "client" -> rejected.
    let missing_client = dm_event(
        &keys,
        vec![
            vec!["p".into(), recipient.clone()],
            vec!["expiration".into(), (now + 3600).to_string()],
        ],
        "secret",
    );
    let (_, accepted, msg) = publish(&mut ws, &missing_client).await?;
    assert!(!accepted, "missing client tag should be rejected; msg={msg}");
    assert_eq!(
        msg, "invalid: missing required tag: client",
        "missing tag rejection message; got={msg}"
    );

    // 4. Expiration too far in the future (> 75h) -> rejected.
    let far_exp = dm_event(
        &keys,
        vec![
            vec!["p".into(), recipient.clone()],
            vec!["expiration".into(), (now + 100 * 3600).to_string()],
            vec!["client".into(), "test".into()],
        ],
        "secret",
    );
    let (_, accepted, msg) = publish(&mut ws, &far_exp).await?;
    assert!(!accepted, "far-future expiration should be rejected; msg={msg}");
    assert_eq!(
        msg, "blocked: expiration exceeds max_expiry_duration",
        "max_expiration rejection message; got={msg}"
    );

    // 5. Oversized content (> 4KB) -> rejected.
    let big = dm_event(
        &keys,
        vec![
            vec!["p".into(), recipient.clone()],
            vec!["expiration".into(), (now + 3600).to_string()],
            vec!["client".into(), "test".into()],
        ],
        &"x".repeat(5000),
    );
    let (_, accepted, msg) = publish(&mut ws, &big).await?;
    assert!(!accepted, "oversized kind 4 should be rejected; msg={msg}");
    assert!(
        msg.starts_with("blocked: event exceeds size limit ("),
        "max_size rejection message; got={msg}"
    );
    assert!(
        msg.contains(" > 4096)"),
        "max_size should report limit 4096; got={msg}"
    );
    ws.close(None).await?;
    shutdown(&relay).await;
    Ok(())
}

const RELAY_URL: &str = "wss://nostr.example.com/";

// Perform NIP-42 AUTH on the connection, returning the authenticating pubkey.
async fn authenticate<S>(ws: &mut WebSocketStream<S>, keys: &(KeyPair, XOnlyPublicKey)) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Server sends AUTH challenge first.
    let frame = ws.next().await.expect("expected AUTH challenge").unwrap();
    let text = frame.into_text().unwrap().to_string();
    let v: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(v[0], "AUTH", "expected AUTH challenge, got: {text}");
    let challenge = v[1].as_str().unwrap().to_string();

    let (key_pair, public_key) = keys;
    let secp = Secp256k1::new();
    let mut event = Event {
        id: "0".to_owned(),
        pubkey: public_key.to_hex(),
        delegated_by: None,
        created_at: unix_time(),
        kind: 22242,
        tags: vec![
            vec!["challenge".into(), challenge],
            vec!["relay".into(), RELAY_URL.into()],
        ],
        content: String::new(),
        sig: "0".to_owned(),
        tagidx: None,
    };
    let c = event.to_canonical().unwrap();
    let digest: sha256::Hash = sha256::Hash::hash(c.as_bytes());
    let msg = secp256k1::Message::from_slice(digest.as_ref()).unwrap();
    let sig = secp.sign_schnorr(&msg, key_pair);
    event.id = format!("{digest:x}");
    event.sig = sig.to_hex();

    let auth_msg = format!("[\"AUTH\", {}]", serde_json::to_string(&event)?);
    ws.send(auth_msg.into()).await?;
    // Confirm OK
    let frame = ws.next().await.expect("expected AUTH confirmation").unwrap();
    let text = frame.into_text().unwrap().to_string();
    let v: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(v[0], "OK", "expected OK for AUTH, got: {text}");
    assert!(v[2].as_bool().unwrap_or(false), "AUTH failed: {text}");
    Ok(public_key.to_hex())
}

// REQ by event id, returning the number of EVENT frames received before EOSE.
async fn count_events_for_id<S>(ws: &mut WebSocketStream<S>, event_id: &str) -> Result<usize>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let req = serde_json::json!(["REQ", "sub1", { "ids": [event_id] }]).to_string();
    ws.send(req.into()).await?;
    let mut count = 0usize;
    for _ in 0..10 {
        let frame = ws.next().await.expect("expected response").unwrap();
        let text = frame.into_text().unwrap().to_string();
        let v: serde_json::Value = serde_json::from_str(&text)?;
        match v[0].as_str() {
            Some("EVENT") => count += 1,
            Some("EOSE") => break,
            _ => {}
        }
    }
    Ok(count)
}

#[tokio::test]
async fn authenticated_dm_publish_and_privileged_read() -> Result<()> {
    let relay = common::start_relay_with_settings(settings_with_kind_filters()?)?;
    common::wait_for_healthy_relay(&relay).await?;

    // --- Author authenticates and publishes a valid DM ---
    let author_keys = gen_keys();
    let author_pk = author_keys.1.to_hex();
    let recipient_keys = gen_keys();
    let recipient_pk = recipient_keys.1.to_hex();
    let stranger_keys = gen_keys();
    let now = unix_time();

    let dm = dm_event(
        &author_keys,
        vec![
            vec!["p".into(), recipient_pk.clone()],
            vec!["expiration".into(), (now + 3600).to_string()],
            vec!["client".into(), "e2e-test".into()],
        ],
        "hello recipient",
    );
    let dm_id = dm.id.clone();

    let (mut author_ws, _res) = connect_async(format!("ws://localhost:{}", relay.port)).await?;
    let authed = authenticate(&mut author_ws, &author_keys).await?;
    assert_eq!(authed, author_pk);
    let (id, accepted, msg) = publish(&mut author_ws, &dm).await?;
    assert_eq!(id, dm_id, "saved event id mismatch: {msg}");
    assert!(accepted, "valid authenticated DM should be saved; msg={msg}");
    author_ws.close(None).await?;

    // --- Recipient (authenticated) can read it ---
    let (mut recv_ws, _res) = connect_async(format!("ws://localhost:{}", relay.port)).await?;
    let authed = authenticate(&mut recv_ws, &recipient_keys).await?;
    assert_eq!(authed, recipient_pk);
    let n = count_events_for_id(&mut recv_ws, &dm_id).await?;
    assert_eq!(n, 1, "recipient should receive the DM");
    recv_ws.close(None).await?;

    // --- Author (authenticated) can read it ---
    let (mut author_ws2, _res) = connect_async(format!("ws://localhost:{}", relay.port)).await?;
    let authed = authenticate(&mut author_ws2, &author_keys).await?;
    assert_eq!(authed, author_pk);
    let n = count_events_for_id(&mut author_ws2, &dm_id).await?;
    assert_eq!(n, 1, "author should receive the DM");
    author_ws2.close(None).await?;

    // --- Stranger (authenticated) must NOT see it ---
    let (mut stranger_ws, _res) = connect_async(format!("ws://localhost:{}", relay.port)).await?;
    let authed = authenticate(&mut stranger_ws, &stranger_keys).await?;
    assert_eq!(authed, stranger_keys.1.to_hex());
    let n = count_events_for_id(&mut stranger_ws, &dm_id).await?;
    assert_eq!(n, 0, "stranger must not receive the DM");
    stranger_ws.close(None).await?;

    // --- Unauthenticated client must NOT see it ---
    let (mut anon_ws, _res) = connect_async(format!("ws://localhost:{}", relay.port)).await?;
    let n = count_events_for_id(&mut anon_ws, &dm_id).await?;
    assert_eq!(n, 0, "unauthenticated client must not receive the DM");
    anon_ws.close(None).await?;

    shutdown(&relay).await;
    Ok(())
}