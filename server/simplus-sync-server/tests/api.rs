//! End-to-end API tests against an in-process server on 127.0.0.1.

use serde::Serialize;
use serde_json::{Value, json};
use simplus_sync_server::{AppState, Config, admin};
use simplus_vault_proto::{
    ChangesResponse, DevicesResponse, KdfInfo, KeyBundle, KeysResponse, PreloginResponse, PushResponse,
    PushStatus, Registration, SessionResponse,
};
use uuid::Uuid;

struct TestServer {
    url: String,
    state: AppState,
    _runtime: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn spawn(configure: impl FnOnce(&mut Config)) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config { database: dir.path().join("sync.db"), ..Config::default() };
    configure(&mut config);
    let state = AppState::open(config).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    runtime.spawn(simplus_sync_server::serve(state.clone(), listener, std::future::pending()));
    TestServer { url, state, _runtime: runtime, _dir: dir }
}

fn server() -> TestServer {
    spawn(|_| {})
}

struct Reply {
    status: u16,
    body: Value,
}

impl Reply {
    fn ok<T: serde::de::DeserializeOwned>(self) -> T {
        assert!((200..300).contains(&self.status), "expected success, got {} {}", self.status, self.body);
        serde_json::from_value(self.body).unwrap()
    }

    fn error(&self) -> (u16, &str) {
        (self.status, self.body["code"].as_str().unwrap_or(""))
    }
}

impl TestServer {
    fn request(&self, method: &str, path: &str, token: Option<&str>, body: Option<&impl Serialize>) -> Reply {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut builder = ureq::http::Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.url))
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let payload = body.map(|b| serde_json::to_string(b).unwrap()).unwrap_or_default();
        let mut response = agent.run(builder.body(payload).unwrap()).unwrap();
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().unwrap_or_default();
        Reply { status, body: serde_json::from_str(&text).unwrap_or(Value::Null) }
    }

    fn get(&self, path: &str, token: Option<&str>) -> Reply {
        self.request("GET", path, token, None::<&()>)
    }

    fn post(&self, path: &str, token: Option<&str>, body: &impl Serialize) -> Reply {
        self.request("POST", path, token, Some(body))
    }
}

fn b64(bytes: &[u8]) -> String {
    data_encoding::BASE64.encode(bytes)
}

/// Client-side material for one test account.
struct Client {
    email: String,
    auth_key: [u8; 32],
    key_proof: [u8; 32],
    kdf: KdfInfo,
    keys: KeyBundle,
}

impl Client {
    fn new(email: &str) -> Self {
        Self {
            email: email.into(),
            auth_key: rand32(),
            key_proof: rand32(),
            kdf: KdfInfo { m_cost_kib: 65_536, t_cost: 3, p_cost: 4, salt: vec![7; 16] },
            keys: KeyBundle {
                vault_id: Uuid::now_v7(),
                master_slot: vec![1; 90],
                notes_slot: vec![2; 90],
                recovery_vault_slot: vec![3; 60],
                recovery_notes_slot: vec![4; 60],
            },
        }
    }

    fn register_body(&self, device: &str, invite: Option<&str>) -> Value {
        json!({
            "email": self.email,
            "auth_key": b64(&self.auth_key),
            "key_proof": b64(&self.key_proof),
            "kdf": self.kdf,
            "keys": self.keys,
            "device": { "id": Uuid::now_v7(), "name": device },
            "invite_code": invite,
        })
    }

    fn login_body(&self, device_id: Uuid) -> Value {
        json!({ "email": self.email, "auth_key": b64(&self.auth_key), "device": { "id": device_id, "name": "Laptop" } })
    }
}

fn rand32() -> [u8; 32] {
    simplus_crypto::random_bytes().unwrap()
}

fn register(server: &TestServer, client: &Client) -> String {
    let session: SessionResponse =
        server.post("/v1/accounts", None, &client.register_body("Desktop", None)).ok();
    assert_eq!(session.keys_version, 1);
    session.token
}

fn item(id: Uuid, base_seq: i64, blob: Option<&[u8]>) -> Value {
    json!({
        "id": id, "kind": "record", "parent_id": null, "base_seq": base_seq,
        "deleted": blob.is_none(), "updated_at": 1, "blob": blob.map(b64),
    })
}

#[test]
fn health_and_info() {
    let s = server();
    assert_eq!(s.get("/health", None).status, 200);
    let info = s.get("/v1/info", None).body;
    assert_eq!(info["registration"], "open");
    assert_eq!(info["api_version"], 1);
}

#[test]
fn register_login_and_lockout() {
    let s = spawn(|c| c.lockout_threshold = 3);
    let client = Client::new("Alice@Example.com");
    register(&s, &client);

    // Emails are case-insensitive.
    let again = s.post("/v1/accounts", None, &Client::new("alice@example.com").register_body("Other", None));
    assert_eq!(again.error(), (409, "email_taken"));

    let session: SessionResponse = s.post("/v1/sessions", None, &client.login_body(Uuid::now_v7())).ok();
    assert_eq!(session.keys, client.keys);
    assert_eq!(session.kdf, client.kdf);

    let mut wrong = client.login_body(Uuid::now_v7());
    wrong["auth_key"] = json!(b64(&rand32()));
    for _ in 0..3 {
        assert_eq!(s.post("/v1/sessions", None, &wrong).error(), (401, "invalid_credentials"));
    }
    // Locked now, even with the right key.
    assert_eq!(s.post("/v1/sessions", None, &client.login_body(Uuid::now_v7())).error(), (429, "locked"));

    let mut unknown = client.login_body(Uuid::now_v7());
    unknown["email"] = json!("nobody@example.com");
    assert_eq!(s.post("/v1/sessions", None, &unknown).error(), (401, "invalid_credentials"));
}

#[test]
fn prelogin_does_not_reveal_accounts() {
    let s = server();
    let client = Client::new("bob@example.com");
    register(&s, &client);

    let known: PreloginResponse = s.post("/v1/prelogin", None, &json!({"email": "BOB@example.com"})).ok();
    assert_eq!(known.kdf, client.kdf);

    let fake1: PreloginResponse = s.post("/v1/prelogin", None, &json!({"email": "ghost@example.com"})).ok();
    let fake2: PreloginResponse = s.post("/v1/prelogin", None, &json!({"email": "ghost@example.com"})).ok();
    let other: PreloginResponse = s.post("/v1/prelogin", None, &json!({"email": "spook@example.com"})).ok();
    assert_eq!(fake1, fake2, "stable answers");
    assert_ne!(fake1.kdf.salt, other.kdf.salt);
    assert_eq!(fake1.kdf.salt.len(), 16);
}

#[test]
fn item_feed_push_pull_and_conflicts() {
    let s = server();
    let token = register(&s, &Client::new("carol@example.com"));
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());

    let pushed: PushResponse = s
        .post(
            "/v1/items",
            Some(&token),
            &json!({"items": [item(a, 0, Some(b"one")), item(b, 0, Some(b"two"))]}),
        )
        .ok();
    assert!(pushed.results.iter().all(|r| r.status == PushStatus::Accepted));
    assert_eq!(pushed.latest_seq, 2);

    // Stale base -> conflict, carrying the current seq; correct base -> accepted.
    let stale: PushResponse =
        s.post("/v1/items", Some(&token), &json!({"items": [item(a, 0, Some(b"x"))]})).ok();
    assert_eq!((stale.results[0].status, stale.results[0].seq), (PushStatus::Conflict, 1));
    let tomb: PushResponse = s.post("/v1/items", Some(&token), &json!({"items": [item(a, 1, None)]})).ok();
    assert_eq!(tomb.results[0].seq, 3);

    let all: ChangesResponse = s.get("/v1/items?since=0", Some(&token)).ok();
    assert_eq!(all.latest_seq, 3);
    assert_eq!(all.items.len(), 2);
    assert!(all.items.iter().any(|i| i.id == a && i.deleted && i.blob.is_none()));

    let page: ChangesResponse = s.get("/v1/items?since=0&limit=1", Some(&token)).ok();
    assert!(page.has_more);
    assert_eq!(page.items.len(), 1);
    let rest: ChangesResponse = s.get(&format!("/v1/items?since={}", page.items[0].seq), Some(&token)).ok();
    assert!(!rest.has_more);

    // Malformed requests.
    let note_without_parent = json!({"items": [{"id": Uuid::now_v7(), "kind": "note", "parent_id": null,
        "base_seq": 0, "deleted": false, "updated_at": 0, "blob": b64(b"x")}]});
    assert_eq!(s.post("/v1/items", Some(&token), &note_without_parent).error().1, "bad_request");
    let dup = json!({"items": [item(b, 2, Some(b"y")), item(b, 2, Some(b"z"))]});
    assert_eq!(s.post("/v1/items", Some(&token), &dup).error().1, "bad_request");

    assert_eq!(s.get("/v1/items", None).error(), (401, "unauthorized"));
    assert_eq!(s.get("/v1/items", Some("bogus-token")).error(), (401, "unauthorized"));
}

#[test]
fn accounts_are_isolated() {
    let s = server();
    let t1 = register(&s, &Client::new("one@example.com"));
    let t2 = register(&s, &Client::new("two@example.com"));
    let id = Uuid::now_v7();
    s.post("/v1/items", Some(&t1), &json!({"items": [item(id, 0, Some(b"secret"))]})).ok::<PushResponse>();
    let other: ChangesResponse = s.get("/v1/items", Some(&t2)).ok();
    assert!(other.items.is_empty());
    // The same id in another account is a different item.
    let pushed: PushResponse =
        s.post("/v1/items", Some(&t2), &json!({"items": [item(id, 0, Some(b"mine"))]})).ok();
    assert_eq!(pushed.results[0].status, PushStatus::Accepted);
}

#[test]
fn key_updates_and_password_change() {
    let s = server();
    let client = Client::new("dave@example.com");
    let t1 = register(&s, &client);
    let laptop = Uuid::now_v7();
    let t2 = s.post("/v1/sessions", None, &client.login_body(laptop)).ok::<SessionResponse>().token;

    // Notes password change: bundle only, version check enforced.
    let mut keys = client.keys.clone();
    keys.notes_slot = vec![9; 90];
    let stale = json!({"expected_version": 5, "keys": keys});
    assert_eq!(s.request("PUT", "/v1/keys", Some(&t1), Some(&stale)).error(), (409, "version_conflict"));
    let ok = json!({"expected_version": 1, "keys": keys});
    assert_eq!(s.request("PUT", "/v1/keys", Some(&t1), Some(&ok)).ok::<Value>()["keys_version"], 2);
    let fetched: KeysResponse = s.get("/v1/keys", Some(&t2)).ok();
    assert_eq!((fetched.keys_version, fetched.keys.notes_slot.clone()), (2, vec![9; 90]));

    // A bundle for another vault is refused.
    let mut foreign = keys.clone();
    foreign.vault_id = Uuid::now_v7();
    let bad = json!({"expected_version": 2, "keys": foreign});
    assert_eq!(s.request("PUT", "/v1/keys", Some(&t1), Some(&bad)).error().1, "bad_request");

    // Master password change needs the current key, and signs out other devices.
    let new_auth = rand32();
    let new_kdf = KdfInfo { salt: vec![8; 16], ..client.kdf.clone() };
    let wrong = json!({"expected_version": 2, "keys": keys, "current_auth_key": b64(&rand32()),
        "new_auth_key": b64(&new_auth), "new_kdf": new_kdf, "revoke_other_sessions": true});
    assert_eq!(s.request("PUT", "/v1/keys", Some(&t1), Some(&wrong)).error(), (401, "invalid_credentials"));
    let change = json!({"expected_version": 2, "keys": keys, "current_auth_key": b64(&client.auth_key),
        "new_auth_key": b64(&new_auth), "new_kdf": new_kdf, "revoke_other_sessions": true});
    assert_eq!(s.request("PUT", "/v1/keys", Some(&t1), Some(&change)).ok::<Value>()["keys_version"], 3);

    assert_eq!(s.get("/v1/keys", Some(&t2)).error(), (401, "unauthorized"), "other device signed out");
    assert_eq!(s.get("/v1/keys", Some(&t1)).status, 200, "this device stays signed in");
    assert_eq!(s.post("/v1/sessions", None, &client.login_body(laptop)).error().0, 401);
    let mut login = client.login_body(laptop);
    login["auth_key"] = json!(b64(&new_auth));
    let session: SessionResponse = s.post("/v1/sessions", None, &login).ok();
    assert_eq!(session.kdf, new_kdf);
}

#[test]
fn devices_and_logout() {
    let s = server();
    let client = Client::new("erin@example.com");
    let t1 = register(&s, &client);
    let phone = Uuid::now_v7();
    let t2 = s.post("/v1/sessions", None, &client.login_body(phone)).ok::<SessionResponse>().token;
    // Logging in again from the same device replaces its session.
    let t2b = s.post("/v1/sessions", None, &client.login_body(phone)).ok::<SessionResponse>().token;
    assert_eq!(s.get("/v1/devices", Some(&t2)).status, 401);

    let devices: DevicesResponse = s.get("/v1/devices", Some(&t1)).ok();
    assert_eq!(devices.devices.len(), 2);
    assert_eq!(devices.devices.iter().filter(|d| d.current).count(), 1);

    assert_eq!(s.request("DELETE", &format!("/v1/devices/{phone}"), Some(&t1), None::<&()>).status, 204);
    assert_eq!(s.get("/v1/devices", Some(&t2b)).status, 401);
    assert_eq!(
        s.request("DELETE", &format!("/v1/devices/{phone}"), Some(&t1), None::<&()>).error().1,
        "not_found"
    );

    assert_eq!(s.request("DELETE", "/v1/sessions/current", Some(&t1), None::<&()>).status, 204);
    assert_eq!(s.get("/v1/devices", Some(&t1)).status, 401);
}

#[test]
fn recovery_resets_login_and_sessions() {
    let s = server();
    let client = Client::new("frank@example.com");
    let old_token = register(&s, &client);
    let new_auth = rand32();
    let body = |proof: &[u8], vault_id: Uuid| {
        let keys = KeyBundle { vault_id, ..client.keys.clone() };
        json!({"email": client.email, "key_proof": b64(proof), "new_auth_key": b64(&new_auth),
               "kdf": client.kdf, "keys": keys, "device": {"id": Uuid::now_v7(), "name": "New PC"}})
    };
    assert_eq!(
        s.post("/v1/recover", None, &body(&rand32(), client.keys.vault_id)).error(),
        (401, "invalid_credentials")
    );
    assert_eq!(
        s.post("/v1/recover", None, &body(&client.key_proof, Uuid::now_v7())).error().1,
        "bad_request"
    );

    let session: SessionResponse =
        s.post("/v1/recover", None, &body(&client.key_proof, client.keys.vault_id)).ok();
    assert_eq!(session.keys_version, 2);
    assert_eq!(s.get("/v1/keys", Some(&old_token)).status, 401);
    assert_eq!(s.get("/v1/keys", Some(&session.token)).status, 200);
    let mut login = client.login_body(Uuid::now_v7());
    login["auth_key"] = json!(b64(&new_auth));
    assert_eq!(s.post("/v1/sessions", None, &login).status, 200);
}

#[test]
fn invite_only_and_closed_registration() {
    let s = spawn(|c| c.registration = Registration::Invite);
    let a = Client::new("g1@example.com");
    assert_eq!(s.post("/v1/accounts", None, &a.register_body("PC", None)).error(), (403, "invite_required"));
    assert_eq!(
        s.post("/v1/accounts", None, &a.register_body("PC", Some("NOPE"))).error(),
        (403, "invalid_invite")
    );
    let code = admin::create_invite(&s.state.db, 1, 7).unwrap();
    assert_eq!(s.post("/v1/accounts", None, &a.register_body("PC", Some(&code))).status, 200);
    let b = Client::new("g2@example.com");
    assert_eq!(
        s.post("/v1/accounts", None, &b.register_body("PC", Some(&code))).error().1,
        "invalid_invite",
        "single use"
    );

    let closed = spawn(|c| c.registration = Registration::Closed);
    assert_eq!(
        closed.post("/v1/accounts", None, &a.register_body("PC", None)).error(),
        (403, "registration_closed")
    );
}

#[test]
fn auth_endpoints_are_rate_limited() {
    let s = spawn(|c| c.auth_requests_per_minute = 3);
    // The limiter uses fixed one-minute windows; don't let the requests straddle a boundary.
    let into_minute = simplus_sync_server::db::now() % 60;
    if into_minute > 50 {
        std::thread::sleep(std::time::Duration::from_secs((61 - into_minute) as u64));
    }
    for _ in 0..3 {
        assert_eq!(s.post("/v1/prelogin", None, &json!({"email": "x@example.com"})).status, 200);
    }
    assert_eq!(
        s.post("/v1/prelogin", None, &json!({"email": "x@example.com"})).error(),
        (429, "rate_limited")
    );
}

#[test]
fn size_and_quota_limits() {
    let s = spawn(|c| {
        c.max_blob_bytes = 8;
        c.max_items_per_account = 1;
    });
    let token = register(&s, &Client::new("h@example.com"));
    let big = json!({"items": [item(Uuid::now_v7(), 0, Some(&[0; 9]))]});
    assert_eq!(s.post("/v1/items", Some(&token), &big).error(), (413, "too_large"));
    let first = Uuid::now_v7();
    s.post("/v1/items", Some(&token), &json!({"items": [item(first, 0, Some(b"ok"))]})).ok::<PushResponse>();
    let second = json!({"items": [item(Uuid::now_v7(), 0, Some(b"no"))]});
    assert_eq!(s.post("/v1/items", Some(&token), &second).error(), (413, "quota_exceeded"));
    // Deleting frees the slot again.
    s.post("/v1/items", Some(&token), &json!({"items": [item(first, 1, None)]})).ok::<PushResponse>();
    assert_eq!(s.post("/v1/items", Some(&token), &second).status, 200);
}

#[test]
fn admin_disable_delete_and_backup() {
    let s = server();
    let client = Client::new("ivy@example.com");
    let token = register(&s, &client);
    assert_eq!(admin::list_users(&s.state.db).unwrap()[0].email, "ivy@example.com");

    assert!(admin::set_disabled(&s.state.db, "IVY@example.com", true).unwrap());
    assert_eq!(s.get("/v1/keys", Some(&token)).status, 401, "sessions were revoked");
    assert_eq!(
        s.post("/v1/sessions", None, &client.login_body(Uuid::now_v7())).error(),
        (403, "account_disabled")
    );
    admin::set_disabled(&s.state.db, "ivy@example.com", false).unwrap();
    let token =
        s.post("/v1/sessions", None, &client.login_body(Uuid::now_v7())).ok::<SessionResponse>().token;

    let backup = s._dir.path().join("backup.db");
    admin::backup(&s.state.db, &backup).unwrap();
    assert!(backup.metadata().unwrap().len() > 0);
    assert!(admin::backup(&s.state.db, &backup).is_err(), "never overwrites");

    let delete = json!({"auth_key": b64(&client.auth_key)});
    assert_eq!(
        s.request("DELETE", "/v1/account", Some(&token), Some(&json!({"auth_key": b64(&rand32())})))
            .error()
            .1,
        "invalid_credentials"
    );
    assert_eq!(s.request("DELETE", "/v1/account", Some(&token), Some(&delete)).status, 204);
    assert_eq!(s.get("/v1/keys", Some(&token)).status, 401);
    assert_eq!(admin::stats(&s.state.db).unwrap().accounts, 0);
}
