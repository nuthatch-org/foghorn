//! Alert subscriptions (lodestar#256). Lodestar's indexer page creates and removes them; the probe
//! binary's `subscriptions` loop evaluates and delivers.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use foghorn_core::alerts::{self, AlertEvent};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::AppState;

/// Enough for an operator and a few colleagues, not enough to turn the box into a webhook cannon.
const MAX_PER_WEBHOOK: i64 = 10;
const MAX_PER_INDEXER: i64 = 100;

type Refusal = (StatusCode, Json<Value>);

fn refuse(status: StatusCode, message: &str) -> Refusal {
    (status, Json(json!({ "error": message })))
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[derive(Debug, Deserialize)]
pub struct CreateSubscription {
    pub indexer: String,
    pub webhook_url: String,
    #[serde(default)]
    pub kinds: Option<Vec<String>>,
    #[serde(default)]
    pub signal_move_pct: Option<f64>,
}

#[derive(Debug, PartialEq)]
pub struct Validated {
    pub indexer: String,
    pub webhook_url: String,
    pub kinds: Vec<String>,
    pub signal_move_pct: f64,
}

pub fn validate(req: CreateSubscription) -> Result<Validated, &'static str> {
    let indexer = req.indexer.trim().to_ascii_lowercase();
    let hex = indexer
        .strip_prefix("0x")
        .ok_or("indexer must be a 0x address")?;
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("indexer must be a 0x address");
    }
    let webhook_url = req.webhook_url.trim().to_string();
    alerts::check_webhook_url(&webhook_url)?;
    let mut kinds = req
        .kinds
        .unwrap_or_else(|| alerts::KINDS.iter().map(|k| k.to_string()).collect());
    kinds.sort();
    kinds.dedup();
    if kinds.is_empty() {
        return Err("choose at least one alert");
    }
    if kinds.iter().any(|k| !alerts::KINDS.contains(&k.as_str())) {
        return Err("unknown alert kind");
    }
    let signal_move_pct = req.signal_move_pct.unwrap_or(20.0);
    if !(1.0..=1000.0).contains(&signal_move_pct) {
        return Err("signal_move_pct must be between 1 and 1000");
    }
    Ok(Validated {
        indexer,
        webhook_url,
        kinds,
        signal_move_pct,
    })
}

/// `POST /v1/alerts/subscriptions`. Sends a test post first and saves nothing unless it lands.
pub async fn create(
    State(state): State<AppState>,
    Json(req): Json<CreateSubscription>,
) -> Result<(StatusCode, Json<Value>), Refusal> {
    let v = validate(req).map_err(|m| refuse(StatusCode::BAD_REQUEST, m))?;
    check_limits(&state.pool, &v).await?;

    let hello = AlertEvent {
        kind: "test",
        message: format!(
            "Subscribed to {} for {}. The first check records where things stand; alerts follow on changes.",
            v.indexer,
            v.kinds.join(", ")
        ),
    };
    alerts::deliver(
        &v.webhook_url,
        &alerts::payloads(&v.webhook_url, &v.indexer, &[hello]),
    )
    .await
    .map_err(|e| {
        refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("The test post failed: {e}."),
        )
    })?;

    let (id, token) = insert(&state.pool, &v).await.map_err(|_| {
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the subscription could not be saved",
        )
    })?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "manage_token": token,
            "indexer": v.indexer,
            "kinds": v.kinds,
            "signal_move_pct": v.signal_move_pct,
        })),
    ))
}

async fn check_limits(pool: &PgPool, v: &Validated) -> Result<(), Refusal> {
    let row = sqlx::query(
        "SELECT COUNT(*) FILTER (WHERE webhook_url = $1) AS by_hook, COUNT(*) FILTER (WHERE indexer_address = $2) AS by_indexer \
         FROM alert_subscription WHERE disabled_at IS NULL",
    )
    .bind(&v.webhook_url)
    .bind(&v.indexer)
    .fetch_one(pool)
    .await
    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "the subscription could not be saved"))?;
    if row.get::<i64, _>("by_hook") >= MAX_PER_WEBHOOK {
        return Err(refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "this webhook already has as many subscriptions as it may",
        ));
    }
    if row.get::<i64, _>("by_indexer") >= MAX_PER_INDEXER {
        return Err(refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "this indexer already has as many subscriptions as it may",
        ));
    }
    Ok(())
}

pub async fn insert(pool: &PgPool, v: &Validated) -> sqlx::Result<(Uuid, String)> {
    let id = Uuid::new_v4();
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO alert_subscription (id, indexer_address, webhook_url, kinds, signal_move_pct, manage_token_sha256) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(&v.indexer)
    .bind(&v.webhook_url)
    .bind(&v.kinds)
    .bind(v.signal_move_pct)
    .bind(token_hash(&token))
    .execute(pool)
    .await?;
    Ok((id, token))
}

#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    #[serde(default)]
    pub token: String,
}

/// `GET /v1/alerts/subscriptions/:id?token=`. A wrong token and a missing row both answer 404.
pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<TokenQuery>,
) -> Result<Json<Value>, Refusal> {
    describe(&state.pool, id, &q.token).await.map(Json)
}

/// `POST /v1/alerts/subscriptions/:id/read` with `{"token": "..."}`. The same answer as the GET,
/// with the token kept out of the URL. A body that is missing, malformed or has no token reads as
/// an empty token, which is what the GET does for a missing one.
pub async fn read(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<Value>, Refusal> {
    let token = serde_json::from_slice::<TokenBody>(&body)
        .map(|b| b.token)
        .unwrap_or_default();
    describe(&state.pool, id, &token).await.map(Json)
}

pub async fn describe(pool: &PgPool, id: Uuid, token: &str) -> Result<Value, Refusal> {
    let row = sqlx::query(
        "SELECT indexer_address, webhook_url, kinds, signal_move_pct, created_at, last_evaluated_at, last_delivered_at, \
                consecutive_failures, last_error, disabled_at \
         FROM alert_subscription WHERE id = $1 AND manage_token_sha256 = $2",
    )
    .bind(id)
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await
    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "the subscription could not be read"))?
    .ok_or_else(|| refuse(StatusCode::NOT_FOUND, "no such subscription"))?;
    let url: String = row.get("webhook_url");
    let host = alerts::check_webhook_url(&url)
        .map(|(h, _)| h)
        .unwrap_or_default();
    Ok(json!({
        "id": id,
        "indexer": row.get::<String, _>("indexer_address"),
        "webhook_host": host,
        "kinds": row.get::<Vec<String>, _>("kinds"),
        "signal_move_pct": row.get::<f64, _>("signal_move_pct"),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        "last_evaluated_at": row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_evaluated_at"),
        "last_delivered_at": row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_delivered_at"),
        "consecutive_failures": row.get::<i32, _>("consecutive_failures"),
        "last_error": row.get::<Option<String>, _>("last_error"),
        "disabled": row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("disabled_at").is_some(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct TokenBody {
    #[serde(default)]
    pub token: String,
}

/// `POST /v1/alerts/subscriptions/:id/delete`. POST because kittiwake's proxy forwards GET and POST.
pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<TokenBody>,
) -> Result<Json<Value>, Refusal> {
    remove(&state.pool, id, &body.token).await.map(Json)
}

pub async fn remove(pool: &PgPool, id: Uuid, token: &str) -> Result<Value, Refusal> {
    let done =
        sqlx::query("DELETE FROM alert_subscription WHERE id = $1 AND manage_token_sha256 = $2")
            .bind(id)
            .bind(token_hash(token))
            .execute(pool)
            .await
            .map_err(|_| {
                refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the subscription could not be removed",
                )
            })?;
    if done.rows_affected() == 0 {
        return Err(refuse(StatusCode::NOT_FOUND, "no such subscription"));
    }
    Ok(json!({ "deleted": true }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use foghorn_core::testdb::TestDb;

    fn req(indexer: &str, url: &str) -> CreateSubscription {
        CreateSubscription {
            indexer: indexer.into(),
            webhook_url: url.into(),
            kinds: None,
            signal_move_pct: None,
        }
    }

    const INDEXER: &str = "0x2B3C7D1EF5FDFC0557934019C531D3E70D6200AE";
    const HOOK: &str = "https://discord.com/api/webhooks/1/abc";

    #[test]
    fn validation_normalises_and_refuses() {
        let v = validate(req(INDEXER, HOOK)).unwrap();
        assert_eq!(v.indexer, INDEXER.to_ascii_lowercase());
        assert_eq!(v.kinds.len(), alerts::KINDS.len());
        assert_eq!(v.signal_move_pct, 20.0);
        assert!(validate(req("0x123", HOOK)).is_err());
        assert!(validate(req(INDEXER, "https://10.0.0.1/x")).is_err());
        let mut r = req(INDEXER, HOOK);
        r.kinds = Some(vec!["poi".into(), "weather".into()]);
        assert_eq!(validate(r), Err("unknown alert kind"));
        let mut r = req(INDEXER, HOOK);
        r.kinds = Some(vec![]);
        assert!(validate(r).is_err());
    }

    #[tokio::test]
    async fn the_token_reads_and_removes_and_nothing_else_does() {
        let Some(db) = TestDb::create().await else {
            return;
        };
        let v = validate(req(INDEXER, HOOK)).unwrap();
        let (id, token) = insert(&db.pool, &v).await.unwrap();

        let got = describe(&db.pool, id, &token).await.unwrap();
        assert_eq!(got["webhook_host"], "discord.com");
        assert!(got.get("webhook_url").is_none());
        assert_eq!(
            describe(&db.pool, id, "wrong").await.unwrap_err().0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            remove(&db.pool, id, "wrong").await.unwrap_err().0,
            StatusCode::NOT_FOUND
        );
        assert!(remove(&db.pool, id, &token).await.is_ok());
        assert_eq!(
            describe(&db.pool, id, &token).await.unwrap_err().0,
            StatusCode::NOT_FOUND
        );
        db.drop_database().await;
    }

    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Captured {
            self.clone()
        }
    }

    async fn call(
        app: &axum::Router,
        req: axum::http::Request<axum::body::Body>,
    ) -> (StatusCode, Vec<u8>) {
        use tower::ServiceExt;
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, body.to_vec())
    }

    fn get_req(id: &str, query: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::get(format!("/v1/alerts/subscriptions/{id}{query}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn post_req(id: &str, body: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::post(format!("/v1/alerts/subscriptions/{id}/read"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn the_post_read_answers_as_the_get_does_and_logs_no_token() {
        let Some(db) = TestDb::create().await else {
            return;
        };
        let logs = Captured::default();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(logs.clone())
                .finish(),
        );
        let app = crate::app(AppState {
            schema: crate::graphql::schema(db.pool.clone()),
            probe_interval_secs: 3600,
            pool: db.pool.clone(),
        });
        let v = validate(req(INDEXER, HOOK)).unwrap();
        let (id, token) = insert(&db.pool, &v).await.unwrap();
        let id = id.to_string();
        let unknown = Uuid::new_v4().to_string();
        let wrong = "a-wrong-token-that-must-not-be-logged";

        let (get_status, get_body) = call(&app, get_req(&id, &format!("?token={token}"))).await;
        assert_eq!(get_status, StatusCode::OK);
        let (status, body) = call(&app, post_req(&id, &format!(r#"{{"token":"{token}"}}"#))).await;
        assert_eq!((status, &body), (get_status, &get_body));

        let pairs = [
            (
                get_req(&id, &format!("?token={wrong}")),
                post_req(&id, &format!(r#"{{"token":"{wrong}"}}"#)),
            ),
            (get_req(&id, ""), post_req(&id, "{}")),
            (get_req(&id, ""), post_req(&id, "{not json")),
            (get_req(&id, ""), post_req(&id, "")),
            (
                get_req(&unknown, &format!("?token={token}")),
                post_req(&unknown, &format!(r#"{{"token":"{token}"}}"#)),
            ),
        ];
        for (get, post) in pairs {
            let (want_status, want_body) = call(&app, get).await;
            assert_eq!(want_status, StatusCode::NOT_FOUND);
            assert_eq!(call(&app, post).await, (want_status, want_body));
        }

        let captured = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(!captured.contains(&token), "token logged: {captured}");
        assert!(!captured.contains(wrong), "token logged: {captured}");
        db.drop_database().await;
    }

    #[tokio::test]
    async fn a_webhook_takes_only_so_many() {
        let Some(db) = TestDb::create().await else {
            return;
        };
        let v = validate(req(INDEXER, HOOK)).unwrap();
        for _ in 0..MAX_PER_WEBHOOK {
            insert(&db.pool, &v).await.unwrap();
        }
        assert_eq!(
            check_limits(&db.pool, &v).await.unwrap_err().0,
            StatusCode::TOO_MANY_REQUESTS
        );
        db.drop_database().await;
    }
}
