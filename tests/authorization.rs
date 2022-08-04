mod setup;

use crate::setup::get_test_host;
use api::auth::TokenHolderType;
use api::handlers::list_pending_commands;
use api::models::{Token, TokenRole};
use axum::routing::get;
use axum::{Extension, Router};
use base64::encode;
use http::{Request, StatusCode};
use hyper::Body;
use setup::{get_admin_user, setup};
use std::sync::Arc;
use test_macros::*;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;

#[before(call = "setup")]
#[tokio::test]
async fn should_respond_ok() {
    let db = _before_values.await;
    let user = get_admin_user(&db).await;
    let host = get_test_host(&db).await;
    let token = Token::create(user.id, TokenRole::Admin, &db, TokenHolderType::User)
        .await
        .unwrap();
    let auth_header = encode(token.token);
    let uri = format!("/hosts/{}/commands/pending", host.id);

    let app = Router::new()
        .route("/hosts/:id/commands/pending", get(list_pending_commands))
        .layer(Extension(Arc::new(db)))
        .layer(TraceLayer::new_for_http());

    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("Authorization", auth_header)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
