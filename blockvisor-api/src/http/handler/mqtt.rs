use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Json, State};
use axum::response::Response;
use axum::routing::{Router, post};
use axum_extra::extract::WithRejection;
use displaydoc::Display;
use serde_json::Value;
use thiserror::Error;
use tracing::{debug, error};

use crate::auth::rbac::{MqttAdminPerm, MqttPerm};
use crate::auth::resource::{Resource, Resources};
use crate::config::Context;
use crate::database::Database;
use crate::grpc::Status;
use crate::http::response;
use crate::mqtt::handler::{self, AclRequest, Topic};

use super::ErrorWrapper;

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Auth check failed: {0}
    Auth(#[from] crate::auth::Error),
    /// Database error: {0}
    Database(#[from] crate::database::Error),
    /// MQTT handler error: {0}
    Handler(#[from] handler::Error),
    /// Failed to parse JSON: {0}
    ParseJson(#[from] JsonRejection),
    /// Failed to parse RequestToken: {0}
    ParseRequestToken(crate::auth::token::Error),
    /// Wildcard topic subscribe without `mqtt-admin-acl`: {0}
    WildcardTopic(String),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use crate::auth::Error::{ExpiredJwt, ExpiredRefresh};
        use Error::*;
        if !matches!(err, Error::Auth(ExpiredJwt(_) | ExpiredRefresh(_))) {
            error!("{err}");
        }
        match err {
            Auth(_)
            | Handler(handler::Error::Claims(_))
            | ParseRequestToken(_)
            | WildcardTopic(_) => Status::unauthorized("Unauthorized"),
            Database(_) => Status::internal("Database error"),
            Handler(_) => Status::invalid_argument("Invalid arguments"),
            ParseJson(rejection) => Status::unparseable_request(rejection.body_text()),
        }
    }
}

impl From<JsonRejection> for ErrorWrapper<Error> {
    fn from(value: JsonRejection) -> Self {
        Self(value.into())
    }
}

#[derive(serde::Serialize)]
struct AclResponse {
    result: &'static str,
}

pub fn router<S>(context: Arc<Context>) -> Router<S>
where
    S: Clone + Send + Sync,
{
    Router::new()
        .route("/acl", post(acl))
        .route("/auth", post(auth))
        .with_state(context)
}

#[allow(clippy::unused_async)]
async fn auth(
    WithRejection(value, _): WithRejection<Json<Value>, ErrorWrapper<Error>>,
) -> Response {
    debug!("MQTT auth payload: {value:?}");
    response::ok()
}

async fn acl(
    State(ctx): State<Arc<Context>>,
    WithRejection(Json(req), _): WithRejection<Json<AclRequest>, ErrorWrapper<Error>>,
) -> Result<Json<AclResponse>, super::Error> {
    let token = req
        .username
        .parse()
        .map_err(|err| Status::from(Error::ParseRequestToken(err)))?;
    let mut conn = ctx.pool.conn().await?;

    if ctx
        .auth
        .authorize_token(&token, MqttAdminPerm::Acl.into(), Resources::All, &mut conn)
        .await
        .is_ok()
    {
        return Ok(Json(AclResponse { result: "allow" }));
    }

    let resources: Resources = match req.topic {
        Topic::Orgs(org_id) => Resource::from(org_id).into(),
        Topic::Hosts(host_id) => Resource::from(host_id).into(),
        Topic::Nodes(node_id) => Resource::from(node_id).into(),
        Topic::BvHostsStatus(host_id) => Resource::from(host_id).into(),
        Topic::Wildcard(topic) => return Err(Status::from(Error::WildcardTopic(topic)).into()),
    };

    match ctx
        .auth
        .authorize_token(&token, MqttPerm::Acl.into(), resources, &mut conn)
        .await
    {
        Ok(_) => Ok(Json(AclResponse { result: "allow" })),
        Err(_) => Ok(Json(AclResponse { result: "deny" })),
    }
}
