use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::header::HeaderMap;
use axum::routing::{self, Router};
use axum::Json;
use diesel_async::scoped_futures::ScopedFutureExt;

use crate::config::Context;
use crate::database::Transaction;
use crate::grpc::{self, api, common};

use super::Error;

pub fn router<S>(context: Arc<Context>) -> Router<S>
where
    S: Clone + Send + Sync,
{
    Router::new()
        .route("/", routing::post(create_host))
        .route("/region", routing::post(create_region))
        .route("/:id", routing::get(get_host))
        .route("/region/:id", routing::get(get_region))
        .route("/", routing::get(list_hosts))
        .route("/regions", routing::get(list_regions))
        .route("/:id", routing::put(update_host))
        .route("/region/:id", routing::put(update_region))
        .route("/:id", routing::delete(delete_host))
        .route("/:id/start", routing::put(start))
        .route("/:id/stop", routing::put(stop))
        .route("/:id/restart", routing::put(restart))
        .with_state(context)
}

async fn create_host(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::HostServiceCreateHostRequest>,
) -> Result<Json<api::HostServiceCreateHostResponse>, Error> {
    ctx.write(|write| grpc::host::create_host(req, headers.into(), write).scope_boxed())
        .await
}

async fn create_region(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::HostServiceCreateRegionRequest>,
) -> Result<Json<api::HostServiceCreateRegionResponse>, Error> {
    ctx.write(|write| grpc::host::create_region(req, headers.into(), write).scope_boxed())
        .await
}

async fn get_host(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceGetHostResponse>, Error> {
    let req = api::HostServiceGetHostRequest { host_id };
    ctx.read(|read| grpc::host::get_host(req, headers.into(), read).scope_boxed())
        .await
}

async fn get_region(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((region_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceGetRegionResponse>, Error> {
    let req = api::HostServiceGetRegionRequest {
        region: Some(api::host_service_get_region_request::Region::RegionId(
            region_id,
        )),
    };
    ctx.read(|read| grpc::host::get_region(req, headers.into(), read).scope_boxed())
        .await
}

async fn list_hosts(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(req): Query<api::HostServiceListHostsRequest>,
) -> Result<Json<api::HostServiceListHostsResponse>, Error> {
    ctx.read(|read| grpc::host::list_hosts(req, headers.into(), read).scope_boxed())
        .await
}

async fn list_regions(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(req): Query<api::HostServiceListRegionsRequest>,
) -> Result<Json<api::HostServiceListRegionsResponse>, Error> {
    ctx.read(|read| grpc::host::list_regions(req, headers.into(), read).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostServiceUpdateHostRequest {
    network_name: Option<String>,
    display_name: Option<String>,
    region_id: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    bv_version: Option<String>,
    cpu_cores: Option<u64>,
    memory_bytes: Option<u64>,
    disk_bytes: Option<u64>,
    schedule_type: Option<i32>,
    update_tags: Option<common::UpdateTags>,
    cost: Option<common::BillingAmount>,
}

async fn update_host(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
    Json(req): Json<HostServiceUpdateHostRequest>,
) -> Result<Json<api::HostServiceUpdateHostResponse>, Error> {
    let req = api::HostServiceUpdateHostRequest {
        host_id,
        network_name: req.network_name,
        display_name: req.display_name,
        region_id: req.region_id,
        os: req.os,
        os_version: req.os_version,
        bv_version: req.bv_version,
        cpu_cores: req.cpu_cores,
        memory_bytes: req.memory_bytes,
        disk_bytes: req.disk_bytes,
        schedule_type: req.schedule_type,
        update_tags: req.update_tags,
        cost: req.cost,
    };
    ctx.write(|write| grpc::host::update_host(req, headers.into(), write).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostServiceUpdateRegionRequest {
    display_name: Option<String>,
    sku_code: Option<String>,
}

async fn update_region(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((region_id,)): Path<(String,)>,
    Json(req): Json<HostServiceUpdateRegionRequest>,
) -> Result<Json<api::HostServiceUpdateRegionResponse>, Error> {
    let req = api::HostServiceUpdateRegionRequest {
        region_id,
        display_name: req.display_name,
        sku_code: req.sku_code,
    };
    ctx.write(|write| grpc::host::update_region(req, headers.into(), write).scope_boxed())
        .await
}

async fn delete_host(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceDeleteHostResponse>, Error> {
    let req = api::HostServiceDeleteHostRequest { host_id };
    ctx.write(|write| grpc::host::delete_host(req, headers.into(), write).scope_boxed())
        .await
}

async fn start(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceStartResponse>, Error> {
    let req = api::HostServiceStartRequest { host_id };
    ctx.write(|write| grpc::host::start(req, headers.into(), write).scope_boxed())
        .await
}

async fn stop(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceStopResponse>, Error> {
    let req = api::HostServiceStopRequest { host_id };
    ctx.write(|write| grpc::host::stop(req, headers.into(), write).scope_boxed())
        .await
}

async fn restart(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceRestartResponse>, Error> {
    let req = api::HostServiceRestartRequest { host_id };
    ctx.write(|write| grpc::host::restart(req, headers.into(), write).scope_boxed())
        .await
}
