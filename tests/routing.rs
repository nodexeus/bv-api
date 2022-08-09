use api::auth::middleware::authorization::AuthorizationService;
use api::auth::Authorization;
use api::http::routes::{api_router, unauthenticated_routes};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use hyper::Body;
use tower::ServiceExt;
use tower_http::auth::AsyncRequireAuthorizationLayer;
use tower_http::trace::TraceLayer;

fn possible_routes() -> Vec<(&'static str, &'static str, StatusCode)> {
    vec![
        // Non nested routes
        ("/foo_bar", "GET", StatusCode::OK),
        ("/reset", "POST", StatusCode::UNAUTHORIZED),
        ("/reset", "PUT", StatusCode::UNAUTHORIZED),
        ("/login", "POST", StatusCode::INTERNAL_SERVER_ERROR),
        ("/refresh", "POST", StatusCode::UNAUTHORIZED),
        ("/whoami", "GET", StatusCode::UNAUTHORIZED),
        ("/block_height", "GET", StatusCode::UNAUTHORIZED),
        ("/block_info", "GET", StatusCode::UNAUTHORIZED),
        ("/block_info", "PUT", StatusCode::UNAUTHORIZED),
        ("/payments_due", "GET", StatusCode::UNAUTHORIZED),
        ("/pay_adresses", "GET", StatusCode::UNAUTHORIZED),
        ("/rewards", "POST", StatusCode::UNAUTHORIZED),
        ("/payments", "POST", StatusCode::UNAUTHORIZED),
        ("/qr/id", "GET", StatusCode::UNAUTHORIZED),
        ("/blockchains", "GET", StatusCode::UNAUTHORIZED),
        // Group routes
        ("/groups/nodes", "GET", StatusCode::UNAUTHORIZED),
        ("/groups/nodes/id", "GET", StatusCode::UNAUTHORIZED),
        // Node routes
        ("/nodes", "POST", StatusCode::UNAUTHORIZED),
        ("/nodes/id", "GET", StatusCode::UNAUTHORIZED),
        ("/nodes/id/info", "PUT", StatusCode::UNAUTHORIZED),
        // Command routes
        ("/commands/id", "GET", StatusCode::UNAUTHORIZED),
        ("/commands/id", "DELETE", StatusCode::UNAUTHORIZED),
        ("/commands/id/response", "PUT", StatusCode::UNAUTHORIZED),
        // Validator routes
        ("/validators", "GET", StatusCode::UNAUTHORIZED),
        ("/validators/id", "GET", StatusCode::UNAUTHORIZED),
        ("/validators/id/migrate", "POST", StatusCode::UNAUTHORIZED),
        ("/validators/id/status", "PUT", StatusCode::UNAUTHORIZED),
        (
            "/validators/id/stake_status",
            "PUT",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/validators/id/owner_address",
            "PUT",
            StatusCode::UNAUTHORIZED,
        ),
        ("/validators/id/penalty", "PUT", StatusCode::UNAUTHORIZED),
        ("/validators/id/identity", "PUT", StatusCode::UNAUTHORIZED),
        ("/validators/staking", "GET", StatusCode::UNAUTHORIZED),
        ("/validators/consensus", "GET", StatusCode::UNAUTHORIZED),
        (
            "/validators/needs_attention",
            "GET",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/validators/inventory/count",
            "GET",
            StatusCode::UNAUTHORIZED,
        ),
        // Broadcast filter routes
        ("/broadcast_filters", "POST", StatusCode::UNAUTHORIZED),
        ("/broadcast_filters/id", "GET", StatusCode::UNAUTHORIZED),
        ("/broadcast_filters/id", "PUT", StatusCode::UNAUTHORIZED),
        ("/broadcast_filters/id", "DELETE", StatusCode::UNAUTHORIZED),
        // Organization routes
        ("/orgs", "POST", StatusCode::UNAUTHORIZED),
        ("/orgs/id", "GET", StatusCode::UNAUTHORIZED),
        ("/orgs/id", "DELETE", StatusCode::UNAUTHORIZED),
        ("/orgs/id", "PUT", StatusCode::UNAUTHORIZED),
        ("/orgs/id/members", "GET", StatusCode::UNAUTHORIZED),
        (
            "/orgs/id/broadcast_filters",
            "GET",
            StatusCode::UNAUTHORIZED,
        ),
        // User routes
        ("/users", "POST", StatusCode::UNAUTHORIZED),
        ("/users/id/orgs", "GET", StatusCode::UNAUTHORIZED),
        ("/users/id/summary", "GET", StatusCode::UNAUTHORIZED),
        ("/users/id/payments", "GET", StatusCode::UNAUTHORIZED),
        ("/users/id/rewards/summary", "GET", StatusCode::UNAUTHORIZED),
        ("/users/id/validators", "GET", StatusCode::UNAUTHORIZED),
        ("/users/id/validators", "POST", StatusCode::UNAUTHORIZED),
        (
            "/users/id/validators/staking/export",
            "GET",
            StatusCode::UNAUTHORIZED,
        ),
        ("/users/id/invoices", "GET", StatusCode::UNAUTHORIZED),
        ("/users/summary", "GET", StatusCode::UNAUTHORIZED),
        // Host routes
        ("/hosts", "POST", StatusCode::UNAUTHORIZED),
        ("/hosts", "GET", StatusCode::UNAUTHORIZED),
        ("/hosts/id", "GET", StatusCode::UNAUTHORIZED),
        ("/hosts/id", "PUT", StatusCode::UNAUTHORIZED),
        ("/hosts/id", "DELETE", StatusCode::UNAUTHORIZED),
        ("/hosts/id/status", "PUT", StatusCode::UNAUTHORIZED),
        ("/hosts/id/commands", "POST", StatusCode::UNAUTHORIZED),
        ("/hosts/id/commands", "GET", StatusCode::UNAUTHORIZED),
        (
            "/hosts/id/commands/pending",
            "GET",
            StatusCode::UNAUTHORIZED,
        ),
        ("/hosts/token/:token", "GET", StatusCode::UNAUTHORIZED),
        // Host provisions routes
        ("/host_provisions", "POST", StatusCode::UNAUTHORIZED),
        ("/host_provisions/id", "GET", StatusCode::UNAUTHORIZED),
        (
            "/host_provisions/id/hosts",
            "POST",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ]
}

async fn foo_bar() -> &'static str {
    "WORKS!"
}

#[tokio::test]
async fn test_possible_routes() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let routes = possible_routes();
    let enforcer = Authorization::new().await.unwrap();
    let auth_service = AuthorizationService::new(enforcer);
    let app = api_router()
        .layer(TraceLayer::new_for_http())
        .layer(AsyncRequireAuthorizationLayer::new(auth_service))
        .route("/foo_bar", get(foo_bar))
        .nest("/", unauthenticated_routes());

    let mut cnt = 1;

    for item in routes {
        let route = item.0;
        let method = item.1;
        let expected_response_code = item.2;

        println!("testing route #{} {} {}", cnt, method, route);

        let req = Request::builder()
            .method(method)
            .uri(route)
            .body(Body::empty())?;
        let response = app.clone().oneshot(req).await?;

        assert_eq!(response.status(), expected_response_code);
        cnt += 1;
    }

    Ok(())
}
