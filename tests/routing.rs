use api::auth::middleware::authorization::AuthorizationService;
use api::auth::Authorization;
use api::routes::api_router;
use axum::http::{Request, StatusCode};
use hyper::Body;
use tower::ServiceExt;
use tower_http::auth::AsyncRequireAuthorizationLayer;
use tower_http::trace::TraceLayer;

fn possible_routes() -> Vec<(&'static str, &'static str, StatusCode)> {
    vec![
        // Non nested routes
        ("/foo_bar", "GET", StatusCode::FORBIDDEN),
        ("/reset", "POST", StatusCode::FORBIDDEN),
        ("/reset", "PUT", StatusCode::FORBIDDEN),
        ("/login", "POST", StatusCode::FORBIDDEN),
        ("/refresh", "POST", StatusCode::FORBIDDEN),
        ("/whoami", "GET", StatusCode::FORBIDDEN),
        ("/block_height", "GET", StatusCode::FORBIDDEN),
        ("/block_info", "GET", StatusCode::FORBIDDEN),
        ("/block_info", "PUT", StatusCode::FORBIDDEN),
        ("/payments_due", "GET", StatusCode::FORBIDDEN),
        ("/pay_adresses", "GET", StatusCode::FORBIDDEN),
        ("/rewards", "POST", StatusCode::FORBIDDEN),
        ("/payments", "POST", StatusCode::FORBIDDEN),
        ("/qr/id", "GET", StatusCode::FORBIDDEN),
        ("/blockchains", "GET", StatusCode::FORBIDDEN),
        // Group routes
        ("/groups/nodes", "GET", StatusCode::FORBIDDEN),
        ("/groups/nodes/id", "GET", StatusCode::FORBIDDEN),
        // Node routes
        ("/nodes", "POST", StatusCode::FORBIDDEN),
        ("/nodes/id", "GET", StatusCode::FORBIDDEN),
        ("/nodes/id/info", "PUT", StatusCode::FORBIDDEN),
        // Command routes
        ("/commands/id", "GET", StatusCode::FORBIDDEN),
        ("/commands/id", "DELETE", StatusCode::FORBIDDEN),
        ("/commands/id/response", "PUT", StatusCode::FORBIDDEN),
        // Validator routes
        ("/validators", "GET", StatusCode::FORBIDDEN),
        ("/validators/id", "GET", StatusCode::FORBIDDEN),
        ("/validators/id/migrate", "POST", StatusCode::FORBIDDEN),
        ("/validators/id/status", "PUT", StatusCode::FORBIDDEN),
        ("/validators/id/stake_status", "PUT", StatusCode::FORBIDDEN),
        ("/validators/id/owner_address", "PUT", StatusCode::FORBIDDEN),
        ("/validators/id/penalty", "PUT", StatusCode::FORBIDDEN),
        ("/validators/id/identity", "PUT", StatusCode::FORBIDDEN),
        ("/validators/staking", "GET", StatusCode::FORBIDDEN),
        ("/validators/consensus", "GET", StatusCode::FORBIDDEN),
        ("/validators/needs_attention", "GET", StatusCode::FORBIDDEN),
        ("/validators/inventory/count", "GET", StatusCode::FORBIDDEN),
        // Broadcast filter routes
        ("/broadcast_filters", "POST", StatusCode::FORBIDDEN),
        ("/broadcast_filters/id", "GET", StatusCode::FORBIDDEN),
        ("/broadcast_filters/id", "PUT", StatusCode::FORBIDDEN),
        ("/broadcast_filters/id", "DELETE", StatusCode::FORBIDDEN),
        // Organization routes
        ("/orgs", "POST", StatusCode::FORBIDDEN),
        ("/orgs/id", "GET", StatusCode::FORBIDDEN),
        ("/orgs/id", "DELETE", StatusCode::FORBIDDEN),
        ("/orgs/id", "PUT", StatusCode::FORBIDDEN),
        ("/orgs/id/members", "GET", StatusCode::FORBIDDEN),
        ("/orgs/id/broadcast_filters", "GET", StatusCode::FORBIDDEN),
        // User routes
        ("/users", "POST", StatusCode::FORBIDDEN),
        ("/users/id/orgs", "GET", StatusCode::FORBIDDEN),
        ("/users/id/summary", "GET", StatusCode::FORBIDDEN),
        ("/users/id/payments", "GET", StatusCode::FORBIDDEN),
        ("/users/id/rewards/summary", "GET", StatusCode::FORBIDDEN),
        ("/users/id/validators", "GET", StatusCode::FORBIDDEN),
        ("/users/id/validators", "POST", StatusCode::FORBIDDEN),
        (
            "/users/id/validators/staking/export",
            "GET",
            StatusCode::FORBIDDEN,
        ),
        ("/users/id/invoices", "GET", StatusCode::FORBIDDEN),
        ("/users/summary", "GET", StatusCode::FORBIDDEN),
        // Host routes
        ("/hosts", "POST", StatusCode::FORBIDDEN),
        ("/hosts", "GET", StatusCode::FORBIDDEN),
        ("/hosts/id", "GET", StatusCode::FORBIDDEN),
        ("/hosts/id", "PUT", StatusCode::FORBIDDEN),
        ("/hosts/id", "DELETE", StatusCode::FORBIDDEN),
        ("/hosts/id/status", "PUT", StatusCode::FORBIDDEN),
        ("/hosts/id/commands", "POST", StatusCode::FORBIDDEN),
        ("/hosts/id/commands", "GET", StatusCode::FORBIDDEN),
        ("/hosts/id/commands/pending", "GET", StatusCode::FORBIDDEN),
        ("/hosts/token/:token", "GET", StatusCode::FORBIDDEN),
        // Host provisions routes
        ("/host_provisions", "POST", StatusCode::FORBIDDEN),
        ("/host_provisions/id", "GET", StatusCode::FORBIDDEN),
        ("/host_provisions/id/hosts", "POST", StatusCode::FORBIDDEN),
    ]
}

#[tokio::test]
async fn test_possible_routes() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let routes = possible_routes();
    let enforcer = Authorization::new().await.unwrap();
    let auth_service = AuthorizationService::new(enforcer);
    let app = api_router()
        .layer(TraceLayer::new_for_http())
        .layer(AsyncRequireAuthorizationLayer::new(auth_service));
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
