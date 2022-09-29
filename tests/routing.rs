#[allow(dead_code)]
mod setup;

use setup::setup;
use std::sync::Arc;

use axum::http::{Request, StatusCode};
use hyper::Body;
use test_macros::before;
use tower::ServiceExt;

fn possible_routes() -> Vec<(&'static str, &'static str, StatusCode)> {
    vec![
        // Non nested routes
        ("/health", "GET", StatusCode::OK),
    ]
}

#[before(call = "setup")]
#[tokio::test]
async fn test_possible_routes() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let db = Arc::new(_before_values.await);
    let routes = possible_routes();
    let app = api::http::server(std::sync::Arc::new(db.pool.clone())).await;

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
