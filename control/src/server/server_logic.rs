use std::sync::{Arc, RwLock};

use axum::{
    routing::{get, put},
    Extension, Json, Router,
};
use log::debug;
use tower::ServiceBuilder;

use crate::util::env::{read_allowlist_from_env, read_blocklist_from_env};

use super::common::List;

async fn handler_get_allowlist(
    Extension(allowlist): Extension<Arc<RwLock<List>>>,
) -> Result<Json<List>, ()> {
    let allowlist = allowlist.read().unwrap();
    Ok(Json(allowlist.clone()))
}

async fn handler_get_blocklist(
    Extension(blocklist): Extension<Arc<RwLock<List>>>,
) -> Result<Json<List>, ()> {
    let blocklist = blocklist.read().unwrap();
    Ok(Json(blocklist.clone()))
}

async fn handler_push_allowlist(
    Extension(allowlist): Extension<Arc<RwLock<List>>>,
    Json(data): Json<List>,
) -> Result<Json<String>, ()> {
    let mut allowlist = allowlist.write().unwrap();
    *allowlist = data;
    Ok(Json("Ok".to_string()))
}

async fn handler_push_blocklist(
    Extension(blocklist): Extension<Arc<RwLock<List>>>,
    Json(data): Json<List>,
) -> Result<Json<String>, ()> {
    let mut blocklist = blocklist.write().unwrap();
    *blocklist = data;
    Ok(Json("Ok".to_string()))
}

pub fn build_routes() -> Router {
    debug!("Creating default object");
    let allowlist_state = Arc::new(RwLock::new(read_allowlist_from_env()));
    let blocklist_state = Arc::new(RwLock::new(read_blocklist_from_env()));

    debug!("Creating routes");
    let allowlist_routes = Router::new()
        .route("/allow", get(handler_get_allowlist))
        .route("/allow", put(handler_push_allowlist))
        .layer(ServiceBuilder::new().layer(Extension(allowlist_state)));

    let blocklist_routes = Router::new()
        .route("/block", get(handler_get_blocklist))
        .route("/block", put(handler_push_blocklist))
        .layer(ServiceBuilder::new().layer(Extension(blocklist_state)));

    Router::new().merge(allowlist_routes).merge(blocklist_routes)
}
