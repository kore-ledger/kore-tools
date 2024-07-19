use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use axum::{
    routing::{get, put},
    Extension, Json, Router,
};
use log::debug;
use serde_json::json;
use tower::ServiceBuilder;

use crate::{
    middleware::middlewares::limit_ip_request,
    server::common::IPSMaxConnectState,
    util::env::{read_allowlist_from_env, read_blocklist_from_env},
};

use super::{
    common::{AllowList, BlockList},
    errors::Errors,
};

async fn handler_get_allowlist(
    Extension(allowlist): Extension<Arc<RwLock<AllowList>>>,
) -> Result<Json<Vec<String>>, Errors> {
    let allowlist = allowlist.read().unwrap();
    Ok(Json(allowlist.list.clone()))
}

async fn handler_get_blocklist(
    Extension(blocklist): Extension<Arc<RwLock<BlockList>>>,
) -> Result<Json<Vec<String>>, Errors> {
    let blocklist = blocklist.read().unwrap();
    Ok(Json(blocklist.list.clone()))
}

async fn handler_push_allowlist(
    Extension(allowlist): Extension<Arc<RwLock<AllowList>>>,
    Json(data): Json<AllowList>,
) -> Result<Json<String>, Errors> {
    let mut allowlist = allowlist.write().unwrap();
    *allowlist = data;
    Ok(Json(json!({"status": "ok"}).to_string()))
}

async fn handler_push_blocklist(
    Extension(blocklist): Extension<Arc<RwLock<BlockList>>>,
    Json(data): Json<BlockList>,
) -> Result<Json<String>, Errors> {
    let mut blocklist = blocklist.write().unwrap();
    *blocklist = data;
    Ok(Json(json!({"status": "ok"}).to_string()))
}

pub fn build_routes() -> Router {
    debug!("Creating states");
    let ips_connects_state = Arc::new(RwLock::new(IPSMaxConnectState {
        ips_connects: HashMap::default(),
    }));
    debug!("Creating default onject");
    let allowlist_state = Arc::new(RwLock::new(read_allowlist_from_env()));
    let blocklist_state = Arc::new(RwLock::new(read_blocklist_from_env()));

    debug!("Creating routes");
    let public = Router::new()
        .route("/allow", get(handler_get_allowlist))
        .route("/block", get(handler_get_blocklist))
        .route("/allow", put(handler_push_allowlist))
        .route("/block", put(handler_push_blocklist))
        .layer(
            ServiceBuilder::new()
                .layer(Extension(ips_connects_state))
                .layer(axum::middleware::from_fn(limit_ip_request))
                .layer(Extension(allowlist_state))
                .layer(Extension(blocklist_state)),
        );

    Router::new().merge(public)
}
