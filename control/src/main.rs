use std::net::SocketAddr;

use axum::http::{header, HeaderName, Method};
use log::error;
use middleware::middlewares::tower_trace;
use server::server_logic::build_routes;
use std::env::var;
use tower_http::cors::{Any, CorsLayer};
use util::{env::read_port_server, logger::build_logger};
mod middleware;
mod server;
mod util;

#[tokio::main]
async fn main() {
    build_logger();
    let num_servers = read_port_server();
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_lowercase(b"username").unwrap(),
        ])
        .allow_origin(Any);

    let mut servers = Vec::new();
    for i in 0..num_servers.len() {
        let listener = tokio::net::TcpListener::bind(num_servers[i].clone())
            .await
            .unwrap();
        let router = tower_trace(build_routes())
            .layer(cors.clone())
            .into_make_service_with_connect_info::<SocketAddr>();

        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    tokio::select! {
                    _ = tokio::signal::ctrl_c() =>
                        println!("Ctrl-c received, shutting down"),
                    }
                })
                .await.unwrap();
        });

        servers.push(tokio::spawn(server));
        println!("Server started at: {}", num_servers[i]);
    }

    // Espera a que todos los servidores finalicen
    for server in servers {
        let _ = server.await.unwrap();
    }
}
