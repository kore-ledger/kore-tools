use server::server_logic::build_routes;
use util::{env::read_port_server, logger::build_logger};
mod server;
mod util;

#[tokio::main]
async fn main() {
    build_logger();
    let num_servers = read_port_server();

    for server in num_servers.iter().take(num_servers.len() - 1) {
        let listener = tokio::net::TcpListener::bind(server.clone()).await.unwrap();

        tokio::spawn(async move {
            axum::serve(listener, build_routes())
                .with_graceful_shutdown(async move {
                    tokio::select! {
                    _ = tokio::signal::ctrl_c() =>
                        println!("Ctrl-c received, shutting down"),
                    }
                })
                .await
                .unwrap();
        });
        println!("Server started at: {}", server);
    }

    let listener = tokio::net::TcpListener::bind(num_servers.last().unwrap().clone())
        .await
        .unwrap();

    axum::serve(listener, build_routes())
        .with_graceful_shutdown(async move {
            tokio::select! {
            _ = tokio::signal::ctrl_c() =>
                println!("Ctrl-c received, shutting down"),
            }
        })
        .await
        .unwrap();
}
