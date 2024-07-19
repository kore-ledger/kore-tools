use std::env;

use crate::server::common::{AllowList, BlockList};

pub fn read_port_server() -> Vec<String> {
    let read = env::var("SERVERS").unwrap_or_else(|_| "".to_string());
    let servers = read.split(',').map(|s| s.trim().to_string()).collect();
    servers
}

pub fn read_blocklist_from_env() -> BlockList {
    let blocklist_str = env::var("BLOCKLIST").unwrap_or_else(|_| "".to_string());
    let list: Vec<String> = blocklist_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    BlockList { list }
}

pub fn read_allowlist_from_env() -> AllowList {
    let allowlist_str = env::var("ALLOWLIST").unwrap_or_else(|_| "".to_string());
    let list: Vec<String> = allowlist_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    AllowList { list }
}
