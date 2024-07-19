use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::SystemTime};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AllowList {
    pub list: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockList {
    pub list: Vec<String>,
}


#[derive(Clone)]
pub struct ConnectionsDuration {
    pub time: SystemTime,
    pub connections: u32,
}

#[derive(Clone)]
pub struct IPSMaxConnectState {
    pub ips_connects: HashMap<String, ConnectionsDuration>,
}
