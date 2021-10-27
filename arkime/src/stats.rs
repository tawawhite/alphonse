use anyhow::Result;
use elasticsearch::{Elasticsearch, IndexParts};
use serde::Serialize;
use serde_json::json;

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stat {
    /// alphonse version
    pub ver: String,
    pub node_name: String,
    #[serde(rename = "hostname")]
    pub host_name: String,
    pub interval: u32,
    pub current_time: u64,
    pub used_space_m: u64,
    pub free_space_m: u64,
    pub free_space_p: f64,
    pub monitoring: f64,
    pub memory: u64,
    pub memory_p: f64,
    pub cpu: u64,
    pub disk_queue: u64,
    pub es_queue: u64,
    pub packet_queue: u64,
    pub frag_queue: u64,
    pub frags: u64,
    pub need_save: u64,
    pub close_queue: u64,
    pub total_packets: u64,
    pub total_k: u64,
    pub total_sessions: u64,
    pub total_dropped: u64,
    pub tcp_sessions: u64,
    pub udp_sessions: u64,
    pub icmp_sessions: u64,
    pub sctp_sessions: u64,
    pub esp_sessions: u64,
    pub other_sessions: u64,
    pub delta_packets: u64,
    pub delta_bytes: u64,
    pub delta_written_bytes: u64,
    pub delta_un_written_bytes: u64,
    pub delta_sessions: u64,
    pub delta_sessions_bytes: u64,
    pub delta_dropped: u64,
    pub delta_frags_dropped: u64,
    pub delta_overload_dropped: u64,
    pub delta_es_dropped: u64,
    #[serde(rename = "esHealthMS")]
    pub es_health_ms: u64,
    #[serde(rename = "deltaMS")]
    pub delta_ms: u64,
    pub start_time: u64,
}

pub async fn send_stat(es: &Elasticsearch, prefix: &str, stat: &Stat) -> Result<()> {
    let index = format!("{}stats", prefix);
    let parts = IndexParts::Index(&index);
    let resp = es.index(parts).body(json!(stat)).send().await?;
    match resp.status_code().as_u16() {
        code if code >= 200 && code < 300 => {}
        c => {
            println!("status code: {}", c);
            println!("response message: {}", resp.text().await.unwrap());
        }
    };
    Ok(())
}
