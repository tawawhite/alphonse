use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use elasticsearch::http::transport::Transport;
use elasticsearch::params::VersionType;
use elasticsearch::{Elasticsearch, GetParts, IndexParts};
use serde::Serialize;
use serde_json::json;

use alphonse_api as api;
use alphonse_utils as utils;
use api::plugins::rx::RxStat;

use crate::Config;

pub trait StatUnit: Send + Sync {
    fn stats(&self) -> Result<RxStat>;
}

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

fn gather_stats(caps: &[&dyn StatUnit]) -> Result<RxStat> {
    let mut stat = RxStat::default();
    for cap in caps {
        match cap.stats() {
            Ok(stats) => stat += stats,
            Err(e) => eprintln!("{}", e),
        }
    }
    Ok(stat)
}

pub async fn main_loop(
    exit: Arc<AtomicBool>,
    cfg: Arc<Config>,
    caps: Vec<Arc<dyn StatUnit>>,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut stats: Vec<Stat> = Vec::with_capacity(4);
    for _ in 0..stats.capacity() {
        let mut stat = Stat::default();
        stat.node_name = cfg.node.clone();
        stat.host_name = cfg.hostname.clone();
        stat.ver = "2.7.1".to_string();
        stat.start_time = now;
        stats.push(stat);
    }

    let times = [2, 5, 60, 600];

    let mut last_time = [0; 4];

    let es = Arc::new(Elasticsearch::new(Transport::single_node(
        &cfg.elasticsearch,
    )?));

    let mut db_version = load_stats(&cfg, &es).await?;

    while !exit.load(Ordering::Relaxed) {
        // 0.5 seconds
        std::thread::sleep(Duration::from_micros(500000));
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        for i in 0..times.len() {
            if (now - last_time[i]) >= times[i] {
                if stats[i].delta_packets == 0 {
                    last_time[i] = now;
                }

                // ? update disk usage ?
                let caps = caps.iter().map(|cap| cap.as_ref()).collect::<Vec<_>>();
                let rx_stats = gather_stats(&caps)?;

                // ? getrusage ?

                // ? memory usage ?

                stats[i].delta_packets = rx_stats.rx_pkts - stats[i].delta_packets;
                stats[i].delta_dropped = rx_stats.dropped - stats[i].delta_dropped;
                stats[i].delta_overload_dropped =
                    rx_stats.overload_dropped - stats[i].delta_overload_dropped;
                stats[i].delta_bytes = rx_stats.rx_bytes - stats[i].delta_bytes;
                stats[i].current_time = now;

                let cfg = cfg.clone();
                let es = es.clone();
                let stats = stats[i].clone();
                db_version += 1;
                update_stats(cfg, es, stats, i, db_version).await?;

                last_time[i] = now;
            }
        }
    }

    Ok(())
}

async fn load_stats(cfg: &Arc<Config>, es: &Elasticsearch) -> Result<u64> {
    let index = format!("{}stats", cfg.prefix);
    let parts = GetParts::IndexId(&index, &cfg.node);
    let resp = es.get(parts).send().await?;
    match resp.status_code().as_u16() {
        code if code / 100 == 2 => {
            let j: serde_json::Value = resp.json().await?;
            let ver = j
                .get("_version")
                .unwrap_or(&json!(0))
                .as_u64()
                .unwrap_or_default();
            Ok(ver)
        }
        code => Err(anyhow!("{} {}", code, resp.text().await?)),
    }
}

async fn update_stats(
    cfg: Arc<Config>,
    es: Arc<Elasticsearch>,
    stat: Stat,
    i: usize,
    db_version: u64,
) -> Result<()> {
    let intervals = [1, 5, 60, 600];

    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let resp = if i == 0 {
        let index = format!("{}stats", cfg.prefix);
        let parts = IndexParts::IndexId(&index, &cfg.node);
        es.index(parts)
            .version_type(VersionType::External)
            .version(db_version as i64)
            .body(json!(stat))
            .send()
            .await?
    } else {
        let index = format!("{}dstats", cfg.prefix);
        let id = format!(
            "{}-{}-{}",
            cfg.node,
            (now / intervals[i]) / 1440,
            intervals[i]
        );
        let parts = IndexParts::IndexId(&index, &id);
        es.index(parts).body(json!(stat)).send().await?
    };

    utils::elasticsearch::handle_resp(resp).await?;

    Ok(())
}
