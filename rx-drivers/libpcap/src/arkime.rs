use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use elasticsearch::{
    http::transport::Transport, params::VersionType, Elasticsearch, GetParts, IndexParts,
};
use serde_json::json;
use tokio::runtime::Handle;

use alphonse_api as api;
use alphonse_arkime as arkime;
use alphonse_utils as utils;
use api::config::Config;
use arkime::stat::Stat;
use utils::elasticsearch::handle_resp;

use crate::{gather_stats, NetworkInterface};

pub(crate) fn main_loop(cfg: Arc<Config>, caps: Vec<Arc<NetworkInterface>>) -> Result<()> {
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

    let db_version = Arc::new(AtomicU64::default());

    let times = [2, 5, 60, 600];

    let mut last_time = [0; 4];

    let host = cfg.get_str("elasticsearch", "http://localhost:9200");
    let es = Arc::new(Elasticsearch::new(Transport::single_node(host.as_str())?));
    let prefix = cfg.get_str("arkime.prefix", "");

    Handle::current().block_on(async {
        match load_stats(&cfg, &es, prefix.clone(), &db_version).await {
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow!("{}", e)),
        }
    })?;

    while !cfg.exit.load(Ordering::Relaxed) {
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
                let db_version = db_version.clone();
                let prefix = prefix.clone();
                Handle::current().spawn(async move {
                    match update_stats(cfg, es, prefix, stats, i, db_version).await {
                        Ok(_) => Ok(()),
                        Err(e) => Err(anyhow!("{}", e)),
                    }
                });

                last_time[i] = now;
            }
        }
    }

    Ok(())
}

async fn load_stats(
    cfg: &Arc<Config>,
    es: &Elasticsearch,
    prefix: String,
    db_version: &AtomicU64,
) -> Result<()> {
    let index = format!("{}stats", prefix);
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
            db_version.store(ver, Ordering::Relaxed);
        }
        code => {
            println!("status code: {}", code);
            println!("response message: {}", resp.text().await?);
        }
    };
    Ok(())
}

async fn update_stats(
    cfg: Arc<Config>,
    es: Arc<Elasticsearch>,
    prefix: String,
    stat: Stat,
    i: usize,
    db_version: Arc<AtomicU64>,
) -> Result<()> {
    let intervals = [1, 5, 60, 600];

    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let resp = if i == 0 {
        let index = format!("{}stats", prefix);
        let parts = IndexParts::IndexId(&index, &cfg.node);
        db_version.fetch_add(1, Ordering::Relaxed);
        es.index(parts)
            .version_type(VersionType::External)
            .version(db_version.load(Ordering::Relaxed) as i64)
            .body(json!(stat))
            .send()
            .await?
    } else {
        let index = format!("{}dstats", prefix);
        let id = format!(
            "{}-{}-{}",
            cfg.node,
            (now / intervals[i]) / 1440,
            intervals[i]
        );
        let parts = IndexParts::IndexId(&index, &id);
        es.index(parts).body(json!(stat)).send().await?
    };

    handle_resp(resp).await?;

    Ok(())
}
