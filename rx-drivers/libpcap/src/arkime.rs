use std::sync::{atomic::Ordering, Arc};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use elasticsearch::{
    http::response::Response, http::transport::Transport, params::VersionType, Elasticsearch,
    IndexParts,
};
use serde_json::json;

use alphonse_api as api;
use alphonse_arkime as arkime;
use api::config::Config;
use arkime::stat::Stat;

use crate::{gather_stats, NetworkInterface};

pub(crate) async fn main_loop(cfg: Arc<Config>, caps: Vec<Arc<NetworkInterface>>) -> Result<()> {
    let mut stats: Vec<Stat> = Vec::with_capacity(4);
    for _ in 0..stats.capacity() {
        stats.push(Stat::default());
    }

    let db_version = 0;

    let times = [2, 5, 60, 600];

    let mut last_time = [0; 4];

    let host = cfg.get_str("elasticsearch", "http://localhost:9200");
    let es = Arc::new(Elasticsearch::new(Transport::single_node(host.as_str())?));

    while !cfg.exit.load(Ordering::Relaxed) {
        // 0.5 seconds
        tokio::time::sleep(Duration::from_micros(500000)).await;
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

                update_stats(cfg.clone(), &es, stats[i].clone(), i, db_version).await?;

                last_time[i] = now;
            }
        }
    }

    Ok(())
}

async fn update_stats(
    cfg: Arc<Config>,
    es: &Elasticsearch,
    stat: Stat,
    i: usize,
    db_version: u64,
) -> Result<()> {
    let intervals = [1, 5, 60, 600];

    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let prefix = cfg.get_str("arkime.prefix", "");

    let resp = if i == 0 {
        let index = format!("{}stats", prefix);
        let parts = IndexParts::IndexId(&index, &cfg.node);
        es.index(parts)
            .version_type(VersionType::External)
            .version(db_version as i64)
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

async fn handle_resp(resp: Response) -> Result<()> {
    match resp.status_code().as_u16() {
        code if code / 100 == 2 => {}
        c => {
            println!("status code: {}", c);
            println!("response message: {}", resp.text().await.unwrap());
        }
    };
    Ok(())
}
