use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use crossbeam_channel::Receiver;
use elasticsearch::http::{headers::HeaderMap, transport::Transport, Method};
use elasticsearch::{Elasticsearch, UpdateParts};
use serde_json::json;
use tokio::runtime::Handle;

use crate::{Config, PacketInfo, SimpleWriter, FILE_ID};

pub(crate) fn main_loop(cfg: Arc<Config>, receiver: Receiver<Box<PacketInfo>>) -> Result<()> {
    let mut writer = SimpleWriter::default();
    let ts = Transport::single_node(cfg.es_host.as_str())?;
    let es = Arc::new(Elasticsearch::new(ts));

    loop {
        let info = match receiver.try_recv() {
            Ok(info) => info,
            Err(err) => match err {
                crossbeam_channel::TryRecvError::Disconnected => break,
                _ => {
                    std::thread::sleep(Duration::from_micros(500000));
                    continue;
                }
            },
        };

        if info.closing {
            #[cfg(feature = "arkime")]
            {
                let cfg = cfg.clone();
                let es = es.clone();
                let id = FILE_ID.load(Ordering::Relaxed) as u64;
                // Handle::current().spawn(async move { update_file_size(es, cfg, id, filesize) });
            }
            // If current pcap file is about to close, update global file ID
            #[cfg(feature = "arkime")]
            {
                let cfg = cfg.clone();
                let es = es.clone();
                Handle::current().block_on(async move {
                    let mut result = get_sequence_number(&es, &cfg).await;
                    while result.is_err() {
                        result = get_sequence_number(&es, &cfg).await;
                    }
                    let id = match result {
                        Ok(id) => id,
                        Err(e) => return Err(anyhow!("{}", e)),
                    };
                    FILE_ID.store(id as u32, Ordering::SeqCst);
                    Ok(())
                })?;
            }
            #[cfg(not(feature = "arkime"))]
            {
                let id = get_sequence_number(&es, &cfg)?;
                FILE_ID.store(id as u32, Ordering::SeqCst);
            }
        }

        writer.write(info, &es)?;
    }

    Ok(())
}

#[cfg(not(feature = "arkime"))]
fn get_sequence_number(_: &Arc<Elasticsearch>, _: &Arc<Config>) -> Result<u64> {
    Ok((FILE_ID.load(Ordering::Relaxed) + 1) as u64)
}

/// Get next pcap file's sequence number
#[cfg(feature = "arkime")]
pub async fn get_sequence_number(es: &Arc<Elasticsearch>, cfg: &Arc<Config>) -> Result<u64> {
    let resp = es
        .send::<&str, String>(
            Method::Post,
            format!("sequence/_doc/fn-{}", cfg.node).as_str(),
            HeaderMap::default(),
            None,
            Some("{}"),
            None,
        )
        .await?;

    match resp.status_code().as_u16() {
        code if code / 100 == 2 => {
            let text = resp.text().await?;
            let data: serde_json::Map<_, _> = serde_json::from_str(text.as_str())?;
            let version = data
                .get("_version")
                .ok_or(anyhow!("Couldn't fetch sequence"))?
                .as_u64()
                .ok_or(anyhow!("Sequence could be parsed as u64"))?;
            println!("sequence: {}", version);
            return Ok(version);
        }
        code => {
            println!("code: {}", code);
            println!("text: {}", resp.text().await?);
            return Err(anyhow!("Couldn't fetch sequence"));
        }
    }
}

#[cfg(feature = "arkime")]
async fn update_file_size(
    es: Arc<Elasticsearch>,
    cfg: Arc<Config>,
    id: u64,
    filesize: usize,
) -> Result<()> {
    let index = format!("{}files", cfg.prefix);
    let id = format!("{}-{}", cfg.node, id);
    let parts = UpdateParts::IndexId(&index, &id);
    let body = json!({"doc":{"filesize":filesize}});
    let resp = es.update(parts).body(body).send().await?;
    match resp.status_code().as_u16() {
        code if code / 100 == 2 => {}
        code => {
            eprintln!("code: {}", code);
            eprintln!("text: {}", resp.text().await.unwrap());
        }
    }
    Ok(())
}
