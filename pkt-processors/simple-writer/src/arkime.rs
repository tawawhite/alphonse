use std::sync::Arc;

use anyhow::{anyhow, Result};
use elasticsearch::http::{headers::HeaderMap, Method};
use elasticsearch::params::Refresh;
use elasticsearch::{Elasticsearch, UpdateParts};
use serde_json::json;

use crate::{Config, PcapFileInfo};

// Index new file information into Elasticsearch
pub(crate) async fn index_file_info(es: Arc<Elasticsearch>, info: Box<PcapFileInfo>) -> Result<()> {
    let id = format!("{}-{}", info.node, info.num);
    let resp = es
        .index(elasticsearch::IndexParts::IndexId("files", &id))
        .body(json!(info))
        .refresh(Refresh::True)
        .send()
        .await?;

    match resp.status_code().as_u16() {
        code if (code / 100) == 2 => {}
        code => {
            eprintln!("Send file info failed");
            eprintln!("code: {}", code);
            eprintln!("text: {}", resp.text().await.unwrap());
        }
    }

    Ok(())
}

/// Get next pcap file's sequence number
pub(crate) async fn get_sequence_number(es: &Arc<Elasticsearch>, cfg: &Arc<Config>) -> Result<u64> {
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
pub(crate) async fn update_file_size(
    es: Arc<Elasticsearch>,
    cfg: Arc<Config>,
    num: u64,
    filesize: usize,
) -> Result<()> {
    let index = format!("{}files", cfg.prefix);
    let id = format!("{}-{}", cfg.node, num);
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
