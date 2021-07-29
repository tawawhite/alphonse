use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use crossbeam_channel::Receiver;
use elasticsearch::http::transport::Transport;
use elasticsearch::Elasticsearch;
use tokio::runtime::Handle;

#[cfg(feature = "arkime")]
use crate::arkime::get_sequence_number;
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
