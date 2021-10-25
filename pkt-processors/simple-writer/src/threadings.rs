use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::Receiver;
use elasticsearch::http::transport::Transport;
use elasticsearch::Elasticsearch;
use tokio::runtime::Handle;

use crate::arkime::{get_sequence_number, update_file_size};
use crate::{Config, PacketInfo, SimpleWriter, FILE_ID};

pub(crate) fn main_loop(cfg: Arc<Config>, receiver: Receiver<Box<PacketInfo>>) -> Result<()> {
    let ts = Transport::single_node(cfg.es_host.as_str())?;
    let es = Arc::new(Elasticsearch::new(ts));
    let mut writer = SimpleWriter::new(cfg.enable_arkime, es.clone());

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
            // Update last pcap file's filesize
            if cfg.enable_arkime {
                let cfg = cfg.clone();
                let es = es.clone();
                let id = FILE_ID.load(Ordering::Relaxed) as u64;
                match info.file_info {
                    None => unreachable!("should never happens"),
                    Some((_, filesize)) => {
                        Handle::current().spawn(async move {
                            match update_file_size(es, cfg, id, filesize).await {
                                Ok(_) => {}
                                Err(e) => eprintln!("{}", e),
                            }
                        });
                    }
                }
            }

            // If current pcap file is about to close, update global file ID
            if cfg.enable_arkime {
                let cfg = cfg.clone();
                let es = es.clone();
                Handle::current().block_on(async move {
                    let mut result = get_sequence_number(&es, &cfg).await;
                    while result.is_err() {
                        result = get_sequence_number(&es, &cfg).await;
                    }
                    let id = match result {
                        Ok(id) => id,
                        Err(e) => return Err(anyhow::anyhow!("{}", e)),
                    };
                    FILE_ID.store(id as u32, Ordering::SeqCst);
                    Ok(())
                })?;
            } else {
                let id = (FILE_ID.load(Ordering::Relaxed) + 1) as u64;
                FILE_ID.store(id as u32, Ordering::SeqCst);
            }
        }

        writer.write(info)?;
    }

    Ok(())
}
