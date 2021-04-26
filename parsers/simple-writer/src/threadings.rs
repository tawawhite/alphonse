use std::sync::atomic::Ordering;

use anyhow::Result;
use crossbeam_channel::Receiver;
use elasticsearch::http::{headers::HeaderMap, transport::Transport, Method};
use elasticsearch::Elasticsearch;

use crate::{Config, PacketInfo, SimpleWriter, FILE_ID};

/// Pcaket writing thread
pub struct Thread {
    pub writer: SimpleWriter,
    pub receiver: Receiver<Box<PacketInfo>>,
}

impl Thread {
    pub fn spawn(&mut self, cfg: Config) -> Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .thread_name("alphonse-simple")
            .enable_all()
            .build()
            .unwrap();
        let mut writer = SimpleWriter::default();

        println!("alphonse-writer thread started");

        rt.block_on(async {
            let es = Elasticsearch::new(Transport::single_node(cfg.es_host.as_str()).unwrap());
            loop {
                if FILE_ID.load(Ordering::Relaxed) == 0 {
                    #[cfg(feature = "arkime")]
                    let id = get_sequence_number(&es).await;
                    #[cfg(not(feature = "arkime"))]
                    let id = get_sequence_number();

                    FILE_ID.store(id as u32, Ordering::SeqCst);
                }

                let info = match self.receiver.try_recv() {
                    Ok(info) => info,
                    Err(err) => match err {
                        crossbeam_channel::TryRecvError::Disconnected => break,
                        _ => continue,
                    },
                };

                if info.closing {
                    #[cfg(feature = "arkime")]
                    let id = get_sequence_number(&es).await;
                    #[cfg(not(feature = "arkime"))]
                    let id = get_sequence_number();

                    FILE_ID.store(id as u32, Ordering::SeqCst);
                }

                match writer.write(info.buf.as_slice(), &info) {
                    Ok(_) => {}
                    Err(e) => {}
                };
            }
        });

        println!("alphonse-writer thread exit");
        Ok(())
    }
}

#[cfg(not(feature = "arkime"))]
fn get_sequence_number() -> u64 {
    (FILE_ID.load(Ordering::Relaxed) + 1) as u64
}

#[cfg(feature = "arkime")]
async fn get_sequence_number(es: &Elasticsearch) -> u64 {
    let resp = es
        .send::<&str, String>(
            Method::Post,
            format!("sequence/_doc/{}", "test").as_str(),
            HeaderMap::default(),
            None,
            Some("{}"),
            None,
        )
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(_) => todo!("Handle request failed"),
    };
    match resp.status_code().as_u16() {
        200 => {
            let text = resp.text().await.unwrap();
            let a: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
            let version = a.get("_version").unwrap().as_u64().unwrap();
            version
        }
        code => {
            println!("code: {}", code);
            println!("text: {}", resp.text().await.unwrap());
            todo!("Handle status code is not 200")
        }
    }
}
