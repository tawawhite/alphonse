use std::sync::atomic::Ordering;

use anyhow::{anyhow, Result};
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
            .build()?;

        println!("alphonse-writer thread started");

        rt.block_on(async {
            match self.main_loop(cfg.clone()).await {
                Ok(_) => {}
                Err(e) => eprintln!("{}", e),
            };
        });
        cfg.exit.store(true, Ordering::SeqCst);

        println!("alphonse-writer thread exit");
        Ok(())
    }

    async fn main_loop(&mut self, cfg: Config) -> Result<()> {
        let mut writer = SimpleWriter::default();
        let es = Elasticsearch::new(Transport::single_node(cfg.es_host.as_str())?);
        loop {
            if FILE_ID.load(Ordering::Relaxed) == 0 {
                #[cfg(feature = "arkime")]
                let id = get_sequence_number(&es).await?;
                #[cfg(not(feature = "arkime"))]
                let id = get_sequence_number();

                FILE_ID.store(id as u32, Ordering::SeqCst);
            }

            let info = match self.receiver.try_recv() {
                Ok(info) => info,
                Err(err) => match err {
                    crossbeam_channel::TryRecvError::Disconnected => return Ok(()),
                    _ => continue,
                },
            };

            if info.closing {
                #[cfg(feature = "arkime")]
                let id = get_sequence_number(&es).await?;
                #[cfg(not(feature = "arkime"))]
                let id = get_sequence_number();

                FILE_ID.store(id as u32, Ordering::SeqCst);
            }

            writer.write(info.buf.as_slice(), &info)?;
        }
    }
}

#[cfg(not(feature = "arkime"))]
fn get_sequence_number() -> u64 {
    (FILE_ID.load(Ordering::Relaxed) + 1) as u64
}

#[cfg(feature = "arkime")]
async fn get_sequence_number(es: &Elasticsearch) -> Result<u64> {
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
        Err(e) => return Err(anyhow!("{}", e)),
    };

    match resp.status_code().as_u16() {
        code if code >= 200 && code < 300 => {
            let text = resp.text().await.unwrap();
            let a: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
            let version = a.get("_version").unwrap().as_u64().unwrap();
            Ok(version)
        }
        code => {
            println!("code: {}", code);
            println!("text: {}", resp.text().await.unwrap());
            Err(anyhow!("Handle status code is {}", code))
        }
    }
}
