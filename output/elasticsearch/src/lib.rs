use std::convert::TryFrom;
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use chrono::{Datelike, Timelike};
use crossbeam_channel::Receiver;
use elasticsearch::{http::transport::Transport, Elasticsearch};

use alphonse_api as api;
use api::config::Config;
use api::plugins::output::OutputPlugin;
use api::plugins::{Plugin, PluginType};
use api::session::Session;
use api::utils::timeval::{precision::Millisecond, TimeVal};

enum Rotate {
    Hourly(u32),
    Daily,
    Weekly,
    Monthly,
}

impl TryFrom<&str> for Rotate {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let r = match value {
            "daily" => Rotate::Daily,
            "week" => Rotate::Weekly,
            "monthly" => Rotate::Monthly,
            "hourly" => Rotate::Hourly(1),
            "hourly2" => Rotate::Hourly(2),
            "hourly3" => Rotate::Hourly(3),
            "hourly4" => Rotate::Hourly(4),
            "hourly6" => Rotate::Hourly(6),
            "hourly8" => Rotate::Hourly(8),
            "hourly12" => Rotate::Hourly(12),
            _ => return Err(anyhow!("Unknown Rotate: {}", value)),
        };
        Ok(r)
    }
}

/// Convert timestamp to index suffix
///
/// # Arguments
///
/// * `rotate` - index rotate way
///
/// * `ts` - UTC timestamp
fn to_index_suffix(rotate: Rotate, ts: &TimeVal<Millisecond>) -> String {
    let stime = std::time::UNIX_EPOCH
        + std::time::Duration::from_nanos(ts.tv_sec as u64 * 1000000000 + ts.tv_usec as u64 * 1000);
    let datetime = chrono::DateTime::<chrono::Local>::from(stime);
    match rotate {
        Rotate::Daily => datetime.format("%y%m%d").to_string(),
        Rotate::Weekly => {
            format!(
                "{:2}{:2}{:2}",
                datetime.year() % 100,
                datetime.month(),
                datetime.day() / 7,
            )
        }
        Rotate::Monthly => datetime.format("%y%m").to_string(),
        Rotate::Hourly(hours) => {
            format!(
                "{:2}{:2}{:2}{}",
                datetime.year() % 100,
                datetime.month(),
                datetime.day(),
                (datetime.time().hour() / hours) * hours,
            )
        }
    }
}

#[derive(Clone, Default)]
struct Output {
    handles: Arc<RwLock<Vec<JoinHandle<Result<()>>>>>,
}

impl Plugin for Output {
    fn plugin_type(&self) -> PluginType {
        PluginType::RxDriver
    }

    fn name(&self) -> &str {
        "output-es"
    }

    fn cleanup(&self) -> Result<()> {
        let mut handles = match self.handles.write() {
            Ok(h) => h,
            Err(e) => return Err(anyhow!("{}", e)),
        };

        while handles.len() > 0 {
            let hdl = handles.pop();
            match hdl {
                None => continue,
                Some(hdl) => match hdl.join() {
                    Ok(_) => {}
                    Err(e) => eprintln!("{:?}", e),
                },
            }
        }

        Ok(())
    }
}

impl OutputPlugin for Output {
    fn clone_output_plugin(&self) -> Box<dyn OutputPlugin> {
        Box::new(self.clone())
    }

    fn start(&self, cfg: Arc<Config>, receiver: &Receiver<Arc<Box<Session>>>) -> Result<()> {
        let mut handles = vec![];
        let cfg = cfg.clone();
        let mut thread = OutputThread::new(receiver.clone());
        let builder = std::thread::Builder::new().name(thread.name());
        let handle = builder.spawn(move || thread.spawn(cfg)).unwrap();
        handles.push(handle);

        match self.handles.write() {
            Ok(mut h) => {
                *h.as_mut() = handles;
            }
            Err(e) => return Err(anyhow!("{}", e)),
        };
        Ok(())
    }
}

struct OutputThread {
    receiver: Receiver<Arc<Box<Session>>>,
}

impl OutputThread {
    pub fn new(receiver: Receiver<Arc<Box<Session>>>) -> Self {
        OutputThread { receiver }
    }

    pub fn spawn(&mut self, cfg: Arc<Config>) -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("alphonse-output-tokio")
            .enable_all()
            .build()
            .unwrap();
        let host = cfg.get_str("elasticsearch", "http://localhost:9200");
        let es = Arc::new(Elasticsearch::new(Transport::single_node(host.as_str())?));

        println!("{} started", self.name());

        rt.block_on(async {
            match self.main_loop(&cfg, &es).await {
                Ok(_) => {}
                Err(e) => eprintln!("{}", e),
            }
        });

        println!("{} exit", self.name());

        Ok(())
    }

    async fn main_loop(&mut self, cfg: &Arc<Config>, es: &Arc<Elasticsearch>) -> Result<()> {
        let mut sessions = vec![];
        loop {
            let ses = match self.receiver.try_recv() {
                Ok(ses) => ses,
                Err(err) => match err {
                    crossbeam_channel::TryRecvError::Disconnected => break,
                    _ => continue,
                },
            };

            if cfg.dry_run {
                continue;
            }

            sessions.push(ses);
            if sessions.len() == 5 {
                let sessions_cloned = Box::new(sessions.clone());
                let cfg = cfg.clone();
                let es = es.clone();
                tokio::spawn(async {
                    match Self::save_sessions(cfg, es, sessions_cloned).await {
                        Ok(_) => {}
                        Err(e) => eprintln!("{}", e),
                    };
                })
                .await?;
                sessions.clear();
            }
        }

        if sessions.len() == 0 {
            return Ok(());
        }

        let sessions_cloned = Box::new(sessions.clone());
        let cfg = cfg.clone();
        let es = es.clone();
        tokio::spawn(async {
            match Self::save_sessions(cfg, es, sessions_cloned).await {
                Ok(_) => {}
                Err(e) => eprintln!("{}", e),
            };
        })
        .await?;

        Ok(())
    }

    async fn save_sessions(
        _cfg: Arc<Config>,
        es: Arc<Elasticsearch>,
        sessions: Box<Vec<Arc<Box<Session>>>>,
    ) -> Result<()> {
        let body = sessions
            .iter()
            .map(|ses| {
                let index = format!(
                    "sessions2-{}",
                    to_index_suffix(Rotate::Daily, &ses.start_time)
                );
                elasticsearch::BulkOperation::from(
                    elasticsearch::BulkOperation::index(ses.as_ref()).index(index),
                )
            })
            .collect();
        let resp = es
            .bulk(elasticsearch::BulkParts::None)
            .body(body)
            .send()
            .await?;
        let code = resp.status_code();
        match code.as_u16() {
            code if code >= 200 && code < 300 => {}
            c => {
                println!("status code: {}", c);
                println!("response message: {}", resp.text().await.unwrap());
            }
        };

        Ok(())
    }

    pub fn name(&self) -> String {
        format!("alphonse-output-es")
    }
}

#[no_mangle]
pub extern "C" fn al_new_output_plugin() -> Box<Box<dyn OutputPlugin>> {
    Box::new(Box::new(Output::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::OutputPlugin
}
