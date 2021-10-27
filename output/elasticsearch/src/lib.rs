use std::convert::TryFrom;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use chrono::{Datelike, Timelike};
use crossbeam_channel::Receiver;
use elasticsearch::{http::transport::Transport, BulkOperation, BulkParts, Elasticsearch};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use alphonse_api as api;
use alphonse_arkime as arkime;
use alphonse_utils as utils;
use api::config::Config;
use api::plugins::output::OutputPlugin;
use api::plugins::{Plugin, PluginType};
use api::session::Session;
use api::session::TimeVal;
use utils::elasticsearch::handle_bulk_index_resp;
use utils::serde::get_ser_json_size;

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
fn to_index_suffix(rotate: Rotate, ts: &TimeVal) -> String {
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

#[derive(Default)]
struct Output {
    handles: Vec<JoinHandle<Result<()>>>,
    rt: Option<Arc<tokio::runtime::Runtime>>,
}

impl Clone for Output {
    fn clone(&self) -> Self {
        Self {
            handles: vec![],
            rt: self.rt.clone(),
        }
    }
}

impl Plugin for Output {
    fn plugin_type(&self) -> PluginType {
        PluginType::RxDriver
    }

    fn name(&self) -> &str {
        "output-es"
    }

    fn cleanup(&mut self) -> Result<()> {
        let mut handles = vec![];
        while let Some(hdl) = self.handles.pop() {
            handles.push(hdl);
        }

        match &self.rt {
            None => unreachable!("this should never happen"),
            Some(rt) => rt.block_on(async {
                futures::future::join_all(handles).await;
            }),
        }

        Ok(())
    }
}

impl OutputPlugin for Output {
    fn clone_output_plugin(&self) -> Box<dyn OutputPlugin> {
        Box::new(self.clone())
    }

    fn start(&mut self, cfg: Arc<Config>, receiver: &Receiver<Arc<Box<Session>>>) -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("alphonse-output-tokio")
            .enable_all()
            .build()?;

        let mut thread = OutputThread::new(receiver.clone());
        let hdl = rt.spawn_blocking(move || thread.main_loop(cfg));
        self.handles.push(hdl);

        self.rt = Some(Arc::new(rt));
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

    fn main_loop(&mut self, cfg: Arc<Config>) -> Result<()> {
        let max_bulk_size =
            cfg.get_integer("output.elasticsearch.maxBulkSize", 1000, 1000, 1000000000) as usize;
        let mut bulk_size = 0;
        let mut sessions = vec![];
        let host = cfg.get_str("elasticsearch", "http://localhost:9200");
        let es = Arc::new(Elasticsearch::new(Transport::single_node(host.as_str())?));
        let mut last_send_time = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        Handle::current().block_on(async {
            let fpath = cfg.get_str(&"arkime.fields", "./etc/fields.yml");
            let fields = arkime::fields::get_fields_from_yaml(&fpath)?;
            let mut arkime_cfg = arkime::Config::default();
            arkime_cfg.hostname = cfg.hostname.clone();
            arkime_cfg.node = cfg.node.clone();
            arkime_cfg.prefix = cfg.get_str(&"arkime.prefix", "");
            arkime_cfg.elasticsearch = host;
            arkime::fields::add_fields(&es, &arkime_cfg, fields).await
        })?;

        println!("{} started", self.name());

        loop {
            let ses = match self.receiver.try_recv() {
                Ok(ses) => ses,
                Err(err) => match err {
                    crossbeam_channel::TryRecvError::Disconnected => break,
                    _ => {
                        let now = SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs();
                        if now - last_send_time >= 60 && !cfg.dry_run && sessions.len() > 0 {
                            let cfg = cfg.clone();
                            let es = es.clone();
                            let sess = sessions.clone();
                            save_sessions_sync(cfg, es, sess, &mut sessions, &mut bulk_size)?;
                            last_send_time = now;
                        } else {
                            std::thread::sleep(Duration::from_micros(100000));
                        }
                        continue;
                    }
                },
            };

            if cfg.dry_run {
                continue;
            }

            let size = get_ser_json_size(&ses)?;
            if bulk_size != 0 && bulk_size + size >= max_bulk_size {
                let cfg = cfg.clone();
                let es = es.clone();
                let sess = sessions.clone();
                save_sessions_sync(cfg, es, sess, &mut sessions, &mut bulk_size)?;
                last_send_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
            }

            sessions.push(ses);
            bulk_size += size;
        }

        if sessions.len() == 0 {
            return Ok(());
        }

        let cfg = cfg.clone();
        let es = es.clone();
        Handle::current().spawn(async {
            match save_sessions(cfg, es, sessions).await {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("{}", e)),
            }
        });

        println!("{} exit", self.name());

        Ok(())
    }

    pub fn name(&self) -> String {
        format!("alphonse-output-es")
    }
}

/// Sync wrapper function of save_sessions
fn save_sessions_sync(
    cfg: Arc<Config>,
    es: Arc<Elasticsearch>,
    sess: Vec<Arc<Box<Session>>>,
    sessions: &mut Vec<Arc<Box<Session>>>,
    bulk_size: &mut usize,
) -> Result<()> {
    Handle::current().spawn(async {
        match save_sessions(cfg, es, sess).await {
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow!("{}", e)),
        }
    });
    sessions.clear();
    *bulk_size = 0;
    Ok(())
}

async fn save_sessions(
    _cfg: Arc<Config>,
    es: Arc<Elasticsearch>,
    sessions: Vec<Arc<Box<Session>>>,
) -> Result<()> {
    let body = sessions
        .into_iter()
        .map(|ses| {
            let index = format!(
                "sessions2-{}",
                to_index_suffix(Rotate::Daily, &ses.start_time)
            );
            BulkOperation::from(BulkOperation::index(ses).index(index))
        })
        .collect();
    let resp = es.bulk(BulkParts::None).body(body).send().await?;
    handle_bulk_index_resp(resp).await
}

#[no_mangle]
pub extern "C" fn al_new_output_plugin() -> Box<Box<dyn OutputPlugin>> {
    Box::new(Box::new(Output::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::OutputPlugin
}
