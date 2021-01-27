use std::convert::TryFrom;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use chrono::{Datelike, Timelike};
use crossbeam_channel::Receiver;
use elasticsearch::{http::transport::Transport, Elasticsearch};
use tokio::runtime::Runtime;

use alphonse_api as api;
use api::session::Session;
use api::utils::timeval::{precision::Millisecond, TimeVal};

use crate::config::Config;

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
fn to_index_suffix(rotate: Rotate, ts: &TimeVal<Millisecond>) -> String {
    let stime = std::time::UNIX_EPOCH
        + std::time::Duration::from_nanos(ts.tv_sec as u64 * 1000000000 + ts.tv_usec as u64 * 1000);
    let datetime = chrono::DateTime::<chrono::Utc>::from(stime);
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

pub struct Thread {
    exit: Arc<AtomicBool>,
    receiver: Receiver<Arc<Session>>,
}

impl Thread {
    pub fn new(exit: Arc<AtomicBool>, receiver: Receiver<Arc<Session>>) -> Self {
        Thread { exit, receiver }
    }

    pub fn name(&self) -> String {
        format!("alphonse-output")
    }

    pub fn spawn(&mut self, cfg: Arc<Config>) -> Result<()> {
        let mut rt = tokio::runtime::Builder::new()
            .core_threads(4)
            .thread_name("alphonse-output-tokio")
            .threaded_scheduler()
            .enable_all()
            .build()
            .unwrap();
        println!("{} started", self.name());

        let mut sessions = vec![];

        rt.block_on(async {
            while !self.exit.load(Ordering::Relaxed) {
                let ses = match self.receiver.try_recv() {
                    Ok(ses) => ses,
                    Err(err) => match err {
                        crossbeam_channel::TryRecvError::Empty => continue,
                        crossbeam_channel::TryRecvError::Disconnected => break,
                    },
                };
                sessions.push(ses);
                if sessions.len() == 100 {
                    let sessions_cloned = sessions.clone();
                    let cfg = cfg.clone();
                    let a = tokio::spawn(async {
                        Thread::save_sessions(cfg, sessions_cloned).await.unwrap();
                    });
                    a.await.unwrap();
                    sessions.clear();
                }
            }
        });

        println!("{} exit", self.name());

        Ok(())
    }

    async fn save_sessions(cfg: Arc<Config>, sessions: Vec<Arc<Session>>) -> Result<()> {
        let host = cfg.get_str("elasticsearch", "http://localhost:9200");
        let es = Elasticsearch::new(Transport::single_node(host.as_str())?);
        let c = es.cat();
        let resp = c.health().send().await?;
        let resp = resp.text().await.unwrap();
        println!("resp: {}", resp);
        println!("sessions count: {}", sessions.len());
        for ses in &sessions {}

        Ok(())
    }
}
