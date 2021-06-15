#[macro_use]
extern crate clap;
#[macro_use]
extern crate strum;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::bounded;

use alphonse_api as api;
use api::classifiers;

mod commands;
mod config;
mod plugins;
mod stats;
mod threadings;

use threadings::SessionTable;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let root_cmd = commands::new_root_command();
    let cfg = config::parse_args(root_cmd)?;

    signal_hook::flag::register(signal_hook::consts::SIGTERM, cfg.exit.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, cfg.exit.clone())?;

    let cfg = Arc::new(cfg);

    let plugins = plugins::load_plugins(&cfg)?;
    let mut warehouse = plugins::PluginWarehouse::default();
    plugins::init_plugins(&plugins, &mut warehouse, &cfg)?;

    let mut classifier_manager = classifiers::ClassifierManager::new();
    for processor in &mut warehouse.pkt_processors {
        processor.register_classify_rules(&mut classifier_manager)?;
    }

    classifier_manager.prepare()?;
    let classifier_manager = Arc::new(classifier_manager);

    let mut handles = vec![];
    let mut ses_senders = vec![];
    let mut ses_receivers = vec![];
    for _ in 0..warehouse.output_plugins.len() {
        let (sender, receiver) = bounded(cfg.pkt_channel_size as usize);
        ses_senders.push(sender);
        ses_receivers.push(receiver);
    }

    // initialize pkt threads and timeout threads
    let mut pkt_senders = vec![];
    let mut pkt_receivers = vec![];
    let mut pkt_threads = vec![];
    let mut timeout_threads = vec![];
    let mut session_tables = vec![];

    for i in 0..cfg.pkt_threads {
        let (sender, receiver) = bounded(cfg.pkt_channel_size as usize);
        let session_table: Arc<SessionTable> = Arc::new(
            dashmap::DashMap::with_capacity_and_hasher(1000000, fnv::FnvBuildHasher::default()),
        );
        let thread = threadings::PktThread::new(
            i,
            cfg.exit.clone(),
            classifier_manager.clone(),
            receiver.clone(),
            session_table.clone(),
        );
        pkt_senders.push(sender);
        pkt_receivers.push(receiver);
        pkt_threads.push(thread);

        let thread = threadings::TimeoutThread::new(
            i,
            cfg.exit.clone(),
            ses_senders.clone(),
            session_table.clone(),
        );
        timeout_threads.push(thread);

        session_tables.push(session_table);
    }

    warehouse.start_output_plugins(&cfg, &ses_receivers)?;

    // start all session timeout threads
    for thread in timeout_threads {
        let cfg = cfg.clone();
        let handle = tokio::task::spawn_blocking(move || thread.main_loop(cfg));
        handles.push(handle);
    }

    // start all pkt threads
    for thread in pkt_threads {
        let cfg = cfg.clone();
        let processors = Box::new(
            warehouse
                .pkt_processors
                .iter()
                .map(|p| p.clone_processor())
                .collect(),
        );
        let handle = tokio::task::spawn_blocking(move || thread.main_loop(cfg, processors));
        handles.push(handle);
    }

    warehouse.start_rx(&cfg, &pkt_senders)?;

    drop(pkt_senders);
    drop(pkt_receivers);
    drop(ses_senders);
    drop(ses_receivers);

    for handle in handles {
        match handle.await {
            Ok(r) => match r {
                Ok(_) => {}
                Err(e) => {
                    cfg.exit.store(true, Ordering::SeqCst);
                    eprintln!("{}", e);
                }
            },
            Err(e) => {
                cfg.exit.store(true, Ordering::SeqCst);
                eprintln!("{}", e);
            }
        };
    }

    plugins::cleanup_plugins(&mut warehouse)?;

    Ok(())
}
