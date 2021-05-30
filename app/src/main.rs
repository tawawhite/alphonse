#[macro_use]
extern crate clap;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::bounded;

use alphonse_api as api;
use api::classifiers;

mod commands;
mod config;
mod packet;
mod plugins;
mod stats;
mod threadings;

fn main() -> Result<()> {
    let root_cmd = commands::new_root_command();
    let cfg = config::parse_args(root_cmd)?;

    let session_table = Arc::new(dashmap::DashMap::with_capacity_and_hasher(
        1000000,
        fnv::FnvBuildHasher::default(),
    ));

    signal_hook::flag::register(signal_hook::consts::SIGTERM, cfg.exit.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, cfg.exit.clone())?;

    let cfg = Arc::new(cfg);

    let plugins = plugins::load_plugins(&cfg)?;
    let mut warehouse = plugins::PluginWarehouse::default();
    plugins::init_plugins(&plugins, &mut warehouse, &cfg)?;

    let mut classifier_manager = classifiers::ClassifierManager::new();
    for parser in &mut warehouse.pkt_processors {
        parser.register_classify_rules(&mut classifier_manager)?;
    }

    classifier_manager.prepare()?;
    let classifier_manager = Arc::new(classifier_manager);

    let mut handles = vec![];
    let (ses_sender, ses_receiver) = bounded(cfg.pkt_channel_size as usize);
    let mut output_thread = threadings::output::Thread::new(ses_receiver.clone());

    // initialize pkt threads
    let (pkt_sender, pkt_receiver) = bounded(cfg.pkt_channel_size as usize);
    let mut pkt_threads = Vec::new();
    warehouse.start_rx(&cfg, &pkt_sender)?;

    for i in 0..cfg.pkt_threads {
        let thread = threadings::PktThread::new(
            i,
            cfg.exit.clone(),
            classifier_manager.clone(),
            pkt_receiver.clone(),
        );
        pkt_threads.push(thread);
    }

    let timeout_thread = threadings::TimeoutThread::new(cfg.exit.clone(), ses_sender.clone());

    // start all output threads
    {
        let cfg = cfg.clone();
        let builder = std::thread::Builder::new().name(output_thread.name());
        let handle = builder.spawn(move || output_thread.spawn(cfg)).unwrap();
        handles.push(handle);
    }

    // start all pkt threads
    for thread in pkt_threads {
        let cfg = cfg.clone();
        let session_table = session_table.clone();
        let parsers = Box::new(
            warehouse
                .pkt_processors
                .iter()
                .map(|p| p.clone_processor())
                .collect(),
        );
        let builder = std::thread::Builder::new().name(thread.name());
        let handle = builder.spawn(move || thread.spawn(cfg, session_table, parsers))?;
        handles.push(handle);
    }

    // start session timeout thread
    {
        let cfg = cfg.clone();
        let builder = std::thread::Builder::new().name(timeout_thread.name());
        let handle = builder
            .spawn(move || timeout_thread.spawn(cfg, session_table.clone()))
            .unwrap();
        handles.push(handle);
    }

    drop(pkt_sender);
    drop(pkt_receiver);
    drop(ses_sender);
    drop(ses_receiver);

    for handle in handles {
        match handle.join() {
            Ok(_) => {}
            Err(e) => {
                cfg.exit.store(true, Ordering::SeqCst);
                println!("{:?}", e)
            }
        };
    }

    plugins::cleanup_plugins(&mut warehouse)?;

    Ok(())
}
