#[macro_use]
extern crate clap;
#[macro_use]
extern crate strum;

use std::num::NonZeroUsize;
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

fn main() -> Result<()> {
    let root_cmd = commands::new_root_command();
    let cfg = config::parse_args(root_cmd)?;

    signal_hook::flag::register(signal_hook::consts::SIGTERM, cfg.exit.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, cfg.exit.clone())?;

    let cfg = Arc::new(cfg);

    let plugins = plugins::load_plugins(&cfg)?;
    let mut warehouse = plugins::PluginWarehouse::default();
    plugins::init_plugins(&plugins, &mut warehouse, &cfg)?;

    let mut classifier_manager = classifiers::ClassifierManager::new();
    for builder in &mut warehouse.pkt_processor_builders {
        let builder = match Arc::get_mut(builder) {
            None => unreachable!("this would never happens"),
            Some(b) => b,
        };
        builder.register_classify_rules(&mut classifier_manager)?;
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

    for i in 0..cfg.pkt_threads {
        let (sender, receiver) = bounded(cfg.pkt_channel_size as usize);
        let thread = threadings::PktThread::new(
            i,
            cfg.exit.clone(),
            classifier_manager.clone(),
            receiver.clone(),
            ses_senders.clone(),
            unsafe { NonZeroUsize::new_unchecked(1000000) },
        );
        pkt_senders.push(sender);
        pkt_receivers.push(receiver);
        pkt_threads.push(thread);
    }

    warehouse.start_output_plugins(&cfg, &ses_receivers)?;

    // start all pkt threads
    for mut thread in pkt_threads {
        let cfg = cfg.clone();
        let builders = warehouse.pkt_processor_builders.clone();
        let builder = std::thread::Builder::new().name(thread.name());
        let handle = builder.spawn(move || thread.spawn(cfg, builders))?;
        handles.push(handle);
    }

    warehouse.start_rx(&cfg, &pkt_senders)?;

    drop(pkt_senders);
    drop(pkt_receivers);
    drop(ses_senders);
    drop(ses_receivers);

    for handle in handles {
        match handle.join() {
            Ok(_) => {}
            Err(e) => {
                cfg.exit.store(true, Ordering::SeqCst);
                println!("{:?}", e)
            }
        };
    }

    plugins::cleanup_plugins(warehouse)?;

    Ok(())
}
