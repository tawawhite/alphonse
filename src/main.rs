#[macro_use]
extern crate clap;
extern crate alphonse_api;
extern crate crossbeam_channel;
extern crate hyperscan;
extern crate libc;
extern crate path_absolutize;
extern crate serde_json;
extern crate signal_hook;
extern crate twox_hash;
extern crate yaml_rust;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

use anyhow::Result;
use crossbeam_channel::unbounded;

use alphonse_api as api;
use api::{packet, session};

mod capture;
mod commands;
mod config;
mod protocol;
mod threadings;

fn main() -> Result<()> {
    let root_cmd = commands::new_root_command();
    let cfg = config::parse_args(root_cmd)?;
    let exit = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::SIGTERM, Arc::clone(&exit))?;
    signal_hook::flag::register(signal_hook::SIGINT, Arc::clone(&exit))?;

    let cfg = Arc::new(cfg);
    let mut handles = vec![];

    // initialize session threads
    let mut ses_threads = Vec::new();
    let mut pkt_senders = Vec::new();

    let mut classifier = protocol::Classifier::new();
    classifier.prepare();
    let classifier = Arc::new(classifier);

    for i in 0..cfg.ses_threads {
        let (sender, receiver) = unbounded();
        pkt_senders.push(sender);
        let thread = threadings::SessionThread::new(i, exit.clone(), receiver, classifier.clone());
        ses_threads.push(thread);
    }

    // initialize rx threads
    let mut rx_threads = Vec::new();
    for i in 0..cfg.rx_threads {
        let mut senders = Vec::new();
        for sender in &pkt_senders {
            senders.push(sender.clone());
        }
        let thread = threadings::RxThread::new(i, packet::link::ETHERNET, senders, exit.clone());
        rx_threads.push(thread);
        pkt_senders.clear(); // release all original senders
    }

    // start all session threads
    for mut thread in ses_threads {
        let cfg = cfg.clone();
        handles.push(thread::spawn(move || thread.spawn(cfg)));
    }

    // start all rx threads
    for mut thread in rx_threads {
        let cfg = cfg.clone();
        handles.push(thread::spawn(move || thread.spawn(cfg)));
    }

    for handle in handles {
        match handle.join() {
            Ok(_) => {}
            Err(e) => println!("{:?}", e),
        };
    }

    Ok(())
}
