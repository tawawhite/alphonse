#[macro_use]
extern crate clap;
extern crate alphonse_api;
extern crate crossbeam_channel;
extern crate hyperscan;
extern crate libc;
extern crate libloading;
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
use api::{
    classifiers, parsers::NewProtocolParserBoxFunc, parsers::NewProtocolParserBoxesFunc, session,
};

mod capture;
mod commands;
mod config;
mod packet;
mod threadings;

fn main() -> Result<()> {
    let root_cmd = commands::new_root_command();
    let cfg = config::parse_args(root_cmd)?;
    let exit = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::SIGTERM, Arc::clone(&exit))?;
    signal_hook::flag::register(signal_hook::SIGINT, Arc::clone(&exit))?;

    let cfg = Arc::new(cfg);
    let mut handles = vec![];

    let mut protocol_parsers = Vec::new();

    let mut id = 0;
    for p in &cfg.as_ref().parsers {
        let lib = libloading::Library::new(p)?;

        let new_protocol_parser: libloading::Symbol<NewProtocolParserBoxFunc>;
        unsafe {
            match lib.get(b"new_protocol_parser\0") {
                Ok(func) => {
                    new_protocol_parser = func;
                    let mut parser = new_protocol_parser()?;
                    parser.set_id(id);
                    id += 1;
                    protocol_parsers.push(parser);
                }
                Err(e) => {
                    eprintln!("{:?}", e);
                }
            }
        }

        let new_protocol_parsers: libloading::Symbol<NewProtocolParserBoxesFunc>;
        unsafe {
            match lib.get(b"new_protocol_parsers\0") {
                Ok(func) => new_protocol_parsers = func,
                Err(e) => continue,
            };
        }
        let mut parsers = new_protocol_parsers()?;
        for parser in &mut parsers {
            parser.set_id(id);
            id += 1;
            protocol_parsers.push(parser.box_clone());
        }
    }

    let mut classifier_manager = classifiers::ClassifierManager::new();
    for parser in &mut protocol_parsers {
        parser.register_classifier(&mut classifier_manager)?;
        parser.init()?;
    }

    classifier_manager.prepare()?;
    let classifier_manager = Arc::new(classifier_manager);

    // initialize session threads
    let mut ses_threads = Vec::new();
    let mut pkt_senders = Vec::new();

    for i in 0..cfg.ses_threads {
        let (sender, receiver) = unbounded();
        pkt_senders.push(sender);
        let thread =
            threadings::SessionThread::new(i, exit.clone(), receiver, classifier_manager.clone());
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
        let mut parsers: Box<Vec<Box<dyn api::parsers::ProtocolParser>>> = Box::new(Vec::new());
        for parser in &protocol_parsers {
            parsers.push(parser.box_clone());
        }
        handles.push(thread::spawn(move || thread.spawn(cfg, parsers)));
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
