#[macro_use]
extern crate clap;
extern crate alphonse_api;
extern crate crossbeam_channel;
extern crate hyperscan;
extern crate libc;
extern crate libloading;
extern crate path_absolutize;
#[cfg(all(target_os = "linux", feature = "dpdk"))]
extern crate rte;
extern crate serde_json;
extern crate signal_hook;
extern crate yaml_rust;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

use anyhow::Result;
use crossbeam_channel::bounded;

use alphonse_api as api;
use api::{classifiers, parsers::NewProtocolParserFunc, parsers::ParserID, session};

mod capture;
mod commands;
mod config;
mod packet;
mod stats;
mod threadings;

use capture::Capture;

fn main() -> Result<()> {
    let root_cmd = commands::new_root_command();
    let cfg = config::parse_args(root_cmd)?;
    let exit = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&exit))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&exit))?;

    let cfg = Arc::new(cfg);

    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    {
        capture::dpdk::Device::init(&cfg)?;
    }

    let mut handles = vec![];

    // keep share library 'alive' so that the vtable of trait object pointer is not pointing to an invalid position
    let mut parser_libraries = HashMap::new();
    let mut protocol_parsers = Vec::new();

    for p in &cfg.as_ref().parsers {
        parser_libraries.insert(p.clone(), libloading::Library::new(p)?);
        let lib = parser_libraries.get(p).unwrap();

        unsafe {
            match lib.get::<NewProtocolParserFunc>(b"al_new_protocol_parser\0") {
                Ok(func) => {
                    let mut parser = func();
                    parser.set_id(protocol_parsers.len() as ParserID);
                    let parser = api::parsers::ProtocolParser::new(parser);
                    protocol_parsers.push(parser);
                }
                Err(e) => {
                    eprintln!("{:?}", e);
                }
            }
        }
    }

    let mut classifier_manager = classifiers::ClassifierManager::new();
    for parser in &mut protocol_parsers {
        parser.register_classify_rules(&mut classifier_manager)?;
        parser.init()?;
    }

    classifier_manager.prepare()?;
    let classifier_manager = Arc::new(classifier_manager);

    // initialize session threads
    let mut ses_threads = Vec::new();
    let (sender, receiver) = bounded(cfg.pkt_channel_size as usize);

    for i in 0..cfg.ses_threads {
        let thread = threadings::SessionThread::new(i, exit.clone(), receiver.clone());
        ses_threads.push(thread);
    }

    // initialize rx threads
    let mut rx_threads = Vec::new();
    for i in 0..cfg.rx_threads {
        let thread = threadings::RxThread::new(
            i,
            packet::link::ETHERNET,
            sender.clone(),
            classifier_manager.clone(),
            exit.clone(),
        );
        rx_threads.push(thread);
    }

    drop(sender);
    drop(receiver);

    // start all session threads
    for mut thread in ses_threads {
        let cfg = cfg.clone();
        let builder = thread::Builder::new().name(format!("alphonse-ses{}", thread.id()));
        let handle = builder.spawn(move || thread.spawn(cfg))?;
        handles.push(handle);
    }

    // start all rx threads
    for mut thread in rx_threads {
        let cfg = cfg.clone();
        let mut parsers: Box<Vec<Box<dyn api::parsers::ProtocolParserTrait>>> =
            Box::new(Vec::new());
        for parser in &protocol_parsers {
            parsers.push(parser.box_clone());
        }
        let builder = thread::Builder::new().name(format!("alphonse-rx{}", thread.id()));
        let handle = builder.spawn(move || thread.spawn(cfg, parsers))?;
        handles.push(handle);
    }

    for handle in handles {
        match handle.join() {
            Ok(_) => {}
            Err(e) => println!("{:?}", e),
        };
    }

    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    {
        capture::dpdk::Device::cleanup()?;
    }

    Ok(())
}
