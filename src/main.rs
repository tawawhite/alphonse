#[macro_use]
extern crate clap;
extern crate crossbeam_channel;
extern crate libc;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

use crossbeam_channel::unbounded;

mod capture;
mod commands;
mod config;
#[cfg(all(target_os = "linux", feature = "dpdk"))]
mod dpdk;
mod error;
mod packet;
mod session;
mod threadings;

#[cfg(all(target_os = "linux", feature = "dpdk"))]
fn main() -> Result<(), error::Error> {
    let root_cmd = commands::new_root_command();

    let mut config = config::parse_args(root_cmd)?;

    match dpdk::eal_init(&mut config.dpdk_eal_args) {
        Err(e) => {
            dpdk::eal_cleanup();
            return Err(e);
        }
        Ok(_) => {}
    };

    let parser_result = protocols::Parser::from_pcap_file(&config.pcap_file);
    let mut parser;
    match parser_result {
        Err(e) => {
            dpdk::eal_cleanup();
            return Err(e);
        }
        Ok(p) => parser = p,
    }

    let cap_result = capture::Capture::from_pcap_file(&config.pcap_file);
    let mut cap;
    match cap_result {
        Err(e) => {
            dpdk::eal_cleanup();
            return Err(e);
        }
        Ok(c) => cap = c,
    }

    while let Ok(mut pkt) = cap.next() {
        let result = parser.parse_pkt(&mut pkt);
        match result {
            Ok(_) => {}
            Err(e) => println!("{:?}", e),
        }
    }

    dpdk::eal_cleanup();

    Ok(())
}

#[cfg(not(feature = "dpdk"))]
fn main() -> Result<(), error::Error> {
    let root_cmd = commands::new_root_command();
    let cfg = config::parse_args(root_cmd)?;
    let exit = Arc::new(AtomicBool::new(false));

    let cfg = Arc::new(cfg);
    let mut handles = vec![];

    // initialize session threads
    let mut ses_threads = Vec::new();
    let mut pkt_senders = Vec::new();
    for i in 0..cfg.ses_threads {
        let (sender, receiver) = unbounded();
        pkt_senders.push(sender);
        let thread = threadings::SessionThread::new(i, exit.clone(), receiver);
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
    }

    // start all session threads
    for mut thread in ses_threads {
        handles.push(thread::spawn(move || thread.spawn()));
    }

    // start all rx threads
    for mut thread in rx_threads {
        let cfg = cfg.clone();
        handles.push(thread::spawn(move || match thread.spawn(cfg) {
            Ok(_) => {}
            Err(e) => println!("{}", e),
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(_) => {}
            Err(e) => println!("{:?}", e),
        };
    }

    Ok(())
}
