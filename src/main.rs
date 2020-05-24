#[macro_use]
extern crate clap;
extern crate crossbeam_channel;

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
    let cfg = Arc::new(config::parse_args(root_cmd)?);

    let mut senders = Vec::new();
    let (sender, receiver) = unbounded();
    senders.push(sender);
    let mut rx_thread = threadings::RxThread::new(0, packet::link::ETHERNET, senders);
    let mut session_thread = threadings::SessionThread::new(0, Box::from(receiver.clone()));

    let mut handles = vec![];

    handles.push(thread::spawn(move || session_thread.spawn()));

    handles.push(thread::spawn(move || match rx_thread.spawn(cfg) {
        Ok(_) => {}
        Err(e) => println!("{}", e),
    }));

    for handle in handles {
        match handle.join() {
            Ok(_) => {}
            Err(e) => println!("{:?}", e),
        };
    }

    Ok(())
}
