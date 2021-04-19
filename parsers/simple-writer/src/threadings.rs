use anyhow::Result;
use crossbeam_channel::Receiver;

use crate::{PacketInfo, SimpleWriter};

/// Pcaket writing thread
pub struct Thread {
    pub writer: SimpleWriter,
    pub receiver: Receiver<Box<PacketInfo>>,
}

impl Thread {
    pub fn spawn(&mut self) -> Result<()> {
        println!("alphonse-writer thread started");

        loop {
            let info = match self.receiver.try_recv() {
                Ok(info) => info,
                Err(err) => match err {
                    crossbeam_channel::TryRecvError::Disconnected => break,
                    _ => continue,
                },
            };

            match self.writer.write(info.buf.as_slice(), &info) {
                Ok(_) => {}
                Err(e) => eprintln!("{}", e),
            };
        }

        println!("alphonse-writer thread exit");
        Ok(())
    }
}
