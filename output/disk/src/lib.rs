use std::sync::{Arc, RwLock};
use std::thread::{sleep, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, Result};
use crossbeam_channel::Receiver;

use alphonse_api as api;
use api::config::Config;
use api::plugins::output::OutputPlugin;
use api::plugins::{Plugin, PluginType};
use api::session::Session;

mod writer;

use writer::{OutputPath, Writer};

#[derive(Clone, Default)]
struct Output {
    handles: Arc<RwLock<Vec<JoinHandle<Result<()>>>>>,
}

impl Plugin for Output {
    fn plugin_type(&self) -> PluginType {
        PluginType::RxDriver
    }

    fn name(&self) -> &str {
        "output-disk"
    }

    fn cleanup(&self) -> Result<()> {
        let mut handles = match self.handles.write() {
            Ok(h) => h,
            Err(e) => return Err(anyhow!("{}", e)),
        };

        while handles.len() > 0 {
            let hdl = handles.pop();
            match hdl {
                None => continue,
                Some(hdl) => match hdl.join() {
                    Ok(_) => {}
                    Err(e) => eprintln!("{:?}", e),
                },
            }
        }

        Ok(())
    }
}

impl OutputPlugin for Output {
    fn clone_output_plugin(&self) -> Box<dyn OutputPlugin> {
        Box::new(self.clone())
    }

    fn start(&self, cfg: Arc<Config>, receiver: &Receiver<Arc<Box<Session>>>) -> Result<()> {
        let mut handles = vec![];
        let dirs = cfg.get_str_arr("output.disk.dirs");
        if dirs.is_empty() {
            return Err(anyhow!(
                "No output directory is specified for disk output plugin"
            ));
        }

        for dir in dirs {
            let cfg = cfg.clone();
            let mut thread = OutputThread::new(receiver.clone());
            let builder = std::thread::Builder::new().name(thread.name());
            let handle = builder.spawn(move || thread.spawn(cfg, dir)).unwrap();
            handles.push(handle);
        }

        match self.handles.write() {
            Ok(mut h) => {
                *h.as_mut() = handles;
            }
            Err(e) => return Err(anyhow!("{}", e)),
        };
        Ok(())
    }
}

struct OutputThread {
    receiver: Receiver<Arc<Box<Session>>>,
}

impl OutputThread {
    pub fn new(receiver: Receiver<Arc<Box<Session>>>) -> Self {
        OutputThread { receiver }
    }

    pub fn name(&self) -> String {
        format!("alphonse-output-disk")
    }

    pub fn spawn(&mut self, cfg: Arc<Config>, dir: String) -> Result<()> {
        let mut writer = Writer::default();
        writer.output_dir = OutputPath::from(&dir);
        writer.max_file_size = 1000000;
        std::fs::create_dir_all(&writer.output_dir.tmp_path)?;

        println!("{} started", self.name());

        loop {
            let ses = match self.receiver.try_recv() {
                Ok(ses) => ses,
                Err(err) => match err {
                    crossbeam_channel::TryRecvError::Disconnected => {
                        break;
                    }
                    _ => {
                        sleep(Duration::from_micros(500000));
                        continue;
                    }
                },
            };

            if cfg.dry_run {
                continue;
            }

            writer.write(&ses)?;
        }

        println!("{} exit", self.name());

        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn al_new_output_plugin() -> Box<Box<dyn OutputPlugin>> {
    Box::new(Box::new(Output::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::OutputPlugin
}
