//! We need to figure out a better way to do this plugin thing, these codes are just HORRIBLE.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use dynamic_reload::{DynamicReload, Lib, PlatformName, Search, UpdateState};

use alphonse_api as api;
use api::config::Config;
use api::packet::Packet;
use api::plugins::{
    processor, processor::Processor, rx, rx::RxDriver, PluginType, PluginTypeFunc,
    PLUGIN_TYPE_FUNC_NAME,
};

#[derive(Default)]
pub struct Plugins {
    pub plugins: Vec<Arc<Lib>>,
}

impl Plugins {
    pub fn add_plugin(&mut self, plugin: &Arc<Lib>) {
        self.plugins.push(plugin.clone());
    }

    pub fn unload_plugins(&mut self, lib: &Arc<Lib>) {
        for i in (0..self.plugins.len()).rev() {
            if &self.plugins[i] == lib {
                self.plugins.swap_remove(i);
            }
        }
    }

    pub fn reload_plugin(&mut self, lib: &Arc<Lib>) {
        Self::add_plugin(self, lib);
    }

    // called when a lib needs to be reloaded.
    pub fn reload_callback(&mut self, state: UpdateState, lib: Option<&Arc<Lib>>) {
        match state {
            UpdateState::Before => Self::unload_plugins(self, lib.unwrap()),
            UpdateState::After => Self::reload_plugin(self, lib.unwrap()),
            UpdateState::ReloadFailed(_) => println!("Failed to reload"),
        }
    }
}

#[derive(Default)]
pub struct PluginWarehouse {
    pub rx_driver: Option<Box<dyn RxDriver>>,
    pub pkt_processors: Vec<Box<dyn Processor>>,
}

impl PluginWarehouse {
    pub fn start_rx(&self, cfg: &Arc<Config>, sender: &Sender<Box<dyn Packet>>) -> Result<()> {
        match &self.rx_driver {
            None => return Err(anyhow!("alphonse hasn't load any rx driver plugin")),
            Some(driver) => driver.start(cfg.clone(), sender.clone())?,
        }
        Ok(())
    }
}

pub fn load_plugins(cfg: &Config) -> Result<Plugins> {
    let plugin_dirs = cfg.get_str_arr("plugins.dirs");
    let plugin_dirs = if plugin_dirs.is_empty() {
        vec!["target/debug"]
    } else {
        plugin_dirs.iter().map(|x| x.as_str()).collect()
    };

    let load_tmp_dir = cfg.get_str("plugins.load.dir", "/tmp/alphonse/plugins");

    let mut reload_handler = DynamicReload::new(
        Some(plugin_dirs),
        Some(load_tmp_dir.as_str()),
        Search::Default,
    );

    let mut plugin_names = cfg.processors.clone();
    plugin_names.push(cfg.rx_driver.clone());

    let mut plugins = Plugins::default();
    for plg_name in &plugin_names {
        match reload_handler.add_library(plg_name, PlatformName::Yes) {
            Ok(lib) => plugins.add_plugin(&lib),
            Err(e) => {
                return Err(anyhow!("Unable to load dynamic lib, err {:?}", e));
            }
        }
    }

    Ok(plugins)

    // loop {
    //     reload_handler.update(Plugins::reload_callback, &mut plugs);

    //     if plugs.plugins.len() > 0 {
    //         // In a real program you want to cache the symbol and not do it every time if your
    //         // application is performance critical
    //         let fun: Symbol<extern "C" fn() -> i32> =
    //             unsafe { plugs.plugins[0].lib.get(b"shared_fun\0").unwrap() };

    //         println!("Value {}", fun());
    //     }

    //     // Wait for 0.5 sec
    //     thread::sleep(Duration::from_millis(500));
    // }
}

pub fn init_plugins(
    plugins: &Plugins,
    warehouse: &mut PluginWarehouse,
    cfg: &Config,
) -> Result<()> {
    let mut pkt_processor_cnt = 0;
    for plugin in &plugins.plugins {
        unsafe {
            let plugin_type = match plugin
                .lib
                .get::<PluginTypeFunc>(PLUGIN_TYPE_FUNC_NAME.as_bytes())
            {
                Ok(func) => func(),
                Err(e) => return Err(anyhow!("{:?}", e)),
            };

            match plugin_type {
                PluginType::RxDriver => {
                    let func = plugin
                        .lib
                        .get::<rx::NewRxDriverFunc>(rx::NEW_RX_DRIVER_FUNC_NAME.as_bytes())
                        .map_err(|e| anyhow!("{}", e))?;
                    let driver = *func();
                    println!("Initializing {} rx driver", driver.name());
                    driver.init(cfg)?;
                    match &warehouse.rx_driver {
                        None => warehouse.rx_driver = Some(driver),
                        Some(d) => {
                            return Err(anyhow!(
                                "alphonse is trying to load rx driver '{}', however alphonse has already loaded rx driver '{}', please check {} again",
                                driver.name(),
                                d.name(),
                                cfg.fpath
                            ))
                        }
                    }
                }
                PluginType::PacketProcessor => {
                    let func = plugin
                        .lib
                        .get::<processor::NewProcessorFunc>(
                            processor::NEW_PKT_PROCESSOR_FUNC_NAME.as_bytes(),
                        )
                        .map_err(|e| anyhow!("{}", e))?;
                    let mut processor = *func();
                    println!("Initializing {} pkt processor", processor.name());
                    processor.init(cfg)?;
                    processor.set_id(pkt_processor_cnt);
                    warehouse.pkt_processors.push(processor);
                    pkt_processor_cnt += 1;
                }
                _ => {}
            };
        }
    }

    Ok(())
}

pub fn cleanup_plugins(warehouse: &mut PluginWarehouse) -> Result<()> {
    match &warehouse.rx_driver {
        Some(driver) => driver.cleanup()?,
        None => {}
    };

    for processor in &warehouse.pkt_processors {
        processor.cleanup()?;
    }
    Ok(())
}
