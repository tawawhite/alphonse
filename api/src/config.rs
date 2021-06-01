use std::sync::{atomic::AtomicBool, Arc};

#[derive(Default, Clone)]
pub struct Config {
    pub exit: Arc<AtomicBool>,
    /// Configure file dist location
    pub fpath: String,
    pub rx_driver: String,
    pub verbose_mode: bool,
    pub pkt_channel_size: u32,
    pub default_timeout: u16,
    pub delete: bool,
    pub dpdk_eal_args: Vec<String>,
    pub dry_run: bool,
    pub node: String,
    pub hostname: String,
    pub output_threads: u8,
    pub processors: Vec<String>,
    pub pcap_file: String,
    pub pcap_dir: String,
    pub pkt_threads: u8,
    pub quiet: bool,
    pub recursive: bool,
    pub rx_stat_log_interval: u64,
    pub rx_threads: u8,
    /// Max single session packets
    pub ses_max_packets: u16,
    /// Max session connection duration
    pub ses_save_timeout: u16,
    pub ses_threads: u8,
    pub sctp_timeout: u16,
    pub tags: Vec<String>,
    pub tcp_timeout: u16,
    pub timeout_interval: u64,
    pub udp_timeout: u16,
    pub doc: crate::utils::yaml::Yaml,
}

impl Config {
    pub fn get_integer(&self, key: &str, default: i64, min: i64, max: i64) -> i64 {
        crate::utils::yaml::get_integer(&self.doc.as_ref(), key, default, min, max)
    }

    pub fn get_str(&self, key: &str, default: &str) -> String {
        crate::utils::yaml::get_str(&self.doc.as_ref(), key, default)
    }

    pub fn get_str_arr(&self, key: &str) -> Vec<String> {
        crate::utils::yaml::get_str_arr(&self.doc.as_ref(), key)
    }
}
