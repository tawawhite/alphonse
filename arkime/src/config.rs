#[derive(Debug, Default)]
pub struct Config {
    /// Machine hostname
    pub hostname: String,
    /// Node name
    pub node: String,
    /// Elasticsearch hostname
    pub elasticsearch: String,
    /// Node prefix
    pub prefix: String,
}
