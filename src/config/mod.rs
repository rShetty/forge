use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub trust: TrustConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    pub min_trust_score: f64,
    pub rescan_threshold_days: i64,
    pub block_on_critical_vuln: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8788,
            },
            database: DatabaseConfig { path: "forge.db".to_string() },
            trust: TrustConfig {
                min_trust_score: 0.5,
                rescan_threshold_days: 30,
                block_on_critical_vuln: true,
            },
        }
    }
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(&std::fs::read_to_string(path)?)?)
    }
}
