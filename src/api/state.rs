use std::sync::Arc;

use crate::config::Config;
use crate::db::Database;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let db = Database::new(&config.database.path)?;
        Ok(AppState {
            db: Arc::new(db),
            config: Arc::new(config),
        })
    }

    pub fn new_test() -> anyhow::Result<Self> {
        let config = Config::default();
        let db = Database::new(":memory:")?;
        Ok(AppState {
            db: Arc::new(db),
            config: Arc::new(config),
        })
    }
}
