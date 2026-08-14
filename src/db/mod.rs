use std::sync::Arc;

use chrono::Utc;
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::errors::Result;

pub struct Database {
    conn: Arc<parking_lot::Mutex<Connection>>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| crate::errors::ForgeError::Database(format!("failed to open: {}", e)))?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        Self::migrate(&conn)?;
        Ok(Database {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
        })
    }

    fn migrate(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS packages (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                publisher TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                signature TEXT,
                signed_at TEXT,
                sbom TEXT,
                provenance TEXT,
                trust_score REAL NOT NULL DEFAULT 0.0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
            CREATE INDEX IF NOT EXISTS idx_packages_publisher ON packages(publisher);
            CREATE INDEX IF NOT EXISTS idx_packages_hash ON packages(file_hash);

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                package_id TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                affected_version TEXT,
                found_at TEXT NOT NULL,
                FOREIGN KEY (package_id) REFERENCES packages(id)
            );
            CREATE INDEX IF NOT EXISTS idx_vulns_package ON vulnerabilities(package_id);
            CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);

            CREATE TABLE IF NOT EXISTS signing_keys (
                id TEXT PRIMARY KEY,
                publisher TEXT NOT NULL,
                public_key TEXT NOT NULL,
                private_key_encrypted TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_keys_publisher ON signing_keys(publisher);

            CREATE TABLE IF NOT EXISTS trusted_publishers (
                publisher TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                trust_level REAL NOT NULL DEFAULT 1.0,
                added_at TEXT NOT NULL
            );
        ",
        )?;
        Ok(())
    }

    pub fn register_package(
        &self,
        name: &str,
        version: &str,
        publisher: &str,
        file_hash: &str,
    ) -> Result<Uuid> {
        let conn = self.conn.lock();
        let id = Uuid::now_v7();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO packages (id, name, version, publisher, file_hash, trust_score, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, 0.0, ?, ?)",
            params![id.to_string(), name, version, publisher, file_hash, now, now],
        )?;
        Ok(id)
    }

    pub fn get_package(&self, id: Uuid) -> Result<Option<serde_json::Value>> {
        let conn = self.conn.lock();
        let result = conn.query_row(
            "SELECT id, name, version, publisher, file_hash, signature, signed_at, sbom, provenance, trust_score, created_at, updated_at
             FROM packages WHERE id = ?",
            params![id.to_string()],
            |row| {
                let sig: Option<String> = row.get(5)?;
                let signed_at: Option<String> = row.get(6)?;
                let sbom: Option<String> = row.get(7)?;
                let prov: Option<String> = row.get(8)?;
                Ok(serde_json::json!({
                    "id": row.get::<_, String>(0)?,
                    "name": row.get::<_, String>(1)?,
                    "version": row.get::<_, String>(2)?,
                    "publisher": row.get::<_, String>(3)?,
                    "file_hash": row.get::<_, String>(4)?,
                    "signature": sig,
                    "signed_at": signed_at,
                    "sbom": sbom.and_then(|s: String| serde_json::from_str::<serde_json::Value>(&s).ok()),
                    "provenance": prov.and_then(|s: String| serde_json::from_str::<serde_json::Value>(&s).ok()),
                    "trust_score": row.get::<_, f64>(9)?,
                    "created_at": row.get::<_, String>(10)?,
                    "updated_at": row.get::<_, String>(11)?,
                }))
            },
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_package_by_hash(&self, file_hash: &str) -> Result<Option<serde_json::Value>> {
        let conn = self.conn.lock();
        let result = conn.query_row(
            "SELECT id FROM packages WHERE file_hash = ? ORDER BY created_at DESC LIMIT 1",
            params![file_hash],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(id_str) => {
                drop(conn);
                let id = Uuid::parse_str(&id_str).unwrap_or_default();
                self.get_package(id)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_packages(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, version, publisher, file_hash, signature, trust_score, created_at
             FROM packages ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let sig: Option<String> = row.get(5)?;
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "name": row.get::<_, String>(1)?,
                "version": row.get::<_, String>(2)?,
                "publisher": row.get::<_, String>(3)?,
                "file_hash": format!("{}...", &row.get::<_, String>(4)?[..16]),
                "signed": sig.is_some(),
                "trust_score": row.get::<_, f64>(6)?,
                "created_at": row.get::<_, String>(7)?,
            }))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn update_signature(&self, id: Uuid, signature: &str) -> Result<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE packages SET signature = ?, signed_at = ?, updated_at = ? WHERE id = ?",
            params![signature, now, now, id.to_string()],
        )?;
        Ok(())
    }

    pub fn update_sbom(&self, id: Uuid, sbom: &serde_json::Value) -> Result<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE packages SET sbom = ?, updated_at = ? WHERE id = ?",
            params![sbom.to_string(), now, id.to_string()],
        )?;
        Ok(())
    }

    pub fn update_provenance(&self, id: Uuid, provenance: &serde_json::Value) -> Result<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE packages SET provenance = ?, updated_at = ? WHERE id = ?",
            params![provenance.to_string(), now, id.to_string()],
        )?;
        Ok(())
    }

    pub fn update_trust_score(&self, id: Uuid, score: f64) -> Result<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE packages SET trust_score = ?, updated_at = ? WHERE id = ?",
            params![score, now, id.to_string()],
        )?;
        Ok(())
    }

    pub fn add_vulnerability(
        &self,
        package_id: Uuid,
        cve_id: &str,
        severity: &str,
        description: &str,
        affected_version: &str,
    ) -> Result<()> {
        let conn = self.conn.lock();
        let id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO vulnerabilities (id, package_id, cve_id, severity, description, affected_version, found_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![id, package_id.to_string(), cve_id, severity, description, affected_version, now],
        )?;
        Ok(())
    }

    pub fn list_vulnerabilities(&self, package_id: Uuid) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, cve_id, severity, description, affected_version, found_at
             FROM vulnerabilities WHERE package_id = ? ORDER BY found_at DESC",
        )?;
        let rows = stmt.query_map(params![package_id.to_string()], |row| {
            let desc: Option<String> = row.get(3)?;
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "cve_id": row.get::<_, String>(1)?,
                "severity": row.get::<_, String>(2)?,
                "description": desc,
                "affected_version": row.get::<_, String>(4)?,
                "found_at": row.get::<_, String>(5)?,
            }))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn add_trusted_publisher(
        &self,
        publisher: &str,
        public_key: &str,
        trust_level: f64,
    ) -> Result<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO trusted_publishers (publisher, public_key, trust_level, added_at)
             VALUES (?, ?, ?, ?)",
            params![publisher, public_key, trust_level, now],
        )?;
        Ok(())
    }

    pub fn get_trusted_publisher(&self, publisher: &str) -> Result<Option<(String, f64)>> {
        let conn = self.conn.lock();
        let result = conn.query_row(
            "SELECT public_key, trust_level FROM trusted_publishers WHERE publisher = ?",
            params![publisher],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_trusted_publishers(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT publisher, public_key, trust_level, added_at FROM trusted_publishers",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "publisher": row.get::<_, String>(0)?,
                "public_key": row.get::<_, String>(1)?,
                "trust_level": row.get::<_, f64>(2)?,
                "added_at": row.get::<_, String>(3)?,
            }))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn store_signing_key(
        &self,
        publisher: &str,
        public_key: &str,
        private_key_encrypted: &str,
    ) -> Result<()> {
        let conn = self.conn.lock();
        let id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO signing_keys (id, publisher, public_key, private_key_encrypted, created_at)
             VALUES (?, ?, ?, ?, ?)",
            params![id, publisher, public_key, private_key_encrypted, now],
        )?;
        Ok(())
    }
}
