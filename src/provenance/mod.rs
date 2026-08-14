use serde::{Deserialize, Serialize};

use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub builder: String,
    pub build_type: String,
    pub source_repo: String,
    pub commit_hash: String,
    pub branch: String,
    pub build_time: String,
    pub build_environment: serde_json::Value,
    pub materials: Vec<String>,
}

pub struct ProvenanceEngine;

impl ProvenanceEngine {
    pub fn create(
        builder: &str,
        source_repo: &str,
        commit_hash: &str,
        branch: &str,
        materials: Vec<String>,
    ) -> Provenance {
        Provenance {
            builder: builder.to_string(),
            build_type: "forge-ci-v1".to_string(),
            source_repo: source_repo.to_string(),
            commit_hash: commit_hash.to_string(),
            branch: branch.to_string(),
            build_time: chrono::Utc::now().to_rfc3339(),
            build_environment: serde_json::json!({
                "ci": builder,
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            }),
            materials,
        }
    }

    pub fn verify(provenance: &Provenance) -> bool {
        !provenance.commit_hash.is_empty()
            && !provenance.source_repo.is_empty()
            && !provenance.builder.is_empty()
            && provenance.build_type.starts_with("forge-")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_provenance() {
        let p = ProvenanceEngine::create(
            "github-actions",
            "https://github.com/rShetty/hive",
            "abc123",
            "main",
            vec!["Cargo.toml".to_string()],
        );
        assert_eq!(p.builder, "github-actions");
        assert_eq!(p.commit_hash, "abc123");
        assert!(p.build_time.len() > 0);
    }

    #[test]
    fn test_verify_provenance() {
        let p = ProvenanceEngine::create("ci", "repo", "abc", "main", vec![]);
        assert!(ProvenanceEngine::verify(&p));

        let bad = Provenance {
            builder: "".to_string(),
            build_type: "forge-ci-v1".to_string(),
            source_repo: "repo".to_string(),
            commit_hash: "abc".to_string(),
            branch: "main".to_string(),
            build_time: "now".to_string(),
            build_environment: serde_json::json!({}),
            materials: vec![],
        };
        assert!(!ProvenanceEngine::verify(&bad));
    }
}
