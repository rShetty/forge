use serde::{Deserialize, Serialize};

use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub spdx_version: String,
    pub name: String,
    pub version: String,
    pub packages: Vec<SbomPackage>,
    pub total_dependencies: usize,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomPackage {
    pub name: String,
    pub version: String,
    pub license: Option<String>,
    pub source: String,
}

pub struct SbomEngine;

impl SbomEngine {
    pub fn generate(name: &str, version: &str, dependencies: &[SbomPackage]) -> Result<Sbom> {
        Ok(Sbom {
            spdx_version: "SPDX-2.3".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            packages: dependencies.to_vec(),
            total_dependencies: dependencies.len(),
            generated_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    pub fn parse_cargo_lock(content: &str) -> Vec<SbomPackage> {
        let mut packages = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("name = \"") {
                let name = trimmed
                    .trim_start_matches("name = \"")
                    .trim_end_matches('"')
                    .to_string();
                packages.push(SbomPackage {
                    name,
                    version: String::new(),
                    license: None,
                    source: "cargo".to_string(),
                });
            }
            if trimmed.starts_with("version = \"") && !packages.is_empty() {
                let version = trimmed
                    .trim_start_matches("version = \"")
                    .trim_end_matches('"')
                    .to_string();
                packages.last_mut().unwrap().version = version;
            }
        }
        packages
    }

    pub fn parse_requirements_txt(content: &str) -> Vec<SbomPackage> {
        let mut packages = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
                continue;
            }
            let parts: Vec<&str> = trimmed
                .splitn(2, |c: char| {
                    c == '=' || c == '<' || c == '>' || c == '!' || c == '~' || c == ';'
                })
                .map(|s| s.trim())
                .collect();
            let name = parts[0].to_string();
            let version = parts
                .get(1)
                .map(|v| v.trim_start_matches('=').trim().to_string())
                .unwrap_or_default();
            packages.push(SbomPackage {
                name,
                version,
                license: None,
                source: "pypi".to_string(),
            });
        }
        packages
    }

    pub fn parse_package_json(content: &str) -> Vec<SbomPackage> {
        let mut packages = Vec::new();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(content)
            && let Some(deps) = json.get("dependencies").and_then(|d| d.as_object())
        {
            for (name, version) in deps {
                packages.push(SbomPackage {
                    name: name.clone(),
                    version: version.as_str().unwrap_or("").to_string(),
                    license: None,
                    source: "npm".to_string(),
                });
            }
        }
        packages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_sbom() {
        let deps = vec![
            SbomPackage {
                name: "tokio".to_string(),
                version: "1.0".to_string(),
                license: Some("MIT".to_string()),
                source: "cargo".to_string(),
            },
            SbomPackage {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                license: Some("MIT".to_string()),
                source: "cargo".to_string(),
            },
        ];
        let sbom = SbomEngine::generate("my-agent", "1.0.0", &deps).unwrap();
        assert_eq!(sbom.name, "my-agent");
        assert_eq!(sbom.total_dependencies, 2);
        assert_eq!(sbom.spdx_version, "SPDX-2.3");
    }

    #[test]
    fn test_parse_requirements_txt() {
        let content = "requests==2.28.0\nnumpy>=1.20\nflask\n# comment\n-r other.txt";
        let packages = SbomEngine::parse_requirements_txt(content);
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "requests");
        assert_eq!(packages[0].version, "2.28.0");
        assert_eq!(packages[1].name, "numpy");
        assert_eq!(packages[2].name, "flask");
    }

    #[test]
    fn test_parse_package_json() {
        let content = r#"{"dependencies": {"express": "^4.18", "lodash": "^4.17"}}"#;
        let packages = SbomEngine::parse_package_json(content);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "express");
    }
}
