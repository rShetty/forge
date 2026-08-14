use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve_id: String,
    pub severity: String,
    pub description: String,
    pub affected_package: String,
    pub affected_version: String,
}

pub struct ScanEngine;

impl ScanEngine {
    pub fn scan_sbom(packages: &[crate::sbom::SbomPackage]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        for pkg in packages {
            let known = Self::check_known_vulns(&pkg.name, &pkg.version);
            vulns.extend(known);
        }
        vulns
    }

    fn check_known_vulns(name: &str, version: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let db = Self::vuln_db();
        for entry in &db {
            if entry.0 == name && Self::version_matches(version, entry.1) {
                vulns.push(Vulnerability {
                    cve_id: entry.2.to_string(),
                    severity: entry.3.to_string(),
                    description: entry.4.to_string(),
                    affected_package: name.to_string(),
                    affected_version: version.to_string(),
                });
            }
        }

        vulns
    }

    fn version_matches(version: &str, pattern: &str) -> bool {
        if pattern == "*" || pattern.is_empty() {
            return true;
        }
        if let Some(prefix) = pattern.strip_prefix("<") {
            return Self::compare_versions(version, prefix.trim()) < 0;
        }
        if let Some(prefix) = pattern.strip_prefix(">=") {
            return Self::compare_versions(version, prefix.trim()) >= 0;
        }
        version == pattern
    }

    fn compare_versions(a: &str, b: &str) -> i32 {
        let a_parts: Vec<u32> = a.split('.').filter_map(|s| s.parse().ok()).collect();
        let b_parts: Vec<u32> = b.split('.').filter_map(|s| s.parse().ok()).collect();
        for i in 0..a_parts.len().max(b_parts.len()) {
            let av = a_parts.get(i).copied().unwrap_or(0);
            let bv = b_parts.get(i).copied().unwrap_or(0);
            if av < bv {
                return -1;
            }
            if av > bv {
                return 1;
            }
        }
        0
    }

    fn vuln_db() -> Vec<(
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    )> {
        vec![
            (
                "openssl",
                "< 1.1.1k",
                "CVE-2021-3711",
                "critical",
                "SM2 Decryption Buffer Overflow",
            ),
            (
                "openssl",
                "< 1.0.2h",
                "CVE-2016-2108",
                "high",
                "AES-NI CBC padding oracle",
            ),
            (
                "log4j",
                "< 2.15.0",
                "CVE-2021-44228",
                "critical",
                "Log4Shell RCE via JNDI lookup",
            ),
            (
                "log4j",
                "< 2.17.1",
                "CVE-2021-45046",
                "critical",
                "Log4Shell incomplete fix",
            ),
            (
                "requests",
                "< 2.32.0",
                "CVE-2024-35195",
                "medium",
                "Certificate verification bypass",
            ),
            (
                "node-fetch",
                "< 2.6.7",
                "CVE-2022-0235",
                "high",
                "Credential leak via redirect",
            ),
            (
                "lodash",
                "< 4.17.21",
                "CVE-2021-23337",
                "high",
                "Command injection via template",
            ),
            (
                "minimist",
                "< 1.2.6",
                "CVE-2021-44906",
                "critical",
                "Prototype pollution",
            ),
            (
                "axios",
                "< 0.21.2",
                "CVE-2021-3749",
                "high",
                "ReDoS via trim-whitespace",
            ),
            (
                "pillow",
                "< 9.0.1",
                "CVE-2022-22816",
                "high",
                "Buffer overflow in convert",
            ),
            (
                "pyyaml",
                "< 5.4",
                "CVE-2020-1747",
                "critical",
                "Arbitrary code execution",
            ),
            (
                "jinja2",
                "< 2.11.3",
                "CVE-2020-28493",
                "high",
                "ReDoS via urlize filter",
            ),
        ]
    }

    pub fn has_critical(vulns: &[Vulnerability]) -> bool {
        vulns.iter().any(|v| v.severity == "critical")
    }

    pub fn severity_count(vulns: &[Vulnerability]) -> serde_json::Value {
        let critical = vulns.iter().filter(|v| v.severity == "critical").count();
        let high = vulns.iter().filter(|v| v.severity == "high").count();
        let medium = vulns.iter().filter(|v| v.severity == "medium").count();
        let low = vulns.iter().filter(|v| v.severity == "low").count();
        serde_json::json!({
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": vulns.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom::SbomPackage;

    #[test]
    fn test_scan_finds_log4shell() {
        let packages = vec![SbomPackage {
            name: "log4j".to_string(),
            version: "2.14.0".to_string(),
            license: None,
            source: "maven".to_string(),
        }];
        let vulns = ScanEngine::scan_sbom(&packages);
        assert!(vulns.iter().any(|v| v.cve_id == "CVE-2021-44228"));
        assert!(ScanEngine::has_critical(&vulns));
    }

    #[test]
    fn test_scan_finds_pyyaml() {
        let packages = vec![SbomPackage {
            name: "pyyaml".to_string(),
            version: "5.3".to_string(),
            license: None,
            source: "pypi".to_string(),
        }];
        let vulns = ScanEngine::scan_sbom(&packages);
        assert!(vulns.iter().any(|v| v.cve_id == "CVE-2020-1747"));
    }

    #[test]
    fn test_scan_clean_dependencies() {
        let packages = vec![SbomPackage {
            name: "tokio".to_string(),
            version: "1.0".to_string(),
            license: None,
            source: "cargo".to_string(),
        }];
        let vulns = ScanEngine::scan_sbom(&packages);
        assert!(vulns.is_empty());
        assert!(!ScanEngine::has_critical(&vulns));
    }

    #[test]
    fn test_version_comparison() {
        assert!(ScanEngine::version_matches("2.14.0", "< 2.15.0"));
        assert!(!ScanEngine::version_matches("2.15.0", "< 2.15.0"));
        assert!(ScanEngine::version_matches("2.14.0", "< 2.17.1"));
        assert!(ScanEngine::version_matches("5.3", ">= 5.0"));
    }

    #[test]
    fn test_severity_count() {
        let vulns = vec![
            Vulnerability {
                cve_id: "CVE-1".to_string(),
                severity: "critical".to_string(),
                description: "".to_string(),
                affected_package: "".to_string(),
                affected_version: "".to_string(),
            },
            Vulnerability {
                cve_id: "CVE-2".to_string(),
                severity: "high".to_string(),
                description: "".to_string(),
                affected_package: "".to_string(),
                affected_version: "".to_string(),
            },
            Vulnerability {
                cve_id: "CVE-3".to_string(),
                severity: "high".to_string(),
                description: "".to_string(),
                affected_package: "".to_string(),
                affected_version: "".to_string(),
            },
        ];
        let counts = ScanEngine::severity_count(&vulns);
        assert_eq!(counts["critical"], 1);
        assert_eq!(counts["high"], 2);
        assert_eq!(counts["total"], 3);
    }
}
