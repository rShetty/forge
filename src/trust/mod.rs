use crate::db::Database;
use crate::errors::Result;
use crate::scan::ScanEngine;
use uuid::Uuid;

pub struct TrustEngine;

impl TrustEngine {
    pub fn calculate(
        signed: bool,
        publisher_trusted: bool,
        vulnerabilities_count: usize,
        has_critical_vulns: bool,
        provenance_verified: bool,
        sbom_present: bool,
    ) -> f64 {
        let mut score = 0.0;

        if signed { score += 0.25; }
        if publisher_trusted { score += 0.20; }
        if sbom_present { score += 0.15; }
        if provenance_verified { score += 0.20; }

        if vulnerabilities_count == 0 {
            score += 0.20;
        } else if !has_critical_vulns {
            score += 0.10;
        }

        if has_critical_vulns {
            score = (score - 0.30_f64).max(0.0_f64);
        }

        score.min(1.0_f64)
    }

    pub fn update_package_trust(
        db: &Database,
        id: Uuid,
        signed: bool,
        publisher_trusted: bool,
        vulns: &[crate::scan::Vulnerability],
        provenance_verified: bool,
        sbom_present: bool,
    ) -> Result<f64> {
        let has_critical = ScanEngine::has_critical(vulns);
        let score = Self::calculate(
            signed,
            publisher_trusted,
            vulns.len(),
            has_critical,
            provenance_verified,
            sbom_present,
        );
        db.update_trust_score(id, score)?;
        Ok(score)
    }

    pub fn meets_threshold(score: f64, threshold: f64) -> bool {
        score >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_trust() {
        let score = TrustEngine::calculate(true, true, 0, false, true, true);
        assert!((score - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_unsigned_untrusted() {
        let score = TrustEngine::calculate(false, false, 0, false, false, false);
        assert!((score - 0.20).abs() < 0.001);
    }

    #[test]
    fn test_critical_vuln_penalty() {
        let score = TrustEngine::calculate(true, true, 2, true, true, true);
        assert!(score < 0.7);
    }

    #[test]
    fn test_no_critical_some_vulns() {
        let score = TrustEngine::calculate(true, true, 3, false, true, true);
        assert!((score - 0.90).abs() < 0.001);
    }

    #[test]
    fn test_threshold_check() {
        assert!(TrustEngine::meets_threshold(0.8, 0.5));
        assert!(!TrustEngine::meets_threshold(0.3, 0.5));
    }
}
