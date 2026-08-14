use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

use crate::api::state::AppState;
use crate::errors::ForgeError;

type MethodRouter = axum::routing::MethodRouter<AppState>;

pub fn all_routes() -> Vec<(String, MethodRouter)> {
    vec![
        ("/health".to_string(), get(health)),

        // Package management
        ("/api/packages".to_string(), post(register_package).get(list_packages)),
        ("/api/packages/{id}".to_string(), get(get_package)),
        ("/api/packages/{id}/sign".to_string(), post(sign_package)),
        ("/api/packages/{id}/verify".to_string(), post(verify_package)),
        ("/api/packages/{id}/sbom".to_string(), post(generate_sbom)),
        ("/api/packages/{id}/scan".to_string(), post(scan_package)),
        ("/api/packages/{id}/provenance".to_string(), post(set_provenance)),
        ("/api/packages/{id}/trust".to_string(), get(get_trust_score)),

        // Full verify (does everything: sign + sbom + scan + provenance + trust)
        ("/api/verify".to_string(), post(verify_full)),

        // Trusted publishers
        ("/api/publishers".to_string(), post(add_publisher).get(list_publishers)),

        // Key management
        ("/api/keys/generate".to_string(), post(generate_keypair)),
    ]
}

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok", "service": "forge"})))
}

// ── Package management ────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterPackageRequest {
    name: String,
    version: String,
    publisher: String,
    file_path: Option<String>,
}

async fn register_package(
    State(state): State<AppState>,
    Json(req): Json<RegisterPackageRequest>,
) -> Result<Json<serde_json::Value>, ForgeError> {
    let file_hash = if let Some(path) = &req.file_path {
        crate::signing::SigningEngine::hash_file(path)?
    } else {
        crate::signing::SigningEngine::hash_bytes(req.name.as_bytes())?
    };
    let id = state.db.register_package(&req.name, &req.version, &req.publisher, &file_hash)?;
    Ok(Json(serde_json::json!({
        "id": id,
        "name": req.name,
        "version": req.version,
        "publisher": req.publisher,
        "file_hash": file_hash,
    })))
}

async fn list_packages(
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, ForgeError> {
    Ok(Json(state.db.list_packages()?))
}

async fn get_package(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ForgeError> {
    state.db.get_package(id)?
        .map(Json)
        .ok_or_else(|| ForgeError::NotFound("package not found".to_string()))
}

#[derive(Deserialize)]
struct SignRequest {
    private_key: String,
}

async fn sign_package(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<SignRequest>,
) -> Result<Json<serde_json::Value>, ForgeError> {
    let pkg = state.db.get_package(id)?
        .ok_or_else(|| ForgeError::NotFound("package not found".to_string()))?;
    let hash = pkg["file_hash"].as_str().unwrap_or("");
    let signature = crate::signing::SigningEngine::sign(&req.private_key, hash.as_bytes())?;
    state.db.update_signature(id, &signature)?;
    Ok(Json(serde_json::json!({
        "id": id,
        "signed": true,
        "signature": format!("{}...", &signature[..20]),
    })))
}

#[derive(Deserialize)]
struct VerifyRequest {
    public_key: String,
}

async fn verify_package(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, ForgeError> {
    let pkg = state.db.get_package(id)?
        .ok_or_else(|| ForgeError::NotFound("package not found".to_string()))?;
    let signature = pkg["signature"].as_str()
        .ok_or_else(|| ForgeError::VerificationFailed("package not signed".to_string()))?;
    let hash = pkg["file_hash"].as_str().unwrap_or("");
    let valid = crate::signing::SigningEngine::verify(&req.public_key, hash.as_bytes(), signature)?;
    Ok(Json(serde_json::json!({
        "id": id,
        "signature_valid": valid,
    })))
}

#[derive(Deserialize)]
struct SbomRequest {
    dependencies: Vec<crate::sbom::SbomPackage>,
}

async fn generate_sbom(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<SbomRequest>,
) -> Result<Json<serde_json::Value>, ForgeError> {
    let pkg = state.db.get_package(id)?
        .ok_or_else(|| ForgeError::NotFound("package not found".to_string()))?;
    let sbom = crate::sbom::SbomEngine::generate(
        pkg["name"].as_str().unwrap_or("unknown"),
        pkg["version"].as_str().unwrap_or("0.0.0"),
        &req.dependencies,
    )?;
    state.db.update_sbom(id, &serde_json::to_value(&sbom).unwrap())?;
    Ok(Json(serde_json::json!({
        "id": id,
        "sbom_generated": true,
        "total_dependencies": sbom.total_dependencies,
    })))
}

async fn scan_package(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ForgeError> {
    let pkg = state.db.get_package(id)?
        .ok_or_else(|| ForgeError::NotFound("package not found".to_string()))?;
    let sbom = pkg.get("sbom")
        .ok_or_else(|| ForgeError::VerificationFailed("no SBOM — generate first".to_string()))?;
    let deps: Vec<crate::sbom::SbomPackage> = sbom["packages"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|d| serde_json::from_value(d.clone()).ok())
        .collect();
    let vulns = crate::scan::ScanEngine::scan_sbom(&deps);
    for v in &vulns {
        state.db.add_vulnerability(id, &v.cve_id, &v.severity, &v.description, &v.affected_version)?;
    }
    let counts = crate::scan::ScanEngine::severity_count(&vulns);
    Ok(Json(serde_json::json!({
        "id": id,
        "vulnerabilities": counts,
        "has_critical": crate::scan::ScanEngine::has_critical(&vulns),
        "details": vulns,
    })))
}

#[derive(Deserialize)]
struct ProvenanceRequest {
    builder: String,
    source_repo: String,
    commit_hash: String,
    branch: String,
    materials: Vec<String>,
}

async fn set_provenance(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<ProvenanceRequest>,
) -> Result<Json<serde_json::Value>, ForgeError> {
    let prov = crate::provenance::ProvenanceEngine::create(
        &req.builder, &req.source_repo, &req.commit_hash, &req.branch, req.materials,
    );
    let verified = crate::provenance::ProvenanceEngine::verify(&prov);
    state.db.update_provenance(id, &serde_json::to_value(&prov).unwrap())?;
    Ok(Json(serde_json::json!({
        "id": id,
        "provenance_set": true,
        "verified": verified,
    })))
}

async fn get_trust_score(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ForgeError> {
    let pkg = state.db.get_package(id)?
        .ok_or_else(|| ForgeError::NotFound("package not found".to_string()))?;
    let signed = pkg.get("signature").and_then(|v| v.as_str()).is_some();
    let publisher = pkg["publisher"].as_str().unwrap_or("");
    let publisher_trusted = state.db.get_trusted_publisher(publisher)?.is_some();
    let sbom_present = pkg.get("sbom").is_some() && !pkg["sbom"].is_null();
    let provenance_verified = pkg.get("provenance")
        .and_then(|p| p.get("commit_hash"))
        .and_then(|c| c.as_str())
        .map(|c| !c.is_empty())
        .unwrap_or(false);
    let vulns = state.db.list_vulnerabilities(id)?;
    let vuln_models: Vec<crate::scan::Vulnerability> = vulns.iter().filter_map(|v| {
        Some(crate::scan::Vulnerability {
            cve_id: v["cve_id"].as_str()?.to_string(),
            severity: v["severity"].as_str()?.to_string(),
            description: v["description"].as_str().unwrap_or("").to_string(),
            affected_package: "".to_string(),
            affected_version: v["affected_version"].as_str().unwrap_or("").to_string(),
        })
    }).collect();

    let score = crate::trust::TrustEngine::update_package_trust(
        &state.db, id, signed, publisher_trusted, &vuln_models, provenance_verified, sbom_present,
    )?;

    Ok(Json(serde_json::json!({
        "id": id,
        "trust_score": score,
        "factors": {
            "signed": signed,
            "publisher_trusted": publisher_trusted,
            "sbom_present": sbom_present,
            "provenance_verified": provenance_verified,
            "vulnerability_count": vuln_models.len(),
            "has_critical": crate::scan::ScanEngine::has_critical(&vuln_models),
        },
        "meets_threshold": crate::trust::TrustEngine::meets_threshold(score, state.config.trust.min_trust_score),
    })))
}

// ── Full verify (one-shot) ────────────────────────────────────────

#[derive(Deserialize)]
struct FullVerifyRequest {
    name: String,
    version: String,
    publisher: String,
    file_path: Option<String>,
    dependencies: Vec<crate::sbom::SbomPackage>,
    private_key: Option<String>,
    public_key: Option<String>,
    builder: Option<String>,
    source_repo: Option<String>,
    commit_hash: Option<String>,
    branch: Option<String>,
}

async fn verify_full(
    State(state): State<AppState>,
    Json(req): Json<FullVerifyRequest>,
) -> Result<Json<serde_json::Value>, ForgeError> {
    // 1. Register package
    let file_hash = if let Some(path) = &req.file_path {
        crate::signing::SigningEngine::hash_file(path)?
    } else {
        crate::signing::SigningEngine::hash_bytes(req.name.as_bytes())?
    };
    let id = state.db.register_package(&req.name, &req.version, &req.publisher, &file_hash)?;

    // 2. Sign
    let signed = if let Some(pk) = &req.private_key {
        let sig = crate::signing::SigningEngine::sign(pk, file_hash.as_bytes())?;
        state.db.update_signature(id, &sig)?;
        true
    } else {
        false
    };

    // 3. Generate SBOM
    let sbom = crate::sbom::SbomEngine::generate(&req.name, &req.version, &req.dependencies)?;
    state.db.update_sbom(id, &serde_json::to_value(&sbom).unwrap())?;

    // 4. Scan for vulnerabilities
    let vulns = crate::scan::ScanEngine::scan_sbom(&req.dependencies);
    for v in &vulns {
        state.db.add_vulnerability(id, &v.cve_id, &v.severity, &v.description, &v.affected_version)?;
    }
    let has_critical = crate::scan::ScanEngine::has_critical(&vulns);

    // 5. Provenance
    let provenance_verified = if let (Some(builder), Some(repo), Some(commit), Some(branch)) =
        (&req.builder, &req.source_repo, &req.commit_hash, &req.branch)
    {
        let prov = crate::provenance::ProvenanceEngine::create(
            builder, repo, commit, branch, vec![],
        );
        let verified = crate::provenance::ProvenanceEngine::verify(&prov);
        state.db.update_provenance(id, &serde_json::to_value(&prov).unwrap())?;
        verified
    } else {
        false
    };

    // 6. Check publisher trust
    let publisher_trusted = state.db.get_trusted_publisher(&req.publisher)?.is_some();

    // 7. Calculate trust score
    let score = crate::trust::TrustEngine::update_package_trust(
        &state.db, id, signed, publisher_trusted, &vulns, provenance_verified, true,
    )?;

    // 8. Decision
    let meets_threshold = crate::trust::TrustEngine::meets_threshold(score, state.config.trust.min_trust_score);
    let blocked = has_critical && state.config.trust.block_on_critical_vuln;

    Ok(Json(serde_json::json!({
        "id": id,
        "name": req.name,
        "version": req.version,
        "publisher": req.publisher,
        "file_hash": format!("{}...", &file_hash[..16]),
        "signed": signed,
        "sbom": {
            "total_dependencies": sbom.total_dependencies,
        },
        "vulnerabilities": crate::scan::ScanEngine::severity_count(&vulns),
        "has_critical_vulns": has_critical,
        "provenance_verified": provenance_verified,
        "publisher_trusted": publisher_trusted,
        "trust_score": score,
        "meets_threshold": meets_threshold,
        "blocked": blocked,
        "decision": if blocked { "blocked" } else if meets_threshold { "trusted" } else { "untrusted" },
    })))
}

// ── Publishers ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AddPublisherRequest {
    publisher: String,
    public_key: String,
    trust_level: Option<f64>,
}

async fn add_publisher(
    State(state): State<AppState>,
    Json(req): Json<AddPublisherRequest>,
) -> Result<Json<serde_json::Value>, ForgeError> {
    let trust = req.trust_level.unwrap_or(1.0);
    state.db.add_trusted_publisher(&req.publisher, &req.public_key, trust)?;
    Ok(Json(serde_json::json!({
        "added": true,
        "publisher": req.publisher,
        "trust_level": trust,
    })))
}

async fn list_publishers(
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, ForgeError> {
    Ok(Json(state.db.list_trusted_publishers()?))
}

// ── Keys ──────────────────────────────────────────────────────────

async fn generate_keypair() -> Json<serde_json::Value> {
    let kp = crate::signing::SigningEngine::generate_keypair();
    Json(serde_json::json!({
        "public_key": kp.public_key,
        "private_key": kp.private_key,
        "note": "Save the private key securely — it will not be shown again",
    }))
}

// ── Router ────────────────────────────────────────────────────────

pub fn create_router(state: AppState) -> Router {
    let routes = all_routes();
    let mut router = Router::new();
    for (path, method_router) in routes {
        router = router.route(&path, method_router);
    }
    router
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
