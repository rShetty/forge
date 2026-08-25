<p align="center">
  <img src="docs/logo.svg" width="200" alt="Forge Logo" />
</p>

# Forge

**Agent supply chain security — code signing, SBOM, vulnerability scanning, and provenance attestation.**

Forge ensures that every agent in the ecosystem is verified, signed, and scanned
before it can be registered in Hive or authorized by Patroclus. It addresses
OWASP Agentic AI Top 10 #5: Supply Chain Risks.

## Role in the Ecosystem

```
Governance:   Governance Hub · Patroclus · Argus · Forge
Runtime:      Hive · Relay · Miser
Enforcement:  Aegis · Sentiel · Cortex
```

Forge answers:
- "Was this agent code signed by a trusted publisher?"
- "Does this agent have known vulnerable dependencies?"
- "What's in this agent's software bill of materials?"
- "Who built this agent, from what source, when?"
- "Can we trust this agent with production access?"

## Capabilities

### Code Signing
- Ed25519 signatures on agent packages (tarballs, containers, binaries)
- Signing key management with key rotation
- Verification against trusted publisher registry
- Signature verification integrated into Hive agent registration

### SBOM Generation
- Software Bill of Materials for every agent package
- Dependency tree with versions and licenses
- Formats: SPDX, CycloneDX
- Stored alongside signature for audit trail

### Vulnerability Scanning
- Scan agent dependencies against vulnerability databases
- Rust (cargo audit), Python (pip-audit / safety), Node (npm audit)
- Severity classification (critical/high/medium/low)
- Block registration if critical vulnerabilities found (configurable)

### Provenance Attestation
- SLSA-style provenance: who built it, from what source, when, how
- Build environment attestation (CI/CD pipeline, commit hash, builder identity)
- Provenance bound to signature — can't forge provenance without the key

### Trust Scoring
- Verified publisher → higher trust → broader permissions
- Trust factors: code signed, SBOM clean, no critical CVEs, provenance verified
- Trust score feeds into Patroclus policy (min_trust_level constraint)
- Trust decay: score decreases if not re-scanned within threshold

## Quick Start

```bash
cargo build --release
./target/release/forge serve --config config.toml
# API: http://localhost:8788
```

## Integration

### With Hive (agent registration gate)
Hive calls Forge before accepting an agent registration:
```bash
# Verify agent package before registration
curl -X POST http://localhost:8788/api/verify \
  -d '{"package_path":"/path/to/agent.tar.gz","publisher":"trusted-org"}'
# Returns: {"verified":true,"trust_score":0.92,"sbom":{...},"vulnerabilities":[]}
```

### With Patroclus (trust-based policy)
Patroclus policies can reference Forge trust scores:
```yaml
- name: high-trust-only
  actions: ["deploy"]
  resources: ["prod-*"]
  decision: allow
  min_trust_score: 0.8
  reason: Only high-trust agents can deploy to production
```

## Ecosystem

Forge is part of the AI governance ecosystem governed through Governance Hub:

| Project | Role | Repo |
|---|---|---|
| **Hive** | Agent runtime & orchestration | [rShetty/hive](https://github.com/rShetty/hive) |
| **Patroclus** | Authorization infrastructure | [rShetty/patroclus](https://github.com/rShetty/patroclus) |
| **Relay** | MCP gateway & tool proxy | [rShetty/relay](https://github.com/rShetty/relay) |
| **Miser** | LLM cost optimization | [rShetty/miser](https://github.com/rShetty/miser) |
| **Sentiel** | Observability, DLP & compliance | [rShetty/sentiel](https://github.com/rShetty/sentiel) |
| **Aegis** | Network egress & attestation | [rShetty/Aegis](https://github.com/rShetty/Aegis) |
| **Forge** | Agent supply chain security | [rShetty/forge](https://github.com/rShetty/forge) |
| **Argus** | Human/agent OIDC identity provider | [rShetty/argus](https://github.com/rShetty/argus) |
| **Governance Hub** | Unified admin console and sole product UI | [rShetty/governance-hub](https://github.com/rShetty/governance-hub) |

Forge gates agent registration in Hive: before an agent can be deployed, Forge
verifies its signature, generates an SBOM, scans for vulnerabilities, and
calculates a trust score. Agents with critical vulnerabilities are blocked.
Trust scores feed into Patroclus policies (e.g., only trust score > 0.8 can
deploy to production).

Run the full ecosystem:
```bash
~/patroclus/scripts/start-ecosystem.sh start  # Starts all services
```

See the [ecosystem documentation](https://github.com/rShetty/patroclus/blob/main/docs/ECOSYSTEM.md)
for the complete integration guide.

## Status

**Early development.**

## License

MIT
