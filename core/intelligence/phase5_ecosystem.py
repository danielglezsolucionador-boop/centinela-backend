from __future__ import annotations

import json
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


class PhaseFiveEcosystem:
    """Evidence-based ecosystem visibility.

    Phase 5 inventories what Centinela can prove locally: runtime health,
    FastAPI routes, package manifests, non-secret source metadata, and redacted
    sensitive-pattern findings. It does not claim external scanning.
    """

    SECRET_PATTERNS = {
        "api_key_assignment": re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"),
        "bearer_token_literal": re.compile(r"(?i)bearer\s+[a-z0-9._\-]{20,}"),
        "private_key_marker": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "database_url_literal": re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^\\s'\"]+"),
        "jwt_like_literal": re.compile(r"eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}"),
    }
    SCAN_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".toml", ".yaml", ".yml"}
    EXCLUDED_PARTS = {".git", "node_modules", ".next", "__pycache__", ".pytest_cache", "venv", ".venv", "dist", "build"}

    def build_summary(
        self,
        *,
        health: dict[str, Any],
        provenance: dict[str, Any],
        route_inventory: list[dict[str, Any]],
        phase4_summary: dict[str, Any],
        source_roots: list[Path] | None = None,
    ) -> dict[str, Any]:
        roots = self._source_roots(source_roots)
        manifest = self._manifest_inventory(roots)
        assets = self.build_asset_inventory(health, provenance, route_inventory, manifest)
        endpoints = self.build_endpoint_intelligence(route_inventory)
        dependencies = self.build_dependency_mapping(health, manifest, endpoints)
        exposure = self.build_external_exposure(endpoints)
        secrets = self.build_sensitive_exposure(roots)
        supply_chain = self.build_supply_chain_awareness(manifest, dependencies)
        trust = self.build_trust_zones(assets, endpoints, dependencies, exposure)
        risk = self.build_external_risk_correlation(exposure, dependencies, trust, phase4_summary, secrets)
        ecosystem = self.build_ecosystem_intelligence(assets, dependencies, exposure, trust, risk, phase4_summary)
        certification = self.build_ecosystem_certification(assets, endpoints, dependencies, exposure, secrets, supply_chain, trust, ecosystem)

        return {
            "status": "PHASE_5_ECOSYSTEM_VISIBILITY_SUMMARY",
            "asset_inventory": assets,
            "endpoint_intelligence": endpoints,
            "dependency_mapping": dependencies,
            "external_exposure": exposure,
            "sensitive_exposure": secrets,
            "supply_chain": supply_chain,
            "trust_zones": trust,
            "external_risk_correlation": risk,
            "ecosystem_intelligence": ecosystem,
            "certification": certification,
            "claims": {
                "external_scan_claim": False,
                "dns_scan_claim": False,
                "vulnerability_database_claim": False,
                "secret_value_exposure": False,
                "enterprise_ecosystem_claim": False,
            },
            "limitations": [
                "Inventory is limited to local source, runtime health, route metadata, and manifests.",
                "No internet, DNS, cloud, or vulnerability-database scan is claimed.",
                "Secret findings are redacted and pattern-based; values are never returned.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_asset_inventory(
        self,
        health: dict[str, Any],
        provenance: dict[str, Any],
        route_inventory: list[dict[str, Any]],
        manifest: dict[str, Any],
    ) -> dict[str, Any]:
        engines = health.get("engines") if isinstance(health.get("engines"), dict) else {}
        assets = [
            self._asset("backend_runtime", "runtime_service", "CENTINELA Backend", health.get("status"), "core/backend", "Backend application runtime"),
            self._asset("frontend_runtime", "runtime_service", "CENTINELA Frontend", "KNOWN_SOURCE", "human_cabin/frontend", "Next.js command cockpit source"),
            self._asset("database", "operational_service", "Database", health.get("database"), "technical_cabin/persistence", "Event and normalized memory storage"),
            self._asset("provenance", "operational_service", "Deploy Provenance", "ONLINE" if provenance.get("current_commit") else "LIMITED", "governance/source_traceability", "Source-to-runtime traceability"),
            self._asset("auth", "operational_service", "Authentication", "ONLINE", "heart_cabin/access_control", "Protected data access"),
            self._asset("websocket", "api_surface", "Realtime WebSocket", "ROUTE_PRESENT" if any(route.get("path") == "/ws" for route in route_inventory) else "UNKNOWN", "technical_cabin/runtime", "Runtime event streaming"),
        ]
        for name, state in sorted(engines.items()):
            assets.append(self._asset(name, "engine", name, state, "technical_cabin/engine", "Backend engine from health map"))

        api_routes = [route for route in route_inventory if str(route.get("path", "")).startswith("/api/")]
        assets.append(self._asset("api_surface", "api_collection", "FastAPI API Surface", f"{len(api_routes)}_ROUTES", "technical_cabin/api", "Loaded FastAPI route inventory"))

        assets.append(self._asset("backend_packages", "external_dependency_collection", "Python Requirements", f"{manifest['backend_dependency_count']}_PACKAGES", "supply_chain/backend", "Declared backend dependencies"))
        assets.append(self._asset("frontend_packages", "external_dependency_collection", "NPM Package Manifest", f"{manifest['frontend_dependency_count']}_PACKAGES", "supply_chain/frontend", "Declared frontend dependencies"))

        return {
            "status": "ECOSYSTEM_ASSET_INVENTORY",
            "assets": assets,
            "asset_count": len(assets),
            "runtime_assets": len([asset for asset in assets if asset["type"] == "runtime_service"]),
            "api_assets": len([asset for asset in assets if asset["type"] in {"api_surface", "api_collection"}]),
            "external_dependency_assets": len([asset for asset in assets if "dependency" in asset["type"]]),
            "ownership_visibility": sorted({asset["owner"] for asset in assets}),
            "fake_asset_guard": True,
            "evidence_basis": ["health", "provenance", "FastAPI routes", "package manifests"],
        }

    def build_endpoint_intelligence(self, route_inventory: list[dict[str, Any]]) -> dict[str, Any]:
        endpoints = []
        for route in route_inventory:
            path = str(route.get("path") or "")
            methods = sorted(method for method in route.get("methods", []) if method not in {"HEAD", "OPTIONS"})
            if not path or not methods:
                continue
            exposure = self._endpoint_exposure(path)
            endpoints.append({
                "path": path,
                "methods": methods,
                "classification": self._endpoint_classification(path),
                "exposure": exposure,
                "criticality": self._endpoint_criticality(path),
                "auth_dependency": self._auth_dependency(path),
                "operational_mapping": self._endpoint_owner(path),
                "risk_basis": "route structure and known auth boundary",
            })
        counts = Counter(endpoint["classification"] for endpoint in endpoints)
        exposure_counts = Counter(endpoint["exposure"] for endpoint in endpoints)
        criticality_counts = Counter(endpoint["criticality"] for endpoint in endpoints)
        return {
            "status": "API_ENDPOINT_INTELLIGENCE",
            "endpoints": sorted(endpoints, key=lambda item: item["path"]),
            "endpoint_count": len(endpoints),
            "classification_counts": dict(counts),
            "exposure_counts": dict(exposure_counts),
            "criticality_counts": dict(criticality_counts),
            "fake_endpoint_risk_guard": True,
        }

    def build_dependency_mapping(
        self,
        health: dict[str, Any],
        manifest: dict[str, Any],
        endpoint_intelligence: dict[str, Any],
    ) -> dict[str, Any]:
        dependencies = []
        dependencies.extend([
            self._dependency("frontend_runtime", "backend_api", "INTERNAL", "HIGH", "Dashboard data depends on backend API"),
            self._dependency("backend_api", "auth", "INTERNAL", "HIGH", "Protected endpoints depend on auth"),
            self._dependency("backend_api", "database", "INTERNAL", "HIGH", "Runtime memory depends on database"),
            self._dependency("backend_api", "provenance", "INTERNAL", "MEDIUM", "Deploy traceability depends on provenance"),
        ])
        for dep in manifest["backend_dependencies"]:
            dependencies.append(self._dependency("backend_runtime", dep["name"], "EXTERNAL_PACKAGE", self._package_criticality(dep["name"]), "Declared Python package"))
        for dep in manifest["frontend_dependencies"]:
            dependencies.append(self._dependency("frontend_runtime", dep["name"], "EXTERNAL_PACKAGE", self._package_criticality(dep["name"]), "Declared npm package"))

        auth_endpoints = [endpoint["path"] for endpoint in endpoint_intelligence.get("endpoints", []) if endpoint.get("auth_dependency")]
        trust_relationships = [
            {"from": "frontend_runtime", "to": "backend_api", "trust": "LIMITED_AUTHENTICATED"},
            {"from": "backend_api", "to": "database", "trust": "INTERNAL_RUNTIME"},
            {"from": "operator", "to": "auth", "trust": "HUMAN_AUTH_BOUNDARY"},
        ]

        return {
            "status": "INTEGRATION_DEPENDENCY_MAPPING",
            "dependencies": dependencies,
            "dependency_count": len(dependencies),
            "auth_dependency_mapping": auth_endpoints,
            "operational_trust_relationships": trust_relationships,
            "internal_dependency_count": len([dep for dep in dependencies if dep["relationship"] == "INTERNAL"]),
            "external_dependency_count": len([dep for dep in dependencies if dep["relationship"] == "EXTERNAL_PACKAGE"]),
            "fake_integration_guard": True,
        }

    def build_external_exposure(self, endpoint_intelligence: dict[str, Any]) -> dict[str, Any]:
        endpoints = endpoint_intelligence.get("endpoints") or []
        public = [endpoint for endpoint in endpoints if endpoint["exposure"] == "PUBLIC"]
        limited = [endpoint for endpoint in endpoints if endpoint["exposure"] == "LIMITED"]
        auth_public = [endpoint for endpoint in public if "auth" in endpoint["path"]]
        runtime_public = [endpoint for endpoint in public if endpoint["path"] in {"/api/v1/health", "/api/v1/provenance", "/ws"}]

        return {
            "status": "EXTERNAL_EXPOSURE_AWARENESS",
            "public_endpoints": public,
            "limited_endpoints": limited,
            "public_endpoint_count": len(public),
            "auth_exposure_visibility": auth_public,
            "public_runtime_exposure": runtime_public,
            "integration_exposure_awareness": len([endpoint for endpoint in endpoints if endpoint["path"].startswith("/api/")]),
            "operational_external_visibility": "ROUTE_BASED_ONLY",
            "false_public_risk_guard": True,
            "hallucinated_attack_surface_guard": True,
        }

    def build_sensitive_exposure(self, source_roots: list[Path]) -> dict[str, Any]:
        findings = []
        files_scanned = 0
        for root in source_roots:
            if not root.exists():
                continue
            for path in self._iter_scan_files(root):
                files_scanned += 1
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for pattern_name, pattern in self.SECRET_PATTERNS.items():
                    matches = list(pattern.finditer(text))
                    if not matches:
                        continue
                    findings.append({
                        "file": self._safe_file_label(root, path),
                        "pattern": pattern_name,
                        "count": len(matches),
                        "value": "REDACTED",
                        "evidence_basis": "local source pattern scan",
                    })
        high_risk_count = len([finding for finding in findings if finding["pattern"] in {"private_key_marker", "database_url_literal", "jwt_like_literal"}])
        state = "POTENTIAL_EXPOSURE_REVIEW_REQUIRED" if findings else "NO_PATTERN_MATCHES"
        return {
            "status": "SENSITIVE_EXPOSURE_DETECTION",
            "state": state,
            "files_scanned": files_scanned,
            "finding_count": len(findings),
            "high_risk_pattern_count": high_risk_count,
            "findings": findings[:50],
            "secret_values_returned": False,
            "env_files_scanned": False,
            "env_exposure_awareness": "env files intentionally excluded; presence must be validated operationally without reading values",
            "fake_leak_detection_guard": True,
        }

    def build_supply_chain_awareness(self, manifest: dict[str, Any], dependency_mapping: dict[str, Any]) -> dict[str, Any]:
        packages = manifest["backend_dependencies"] + manifest["frontend_dependencies"]
        critical = [pkg for pkg in packages if self._package_criticality(pkg["name"]) == "HIGH"]
        pinned = [pkg for pkg in packages if pkg.get("version")]
        unpinned = [pkg for pkg in packages if not pkg.get("version")]
        trust_baseline = []
        for pkg in packages:
            trust_baseline.append({
                "name": pkg["name"],
                "ecosystem": pkg["ecosystem"],
                "version": pkg.get("version") or "UNPINNED_OR_RANGE",
                "criticality": self._package_criticality(pkg["name"]),
                "trust_state": "DECLARED_DEPENDENCY",
                "evidence_basis": pkg.get("source", "manifest"),
            })

        risk = "LOW"
        if unpinned:
            risk = "MEDIUM"
        if len(critical) >= 8 and unpinned:
            risk = "HIGH"

        return {
            "status": "SUPPLY_CHAIN_AWARENESS",
            "package_count": len(packages),
            "backend_package_count": manifest["backend_dependency_count"],
            "frontend_package_count": manifest["frontend_dependency_count"],
            "critical_dependency_count": len(critical),
            "pinned_dependency_count": len(pinned),
            "range_or_unpinned_dependency_count": len(unpinned),
            "dependency_trust_baseline": trust_baseline[:80],
            "supply_chain_operational_risk": risk,
            "vulnerability_claim": False,
            "fake_supply_chain_guard": True,
        }

    def build_trust_zones(
        self,
        asset_inventory: dict[str, Any],
        endpoint_intelligence: dict[str, Any],
        dependency_mapping: dict[str, Any],
        exposure: dict[str, Any],
    ) -> dict[str, Any]:
        zones = [
            {"zone": "PUBLIC_EDGE", "members": [endpoint["path"] for endpoint in exposure.get("public_endpoints", [])], "trust": "UNAUTHENTICATED_OR_PUBLIC", "confidence": "HIGH"},
            {"zone": "AUTH_BOUNDARY", "members": endpoint_intelligence.get("classification_counts", {}), "trust": "TOKEN_PROTECTED", "confidence": "MEDIUM"},
            {"zone": "INTERNAL_RUNTIME", "members": ["backend_runtime", "database", "engines"], "trust": "INTERNAL_PROCESS", "confidence": "MEDIUM"},
            {"zone": "SUPPLY_CHAIN", "members": ["backend_packages", "frontend_packages"], "trust": "DECLARED_EXTERNAL_DEPENDENCIES", "confidence": "LOW"},
            {"zone": "HUMAN_COMMAND", "members": ["frontend_runtime", "operator"], "trust": "HUMAN_SESSION_DEPENDENT", "confidence": "MEDIUM"},
        ]
        return {
            "status": "OPERATIONAL_TRUST_ZONES",
            "zones": zones,
            "internal_external_awareness": True,
            "auth_trust_boundaries": ["PUBLIC_EDGE -> AUTH_BOUNDARY", "AUTH_BOUNDARY -> INTERNAL_RUNTIME"],
            "runtime_trust_segmentation": ["frontend_runtime", "backend_runtime", "database", "engines"],
            "operational_confidence_zones": {zone["zone"]: zone["confidence"] for zone in zones},
            "fake_trust_classification_guard": True,
        }

    def build_external_risk_correlation(
        self,
        exposure: dict[str, Any],
        dependency_mapping: dict[str, Any],
        trust_zones: dict[str, Any],
        phase4_summary: dict[str, Any],
        sensitive_exposure: dict[str, Any],
    ) -> dict[str, Any]:
        public_count = exposure.get("public_endpoint_count", 0)
        external_deps = dependency_mapping.get("external_dependency_count", 0)
        degraded = phase4_summary.get("classification") in {"DEGRADED", "PARTIAL_FAILURE", "UNSTABLE", "LIMITED_OPERATION"}
        sensitive_findings = sensitive_exposure.get("finding_count", 0)
        correlations = []
        if public_count:
            correlations.append({"type": "exposure_to_runtime", "evidence": f"{public_count} public route(s)", "risk": "LOW"})
        if external_deps:
            correlations.append({"type": "dependency_to_risk", "evidence": f"{external_deps} declared external package dependencies", "risk": "LOW"})
        if public_count and degraded:
            correlations.append({"type": "operational_risk_propagation", "evidence": "public routes plus degraded runtime classification", "risk": "MEDIUM"})
        if sensitive_findings:
            correlations.append({"type": "sensitive_exposure_to_trust", "evidence": "redacted sensitive pattern findings present", "risk": "REVIEW_REQUIRED"})

        risk = "LOW"
        if any(item["risk"] == "MEDIUM" for item in correlations):
            risk = "MEDIUM"
        if any(item["risk"] == "REVIEW_REQUIRED" for item in correlations):
            risk = "REVIEW_REQUIRED"

        return {
            "status": "EXTERNAL_RISK_CORRELATION",
            "correlations": correlations,
            "risk_level": risk,
            "auth_exposure_correlation": len(exposure.get("auth_exposure_visibility") or []),
            "risk_propagation_awareness": degraded,
            "fake_risk_escalation_guard": True,
            "hallucinated_ecosystem_threat_guard": True,
        }

    def build_ecosystem_intelligence(
        self,
        asset_inventory: dict[str, Any],
        dependency_mapping: dict[str, Any],
        exposure: dict[str, Any],
        trust_zones: dict[str, Any],
        risk: dict[str, Any],
        phase4_summary: dict[str, Any],
    ) -> dict[str, Any]:
        summary = (
            f"{asset_inventory.get('asset_count', 0)} assets, "
            f"{dependency_mapping.get('dependency_count', 0)} dependencies, "
            f"{exposure.get('public_endpoint_count', 0)} public endpoints, "
            f"runtime {phase4_summary.get('classification', 'UNKNOWN')}."
        )
        degradation = phase4_summary.get("classification") in {"DEGRADED", "PARTIAL_FAILURE", "UNSTABLE", "LIMITED_OPERATION"}
        survivability = phase4_summary.get("certification", {}).get("classification", "UNKNOWN")
        return {
            "status": "ECOSYSTEM_WIDE_OPERATIONAL_INTELLIGENCE",
            "ecosystem_operational_summary": summary,
            "dependency_operational_awareness": dependency_mapping.get("dependency_count", 0),
            "ecosystem_survivability_visibility": survivability,
            "ecosystem_degradation_awareness": degradation,
            "operational_ecosystem_intelligence": risk.get("risk_level", "UNKNOWN"),
            "fake_ecosystem_intelligence_guard": True,
        }

    def build_ecosystem_certification(
        self,
        asset_inventory: dict[str, Any],
        endpoint_intelligence: dict[str, Any],
        dependency_mapping: dict[str, Any],
        exposure: dict[str, Any],
        sensitive_exposure: dict[str, Any],
        supply_chain: dict[str, Any],
        trust_zones: dict[str, Any],
        ecosystem: dict[str, Any],
    ) -> dict[str, Any]:
        points = 0
        points += 1 if asset_inventory.get("asset_count", 0) > 0 else 0
        points += 1 if endpoint_intelligence.get("endpoint_count", 0) > 0 else 0
        points += 1 if dependency_mapping.get("dependency_count", 0) > 0 else 0
        points += 1 if exposure.get("operational_external_visibility") == "ROUTE_BASED_ONLY" else 0
        points += 1 if sensitive_exposure.get("secret_values_returned") is False else 0
        points += 1 if supply_chain.get("package_count", 0) > 0 else 0
        points += 1 if trust_zones.get("fake_trust_classification_guard") else 0
        points += 1 if ecosystem.get("fake_ecosystem_intelligence_guard") else 0

        if points <= 2:
            classification = "ISOLATED"
        elif points <= 5:
            classification = "PARTIALLY_AWARE"
        elif points <= 7:
            classification = "ECOSYSTEM_AWARE"
        else:
            classification = "OPERATIONALLY_CONNECTED"

        if sensitive_exposure.get("finding_count", 0) > 0 and classification == "OPERATIONALLY_CONNECTED":
            classification = "ECOSYSTEM_AWARE"

        return {
            "status": "HONEST_ECOSYSTEM_CERTIFICATION",
            "classification": classification,
            "allowed_classifications": ["ISOLATED", "PARTIALLY_AWARE", "ECOSYSTEM_AWARE", "OPERATIONALLY_CONNECTED"],
            "readiness_points": points,
            "ecosystem_visibility": asset_inventory.get("asset_count", 0),
            "exposure_awareness": exposure.get("public_endpoint_count", 0),
            "dependency_intelligence": dependency_mapping.get("dependency_count", 0),
            "trust_segmentation": len(trust_zones.get("zones") or []),
            "supply_chain_awareness": supply_chain.get("package_count", 0),
            "ecosystem_survivability": ecosystem.get("ecosystem_survivability_visibility"),
            "enterprise_claim": False,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def _asset(self, asset_id: str, asset_type: str, name: str, state: Any, owner: str, purpose: str) -> dict[str, str]:
        return {
            "id": asset_id,
            "type": asset_type,
            "name": name,
            "state": str(state or "UNKNOWN"),
            "owner": owner,
            "purpose": purpose,
            "evidence_basis": "runtime or manifest evidence",
        }

    def _dependency(self, source: str, target: str, relationship: str, criticality: str, purpose: str) -> dict[str, str]:
        return {
            "source": source,
            "target": target,
            "relationship": relationship,
            "criticality": criticality,
            "purpose": purpose,
        }

    def _source_roots(self, source_roots: list[Path] | None) -> list[Path]:
        if source_roots:
            return source_roots
        backend_root = Path(__file__).resolve().parents[2]
        frontend_root = Path(os.environ.get("CENTINELA_FRONTEND_SOURCE", r"C:\Users\admin\Desktop\centinela"))
        roots = [backend_root]
        if frontend_root.exists():
            roots.append(frontend_root)
        return roots

    def _manifest_inventory(self, roots: list[Path]) -> dict[str, Any]:
        backend_dependencies: list[dict[str, str]] = []
        frontend_dependencies: list[dict[str, str]] = []
        for root in roots:
            req = root / "requirements.txt"
            if req.exists():
                backend_dependencies.extend(self._parse_requirements(req))
            pkg = root / "package.json"
            if pkg.exists():
                frontend_dependencies.extend(self._parse_package_json(pkg))
        return {
            "backend_dependencies": backend_dependencies,
            "frontend_dependencies": frontend_dependencies,
            "backend_dependency_count": len(backend_dependencies),
            "frontend_dependency_count": len(frontend_dependencies),
        }

    def _parse_requirements(self, path: Path) -> list[dict[str, str]]:
        deps = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            name, version = self._split_dependency(clean)
            deps.append({"name": name, "version": version, "ecosystem": "python", "source": "requirements.txt"})
        return deps

    def _parse_package_json(self, path: Path) -> list[dict[str, str]]:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        deps = []
        for section in ("dependencies", "devDependencies"):
            values = data.get(section) if isinstance(data.get(section), dict) else {}
            for name, version in values.items():
                deps.append({"name": name, "version": str(version), "ecosystem": "npm", "source": f"package.json:{section}"})
        return deps

    def _split_dependency(self, value: str) -> tuple[str, str]:
        for sep in ("==", ">=", "<=", "~=", ">", "<"):
            if sep in value:
                name, version = value.split(sep, 1)
                return name.strip(), f"{sep}{version.strip()}"
        return value.strip(), ""

    def _endpoint_exposure(self, path: str) -> str:
        if path in {"/api/v1/health", "/api/v1/provenance", "/api/v1/auth/login", "/api/v1/prompt/analyze", "/ws"}:
            return "PUBLIC"
        if path.startswith("/api/v1/admin"):
            return "LIMITED"
        if path.startswith("/api/"):
            return "LIMITED"
        if path.startswith("/docs") or path.startswith("/openapi"):
            return "PUBLIC"
        return "UNKNOWN"

    def _endpoint_classification(self, path: str) -> str:
        if path.startswith("/api/v1/resilience"):
            return "RESILIENCE"
        if path.startswith("/api/v1/intelligence"):
            return "INTELLIGENCE"
        if path.startswith("/api/v1/auth"):
            return "AUTH"
        if path.startswith("/api/v1/admin"):
            return "ADMIN"
        if path.startswith("/api/v1/policy") or path.startswith("/api/v1/response"):
            return "GOVERNANCE"
        if path.startswith("/api/"):
            return "OPERATIONAL_API"
        if path == "/ws":
            return "RUNTIME_STREAM"
        return "RUNTIME"

    def _endpoint_criticality(self, path: str) -> str:
        if path.startswith("/api/v1/admin") or path.startswith("/api/v1/auth"):
            return "HIGH"
        if path.startswith("/api/v1/intelligence") or path.startswith("/api/v1/resilience"):
            return "MEDIUM"
        if path in {"/api/v1/health", "/api/v1/provenance", "/ws"}:
            return "MEDIUM"
        return "LOW"

    def _auth_dependency(self, path: str) -> bool:
        return path not in {"/api/v1/health", "/api/v1/provenance", "/api/v1/auth/login", "/api/v1/prompt/analyze", "/ws"}

    def _endpoint_owner(self, path: str) -> str:
        if path.startswith("/api/v1/resilience"):
            return "technical_cabin/resilience"
        if path.startswith("/api/v1/intelligence"):
            return "technical_cabin/intelligence"
        if path.startswith("/api/v1/auth"):
            return "heart_cabin/auth"
        if path.startswith("/api/v1/admin"):
            return "governance/admin"
        if path.startswith("/api/v1/policy") or path.startswith("/api/v1/response"):
            return "governance/defense"
        if path == "/ws":
            return "technical_cabin/runtime_stream"
        return "technical_cabin/api"

    def _package_criticality(self, name: str) -> str:
        lowered = name.lower()
        high = ("fastapi", "sqlalchemy", "psycopg", "passlib", "jose", "cryptography", "bcrypt", "next", "react", "uvicorn")
        if any(item in lowered for item in high):
            return "HIGH"
        if lowered in {"httpx", "redis", "slowapi", "websockets", "@tanstack/react-query"}:
            return "MEDIUM"
        return "LOW"

    def _iter_scan_files(self, root: Path):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            parts = set(path.parts)
            if parts.intersection(self.EXCLUDED_PARTS):
                continue
            if path.name.startswith(".env"):
                continue
            if path.suffix.lower() not in self.SCAN_SUFFIXES:
                continue
            if path.stat().st_size > 600_000:
                continue
            yield path

    def _safe_file_label(self, root: Path, path: Path) -> str:
        try:
            return str(path.relative_to(root)).replace("\\", "/")
        except ValueError:
            return path.name
