"""
PRISM -- Flask + SocketIO Dashboard
Real-time WebSocket-driven scan with credential input and live terminal streaming.
"""

import gc
import json as _json
import pathlib as _pathlib
import os
import re
import secrets
import threading
from datetime import datetime
from typing import Any, Optional

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from loguru import logger

# ── Module imports (lazy to avoid circular) ──────────────────────────────
socketio = SocketIO()

# Global scan state
_scan_results: dict[str, Any] = {}
_scan_running: bool = False


# ============================================================================
#  RESULT PERSISTENCE  (credentials NEVER saved -- analysis data only)
# ============================================================================

_CACHE_PATH = _pathlib.Path(__file__).parent.parent.parent / "prism_cache.json"

# Keys that must never be written to disk
_UNSAFE_KEYS = {
    "_collector", "access_key", "secret_key",
    "aws_access_key_id", "aws_secret_access_key",
}


def _save_results() -> None:
    """Persist sanitized scan results to prism_cache.json."""
    global _scan_results
    try:
        safe = {
            k: v for k, v in _scan_results.items()
            if k not in _UNSAFE_KEYS and isinstance(v, (dict, list, str, int, float, bool, type(None)))
        }
        with open(_CACHE_PATH, "w", encoding="utf-8") as fh:
            _json.dump(safe, fh, default=str)
        logger.info(f"Results cached to {_CACHE_PATH.name} ({_CACHE_PATH.stat().st_size // 1024} KB)")
    except Exception as e:
        logger.warning(f"Cache save failed: {e}")


def _load_results() -> None:
    """Load previous scan results from cache on startup."""
    global _scan_results
    if not _CACHE_PATH.exists():
        return
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as fh:
            cached = _json.load(fh)
        if cached.get("scan_status") == "complete":
            _scan_results.update(cached)
            logger.info(
                f"Loaded cached results from {_CACHE_PATH.name} "
                f"(scan from {cached.get('timestamp', 'unknown')})"
            )
        else:
            logger.info("Cache found but scan was not complete -- skipping load")
    except Exception as e:
        logger.warning(f"Cache load failed: {e}")


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = os.environ.get("PRISM_SECRET", secrets.token_hex(32))

    socketio.init_app(app, cors_allowed_origins="*", async_mode="threading")

    # ── Routes ───────────────────────────────────────────────────────────

    @app.route("/")
    def index() -> str:
        """Serve the main dashboard page."""
        return render_template("index.html")

    @app.route("/api/results")
    def api_results() -> Any:
        """Return complete scan results JSON."""
        safe: dict = {}
        for k, v in _scan_results.items():
            if k in ("_collector",):
                continue
            try:
                safe[k] = v if isinstance(v, (list, dict, str, int, float, bool, type(None))) else str(v)
            except Exception:
                safe[k] = str(v)
        return jsonify(_sanitize_for_frontend(safe))

    @app.route("/api/graph")
    def api_graph() -> Any:
        """Return graph data for the attack graph visualization."""
        graph_data = _scan_results.get("attack_graph")
        if not graph_data or not graph_data.get("nodes"):
            graph_data = _build_graph_data()
        return jsonify(graph_data)

    @app.route("/api/shadow-admins")
    def api_shadow_admins() -> Any:
        return jsonify(_scan_results.get("shadow_admin_findings", []))

    @app.route("/api/privesc-paths")
    def api_privesc_paths() -> Any:
        return jsonify({
            "findings": _scan_results.get("privesc_findings", []),
            "summary": _scan_results.get("privesc_summary", {}),
        })

    @app.route("/api/ghost-identities")
    def api_ghost_identities() -> Any:
        return jsonify(_scan_results.get("ghost_identities", []))

    @app.route("/api/permission-entropy")
    def api_permission_entropy() -> Any:
        return jsonify(_scan_results.get("permission_entropy", {}))

    @app.route("/api/kill-chain")
    def api_kill_chain() -> Any:
        return jsonify(_scan_results.get("kill_chain", {}))

    @app.route("/api/blast-radius")
    def api_blast_radius() -> Any:
        return jsonify(_scan_results.get("blast_radius", []))

    @app.route("/api/attack-narrative")
    def api_attack_narrative() -> Any:
        return jsonify(_scan_results.get("attack_narrative", {}))

    @app.route("/api/policy-fingerprints")
    def api_policy_fingerprints() -> Any:
        return jsonify(_scan_results.get("policy_fingerprints", {}))

    @app.route("/api/network-exposure")
    def api_network_exposure() -> Any:
        return jsonify(_scan_results.get("network_findings", []))

    @app.route("/api/credential-health")
    def api_credential_health() -> Any:
        return jsonify({
            "findings": _scan_results.get("credential_findings", []),
            "stats": _scan_results.get("credential_stats", {}),
        })

    @app.route("/api/mitre-heatmap")
    def api_mitre_heatmap() -> Any:
        return jsonify(_build_mitre_heatmap())

    @app.route("/api/report-data")
    def api_report_data() -> Any:
        return jsonify(_build_report_data())


    # ── Offensive Operations -- Live Computation APIs ─────────────────────
    # These compute fresh results from cached IAM data on every request.
    # No separate scan phase needed -- works immediately after any scan.



    # ── Offensive Operations: live-computation APIs ───────────────────────
    @app.route("/api/mvc")
    def api_mvc() -> Any:
        cached = _scan_results.get("mvc_analysis")
        if cached and isinstance(cached.get("paths"), list):
            return jsonify(cached)
        iam = _scan_results.get("iam_action_map", {})
        if not iam:
            return jsonify({"error": "no_scan"})
        try:
            from src.offensive.mvc_engine import MVCEngine
            result = MVCEngine().analyze(
                iam,
                _scan_results.get("trusts", []),
                _scan_results.get("admin_roles", []),
                _scan_results.get("shadow_admin_findings", []),
                _scan_results.get("privesc_findings", []),
            )
            _scan_results["mvc_analysis"] = result
            return jsonify(result)
        except Exception as exc:
            logger.warning(f"MVC compute: {exc}")
            return jsonify({"error": str(exc)})

    @app.route("/api/assumed-breach/identities")
    def api_breach_identities() -> Any:
        return jsonify(sorted(_scan_results.get("iam_action_map", {}).keys()))

    @app.route("/api/assumed-breach")
    def api_assumed_breach() -> Any:
        identity = request.args.get("identity", "").strip()
        iam = _scan_results.get("iam_action_map", {})
        if not iam:
            return jsonify({"error": "no_scan"})
        if not identity:
            return jsonify({"error": "no_identity"})
        try:
            from src.offensive.assumed_breach import AssumedBreachSimulator
            return jsonify(AssumedBreachSimulator().simulate(
                identity, iam, _scan_results.get("trusts", []), _scan_results))
        except Exception as exc:
            logger.warning(f"AssumedBreach compute: {exc}")
            return jsonify({"error": str(exc)})

    @app.route("/api/ransomware")
    def api_ransomware() -> Any:
        cached = _scan_results.get("ransomware_analysis")
        if cached and cached.get("risk_rating"):
            return jsonify(cached)
        iam = _scan_results.get("iam_action_map", {})
        if not iam:
            return jsonify({"error": "no_scan"})
        try:
            from src.offensive.ransomware_detector import RansomwareDetector
            buckets = _scan_results.get("s3_buckets", [])
            collector = _scan_results.get("_collector")
            if collector:
                buckets = [{**b, **collector.get_s3_bucket_details(b.get("Name",""))} for b in buckets]
            result = RansomwareDetector().analyze(buckets, iam, _scan_results)
            _scan_results["ransomware_analysis"] = result
            return jsonify(result)
        except Exception as exc:
            logger.warning(f"Ransomware compute: {exc}")
            return jsonify({"error": str(exc)})

    @app.route("/api/supply-chain")
    def api_supply_chain() -> Any:
        cached = _scan_results.get("supply_chain_analysis")
        if cached and isinstance(cached.get("findings"), list):
            return jsonify(cached)
        iam = _scan_results.get("iam_action_map", {})
        if not iam:
            return jsonify({"error": "no_scan"})
        collector = _scan_results.get("_collector")
        if not collector:
            return jsonify({"error": "No active session. Deep supply chain analysis requires a live scan collector."})
        try:
            from src.offensive.supply_chain_mapper import SupplyChainMapper
            result = SupplyChainMapper().analyze(
                collector, _scan_results.get("lambda_functions", []), iam)
            _scan_results["supply_chain_analysis"] = result
            return jsonify(result)
        except Exception as exc:
            logger.warning(f"SupplyChain compute: {exc}")
            return jsonify({"error": str(exc)})

    @app.route("/api/golden-saml")
    def api_golden_saml() -> Any:
        cached = _scan_results.get("golden_saml_analysis")
        if cached and isinstance(cached.get("findings"), list):
            return jsonify(cached)
        iam = _scan_results.get("iam_action_map", {})
        if not iam:
            return jsonify({"error": "no_scan"})
        try:
            from src.offensive.golden_saml_detector import GoldenSAMLDetector
            detector = GoldenSAMLDetector()
            modifier_findings = detector._modifiers(iam)
            collector = _scan_results.get("_collector")
            if collector:
                all_findings = detector._saml(collector) + detector._fed_roles(collector, iam) + modifier_findings
            else:
                all_findings = modifier_findings
            result = {
                "findings": all_findings,
                "total_findings": len(all_findings),
                "critical_count": sum(1 for f in all_findings if f.get("severity")=="CRITICAL"),
                "high_count": sum(1 for f in all_findings if f.get("severity")=="HIGH"),
                "saml_findings": [f for f in all_findings if "SAML_HIGH" in f.get("type","")],
                "role_findings": [f for f in all_findings if "UNSCOPED" in f.get("type","")],
                "modifier_findings": modifier_findings,
                "overall_risk": "CRITICAL" if any(f["severity"]=="CRITICAL" for f in all_findings) else ("HIGH" if all_findings else "LOW"),
                "mitre": "T1606.002",
                "real_world_ref": "SolarWinds UNC2452 Golden SAML attack (December 2020)",
                "technique_summary": (
                    "Golden SAML allows an attacker who compromises an Identity Provider to forge "
                    "SAML assertions for ANY user, bypassing all MFA requirements. "
                    "This technique was used in the SolarWinds nation-state breach."
                ),
            }
            _scan_results["golden_saml_analysis"] = result
            return jsonify(result)
        except Exception as exc:
            logger.warning(f"GoldenSAML compute: {exc}")
            return jsonify({"error": str(exc)})

    @app.route("/api/download-pdf")
    def api_download_pdf() -> Any:
        """Generate and return PDF report."""
        from src.report.pdf_engine import PDFReportEngine
        report_data = _build_report_data()
        engine = PDFReportEngine()
        pdf_bytes = engine.generate(report_data)
        from flask import Response
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment;filename=PRISM_Security_Report.pdf"},
        )

    # ── WebSocket Events ─────────────────────────────────────────────────

    @socketio.on("scan_start")
    def handle_scan_start(data: dict) -> None:
        """Handle scan start request with credentials."""
        global _scan_running
        if _scan_running:
            emit("scan_error", {"message": "A scan is already in progress."})
            return

        access_key = data.get("access_key", "").strip()
        secret_key = data.get("secret_key", "").strip()
        region = data.get("region", "us-east-1").strip()

        if not access_key or not secret_key:
            emit("scan_error", {"message": "AWS Access Key and Secret Key are required."})
            return

        _scan_running = True
        thread = threading.Thread(
            target=_run_scan,
            args=(access_key, secret_key, region),
            daemon=True,
        )
        thread.start()

    return app


# ═══════════════════════════════════════════════════════════════════════════
#  SCAN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════

def _emit_progress(phase: str, status: str, findings: int = 0, progress: int = 0) -> None:
    """Emit scan progress event to all connected clients."""
    socketio.emit("scan_progress", {
        "phase": phase,
        "status": status,
        "findings": findings,
        "progress": progress,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    })


def _emit_log(message: str) -> None:
    """Emit a terminal log line."""
    socketio.emit("scan_log", {
        "message": message,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    })


def _run_scan(access_key: str, secret_key: str, region: str) -> None:
    """Execute the full scan pipeline, emitting progress via WebSocket."""
    global _scan_results, _scan_running

    _scan_results = {
        "timestamp": datetime.now().isoformat(),
        "region": region,
        "scan_status": "running",
    }

    try:
        # ── Phase 0: Validate Credentials ────────────────────────────────
        _emit_log("Initializing AWS connection...")
        _emit_progress("Credential Validation", "running", progress=2)

        from src.collectors.aws_collector import AWSCollector
        collector = AWSCollector(access_key, secret_key, region)
        _scan_results["_collector"] = collector

        try:
            identity = collector.get_caller_identity()
            # Sanitize: store only safe fields, mask account ID
            safe_identity = {
                "Account": identity.get("Account", ""),
                "UserId": identity.get("UserId", ""),
                "UserName": identity.get("Arn", "").split("/")[-1] if "/" in identity.get("Arn", "") else "root",
            }
            _scan_results["caller_identity"] = safe_identity
            _emit_log(f"[+] Authenticated as: {safe_identity['UserName']}")
            _emit_progress("Credential Validation", "complete", progress=5)
        except Exception as e:
            _emit_log(f"[-] Authentication failed: {str(e)}")
            socketio.emit("scan_error", {"message": f"Authentication failed: {str(e)}"})
            _scan_running = False
            return

        account_id = identity["Account"]

        # ── Phase 1: IAM Collection ──────────────────────────────────────
        _emit_log("Collecting IAM users...")
        _emit_progress("IAM Collection", "running", progress=8)

        users = collector.get_users()
        roles = collector.get_roles()
        trusts = collector.get_trust_relationships()
        user_details = collector.get_user_details()
        role_details = collector.get_role_details()

        _scan_results["users"] = users
        _scan_results["roles"] = roles
        _scan_results["trusts"] = trusts
        _scan_results["user_details"] = user_details
        _scan_results["role_details"] = role_details

        _emit_log(f"[+] Enumerated {len(users)} IAM Users, {len(roles)} IAM Roles, {len(trusts)} Trust Relationships")
        _emit_progress("IAM Collection", "complete", findings=len(users) + len(roles), progress=15)

        # ── Phase 2: Build IAM Action Map ────────────────────────────────
        _emit_log("Building IAM permission map...")
        _emit_progress("Permission Mapping", "running", progress=18)

        iam_action_map = collector.build_iam_action_map(users, roles)
        _scan_results["iam_action_map"] = iam_action_map
        admin_roles = [r for r in roles if collector.has_admin_policy(r, is_user=False)]
        _scan_results["admin_roles"] = admin_roles

        _emit_log(f"[+] Mapped permissions for {len(iam_action_map)} identities, {len(admin_roles)} admin roles")
        _emit_progress("Permission Mapping", "complete", findings=len(iam_action_map), progress=25)

        # ── Phase 3: Collect Infrastructure ──────────────────────────────
        _emit_log("Collecting infrastructure data (EC2, S3, Lambda, Secrets, CloudTrail)...")
        _emit_progress("Infrastructure Collection", "running", progress=28)

        ec2_instances = collector.get_ec2_instances()
        security_groups = collector.get_security_groups()
        s3_buckets = collector.get_s3_buckets()
        lambda_functions = collector.get_lambda_functions()
        secrets = collector.get_secrets_list()
        ssm_params = collector.get_ssm_parameters()
        trails = collector.get_cloudtrail_status()
        access_key_metadata = collector.get_access_key_metadata(users)
        mfa_status = collector.get_user_mfa_status(users)

        _scan_results["ec2_instances"] = ec2_instances
        _scan_results["security_groups"] = security_groups
        _scan_results["s3_buckets"] = s3_buckets
        _scan_results["lambda_functions"] = lambda_functions
        _scan_results["secrets"] = secrets
        _scan_results["ssm_params"] = ssm_params
        _scan_results["trails"] = trails
        _scan_results["access_key_metadata"] = access_key_metadata
        _scan_results["mfa_status"] = mfa_status

        infra_count = len(ec2_instances) + len(s3_buckets) + len(lambda_functions) + len(secrets) + len(ssm_params)
        _emit_log(f"[+] Collected {infra_count} infrastructure resources")
        _emit_progress("Infrastructure Collection", "complete", findings=infra_count, progress=35)

        # ── Phase 4: Shadow Admin Detection ──────────────────────────────
        _emit_log("Enumerating shadow admin identities...")
        _emit_progress("Shadow Admin Detection", "running", progress=38)

        from src.analysis.iam_shadow_admin_detector import ShadowAdminDetector
        shadow_detector = ShadowAdminDetector()
        shadow_findings = shadow_detector.analyze(iam_action_map, admin_roles)
        _scan_results["shadow_admin_findings"] = shadow_findings

        _emit_log(f"[+] Identified {len(shadow_findings)} shadow admins")
        _emit_progress("Shadow Admin Detection", "complete", findings=len(shadow_findings), progress=42)

        # ── Phase 5: Privilege Escalation Paths ──────────────────────────
        _emit_log("Mapping privilege escalation paths (21 vectors)...")
        _emit_progress("Privilege Escalation Analysis", "running", progress=44)

        from src.analysis.privilege_escalation_paths import PrivescPathDetector
        pathfinder = PrivescPathDetector()
        privesc_result = pathfinder.analyze(iam_action_map, admin_roles)
        privesc_findings = privesc_result.get("findings", [])
        _scan_results["privesc_findings"] = privesc_findings
        _scan_results["privesc_summary"] = privesc_result.get("summary", {})

        _emit_log(f"[+] Mapped {len(privesc_findings)} privilege escalation paths")
        _emit_progress("Privilege Escalation Analysis", "complete", findings=len(privesc_findings), progress=48)

        # ── Phase 6: Network Exposure ────────────────────────────────────
        _emit_log("Analyzing network exposure...")
        _emit_progress("Network Exposure Analysis", "running", progress=50)

        from src.analysis.network_exposure_analyzer import NetworkExposureAnalyzer
        net_analyzer = NetworkExposureAnalyzer()
        # Collect S3 public access data
        s3_public_access = []
        for bucket in s3_buckets:
            bname = bucket.get("Name", "")
            try:
                bpa = collector.session.client("s3").get_public_access_block(Bucket=bname)
                s3_public_access.append({"BucketName": bname, **bpa})
            except Exception:
                s3_public_access.append({"BucketName": bname, "PublicAccessBlockConfiguration": {}})
        network_findings = net_analyzer.analyze(security_groups, s3_public_access)
        _scan_results["network_findings"] = network_findings

        _emit_log(f"[+] Found {len(network_findings)} network exposure issues")
        _emit_progress("Network Exposure Analysis", "complete", findings=len(network_findings), progress=53)

        # ── Phase 7: CloudTrail Evasion ──────────────────────────────────
        _emit_log("Probing CloudTrail evasion opportunities...")
        _emit_progress("CloudTrail Evasion Analysis", "running", progress=55)

        from src.analysis.cloudtrail_evasion_analyzer import CloudTrailEvasionAnalyzer
        ct_analyzer = CloudTrailEvasionAnalyzer()
        cloudtrail_findings = ct_analyzer.analyze(iam_action_map, trails)
        _scan_results["cloudtrail_findings"] = cloudtrail_findings

        _emit_log(f"[+] Found {len(cloudtrail_findings)} CloudTrail evasion vectors")
        _emit_progress("CloudTrail Evasion Analysis", "complete", findings=len(cloudtrail_findings), progress=58)

        # ── Phase 8: Lambda Backdoor Detection ───────────────────────────
        _emit_log("Scanning Lambda functions for backdoor risks...")
        _emit_progress("Lambda Backdoor Detection", "running", progress=60)

        from src.analysis.lambda_backdoor_detector import LambdaBackdoorDetector
        lambda_detector = LambdaBackdoorDetector()
        lambda_findings = lambda_detector.analyze(lambda_functions, iam_action_map, admin_roles)
        _scan_results["lambda_findings"] = lambda_findings

        _emit_log(f"[+] Found {len(lambda_findings)} Lambda backdoor vectors")
        _emit_progress("Lambda Backdoor Detection", "complete", findings=len(lambda_findings), progress=62)

        # ── Phase 9: Secrets Exfiltration ────────────────────────────────
        _emit_log("Mapping secrets exfiltration paths...")
        _emit_progress("Secrets Exfiltration Analysis", "running", progress=64)

        from src.analysis.secrets_exfil_detector import SecretsExfilDetector
        secrets_detector = SecretsExfilDetector()
        secrets_findings = secrets_detector.analyze(iam_action_map, secrets, ssm_params)
        _scan_results["secrets_findings"] = secrets_findings

        _emit_log(f"[+] Found {len(secrets_findings)} exfiltration paths")
        _emit_progress("Secrets Exfiltration Analysis", "complete", findings=len(secrets_findings), progress=66)

        # ── Phase 10: Cross-Account Analysis ─────────────────────────────
        _emit_log("Analyzing cross-account trust risks...")
        _emit_progress("Cross-Account Analysis", "running", progress=68)

        from src.analysis.cross_account_analyzer import CrossAccountAnalyzer
        cross_analyzer = CrossAccountAnalyzer(own_account_id=account_id)
        cross_findings = cross_analyzer.analyze(trusts, roles)
        _scan_results["cross_account_findings"] = cross_findings

        _emit_log(f"[+] Found {len(cross_findings)} cross-account risks")
        _emit_progress("Cross-Account Analysis", "complete", findings=len(cross_findings), progress=70)

        # ── Phase 11: Credential Age ─────────────────────────────────────
        _emit_log("Analyzing credential health...")
        _emit_progress("Credential Age Analysis", "running", progress=72)

        from src.analysis.credential_age_analyzer import CredentialAgeAnalyzer
        cred_analyzer = CredentialAgeAnalyzer()
        credential_findings = cred_analyzer.analyze(access_key_metadata, mfa_status)
        _scan_results["credential_findings"] = credential_findings
        _scan_results["credential_stats"] = cred_analyzer.get_stats()

        _emit_log(f"[+] Found {len(credential_findings)} credential issues")
        _emit_progress("Credential Age Analysis", "complete", findings=len(credential_findings), progress=74)

        # ── Phase 12: Collect Policies for Fingerprinting ────────────────
        _emit_log("Collecting IAM policies for analysis...")
        all_policies = collector.get_all_policies()
        _scan_results["all_policies"] = all_policies

        # ── Phase 13: Ghost Identity Detection (UNIQUE) ──────────────────
        _emit_log("Hunting ghost identities...")
        _emit_progress("Ghost Identity Detection", "running", progress=76)

        from src.unique.ghost_identity_detector import GhostIdentityDetector
        ghost_detector = GhostIdentityDetector(collector)
        ghost_identities = ghost_detector.detect(
            users=user_details,
            roles=role_details,
            shadow_admins=shadow_findings,
            iam_action_map=iam_action_map,
        )
        _scan_results["ghost_identities"] = ghost_identities

        _emit_log(f"[+] Found {len(ghost_identities)} ghost identities")
        _emit_progress("Ghost Identity Detection", "complete", findings=len(ghost_identities), progress=78)

        # ── Phase 14: Permission Entropy (UNIQUE) ────────────────────────
        _emit_log("Computing permission entropy...")
        _emit_progress("Permission Entropy Engine", "running", progress=80)

        from src.unique.permission_entropy_engine import PermissionEntropyEngine
        entropy_engine = PermissionEntropyEngine()
        entropy_result = entropy_engine.compute(iam_action_map)
        _scan_results["permission_entropy"] = entropy_result

        _emit_log(f"[+] IAM Chaos Score: {entropy_result.get('entropy_score', 0):.1f}/100 ({entropy_result.get('chaos_level', 'N/A')})")
        _emit_progress("Permission Entropy Engine", "complete", progress=82)

        # -- Phase 15: Policy Drift Fingerprinter (UNIQUE) ----------------
        _emit_log("Fingerprinting IAM policies against threat database...")
        _emit_progress("Policy Drift Fingerprinter", "running", progress=84)

        from src.unique.policy_drift_fingerprinter import PolicyDriftFingerprinter
        fingerprinter = PolicyDriftFingerprinter()
        fingerprint_results = fingerprinter.fingerprint(all_policies)
        # Merge with action-map fingerprinting for better coverage
        action_map_results = fingerprinter.fingerprint_from_action_map(iam_action_map)
        merged_fps = fingerprint_results.get("fingerprints", []) + action_map_results.get("fingerprints", [])
        # Deduplicate by pattern+identity
        seen_fps: set[str] = set()
        unique_fps: list[dict] = []
        for fp in merged_fps:
            key = f"{fp.get('matched_pattern', '')}:{fp.get('policy_name', '')}"
            if key not in seen_fps:
                seen_fps.add(key)
                unique_fps.append(fp)
        fingerprint_results["fingerprints"] = unique_fps
        fingerprint_results["dangerous_fingerprints_found"] = len(unique_fps)
        _scan_results["policy_fingerprints"] = fingerprint_results

        _emit_log(f"[+] Found {len(unique_fps)} dangerous policy fingerprints")
        _emit_progress("Policy Drift Fingerprinter", "complete", progress=86)

        # ── Phase 16: Blast Radius (UNIQUE) ──────────────────────────────
        _emit_log("Computing blast radius for all identities...")
        _emit_progress("Blast Radius Calculator", "running", progress=88)

        from src.unique.blast_radius_3d import BlastRadius3D
        blast_engine = BlastRadius3D()
        blast_results = []
        # Compute for top identities by action count
        sorted_identities = sorted(iam_action_map.items(), key=lambda x: len(x[1]), reverse=True)
        for identity_name, actions in sorted_identities[:30]:
            blast = blast_engine.compute(identity_name, actions, _scan_results)
            blast_results.append(blast)
        blast_results.sort(key=lambda x: x.get("overall_blast_score", 0), reverse=True)
        _scan_results["blast_radius"] = blast_results

        _emit_log(f"[+] Computed blast radius for {len(blast_results)} identities")
        _emit_progress("Blast Radius Calculator", "complete", progress=90)

        # -- Phase 17: Risk Engine (NIST CSF 2.0) -------------------------
        _emit_log("Computing NIST CSF 2.0 risk scores...")
        _emit_progress("Risk Engine", "running", progress=91)

        from src.analysis.risk_engine import RiskEngine
        risk_engine = RiskEngine()
        all_findings_for_risk = (
            shadow_findings + privesc_findings + network_findings +
            cloudtrail_findings + lambda_findings + secrets_findings +
            cross_findings + credential_findings + ghost_identities
        )
        risk_summary = risk_engine.compute(all_findings_for_risk)
        _scan_results["risk_summary"] = risk_summary

        _emit_log(f"[+] NIST Risk: {risk_summary.get('overall_score', 0)}/100 ({risk_summary.get('rating', 'N/A')})")
        _emit_progress("Risk Engine", "complete", progress=92)

        # ── Phase 18: Temporal Kill Chain (UNIQUE) ───────────────────────
        _emit_log("Building temporal kill chain...")
        _emit_progress("Temporal Kill Chain", "running", progress=93)

        from src.unique.temporal_kill_chain import TemporalKillChain
        kill_chain = TemporalKillChain()
        kill_chain_result = kill_chain.build(_scan_results)
        _scan_results["kill_chain"] = kill_chain_result

        _emit_log(f"[+] Attack duration: ~{kill_chain_result.get('total_attack_duration_minutes', 0)} minutes")
        _emit_progress("Temporal Kill Chain", "complete", progress=94)

        # ── Phase 19: Attack Narrative (UNIQUE) ──────────────────────────
        _emit_log("Generating attack narrative...")
        _emit_progress("Attack Narrative Generator", "running", progress=95)

        from src.unique.attack_narrative_generator import AttackNarrativeGenerator
        narrative_gen = AttackNarrativeGenerator()
        narrative = narrative_gen.generate(_scan_results)
        _scan_results["attack_narrative"] = narrative

        _emit_log("[+] Attack narrative generated")
        _emit_progress("Attack Narrative Generator", "complete", progress=96)

        # ── Phase 20: Remediation ────────────────────────────────────────
        _emit_log("Generating remediation plan...")
        _emit_progress("Remediation Engine", "running", progress=97)

        from src.analysis.remediation_engine import RemediationEngine
        remediation = RemediationEngine()
        all_findings = (
            shadow_findings + privesc_findings + network_findings +
            cloudtrail_findings + lambda_findings + secrets_findings +
            cross_findings + credential_findings + ghost_identities
        )
        remediation_plan = remediation.generate_remediation_plan(all_findings)
        _scan_results["remediation_plan"] = remediation_plan

        _emit_log(f"[+] Generated {len(remediation_plan)} remediation items")
        _emit_progress("Remediation Engine", "complete", progress=98)

        # ── Phase 21: Build Attack Graph ─────────────────────────────────
        _emit_log("Building attack graph...")
        from src.graph.attack_graph import AttackGraph
        graph = AttackGraph()
        graph.build(users, roles, trusts, admin_roles, shadow_findings, privesc_findings, iam_action_map)
        _scan_results["attack_graph"] = graph.to_dict()


        # ── NEW Phase A: Minimum Viable Compromise ───────────────────────
        _emit_log("[+] Running Minimum Viable Compromise Engine...")
        _emit_progress("MVC Engine", "running", progress=88)
        try:
            from src.offensive.mvc_engine import MVCEngine
            mvc = MVCEngine()
            mvc_result = mvc.analyze(iam_action_map, trusts, admin_roles, shadow_findings, privesc_findings)
            _scan_results["mvc_analysis"] = mvc_result
            _emit_log(f"[+] MVC: {mvc_result.get('total_paths',0)} attack paths mapped, fastest={mvc_result.get('fastest_seconds','N/A')}s")
        except Exception as e:
            logger.warning(f"MVC Engine skipped: {e}")
            _scan_results["mvc_analysis"] = {}
        _emit_progress("MVC Engine", "complete", progress=90)

        # ── NEW Phase B: Ransomware Readiness ────────────────────────────
        _emit_log("[+] Analyzing S3 ransomware readiness...")
        _emit_progress("Ransomware Detector", "running", progress=91)
        try:
            from src.offensive.ransomware_detector import RansomwareDetector
            rw = RansomwareDetector()
            enriched_buckets = []
            for bucket in s3_buckets:
                details = collector.get_s3_bucket_details(bucket.get("Name",""))
                enriched_buckets.append({**bucket, **details})
            rw_result = rw.analyze(enriched_buckets, iam_action_map, _scan_results)
            _scan_results["ransomware_analysis"] = rw_result
            _emit_log(f"[+] Ransomware score: {rw_result.get('overall_score',0)}/100 ({rw_result.get('risk_rating','N/A')})")
        except Exception as e:
            logger.warning(f"Ransomware analysis skipped: {e}")
            _scan_results["ransomware_analysis"] = {}
        _emit_progress("Ransomware Detector", "complete", progress=92)

        # ── NEW Phase C: Supply Chain ─────────────────────────────────────
        _emit_log("[+] Mapping supply chain attack surface...")
        _emit_progress("Supply Chain Mapper", "running", progress=93)
        try:
            from src.offensive.supply_chain_mapper import SupplyChainMapper
            sc = SupplyChainMapper()
            sc_result = sc.analyze(collector, lambda_functions, iam_action_map)
            _scan_results["supply_chain_analysis"] = sc_result
            _emit_log(f"[+] Supply chain: {sc_result.get('total_findings',0)} findings")
        except Exception as e:
            logger.warning(f"Supply chain analysis skipped: {e}")
            _scan_results["supply_chain_analysis"] = {}
        _emit_progress("Supply Chain Mapper", "complete", progress=94)

        # ── NEW Phase D: Golden SAML ──────────────────────────────────────
        _emit_log("[+] Detecting Golden SAML / federation attack vectors...")
        _emit_progress("Golden SAML Detector", "running", progress=95)
        try:
            from src.offensive.golden_saml_detector import GoldenSAMLDetector
            gs = GoldenSAMLDetector()
            gs_result = gs.analyze(collector, iam_action_map, roles)
            _scan_results["golden_saml_analysis"] = gs_result
            _emit_log(f"[+] Golden SAML: {gs_result.get('total_findings',0)} federation risks")
        except Exception as e:
            logger.warning(f"Golden SAML analysis skipped: {e}")
            _scan_results["golden_saml_analysis"] = {}
        _emit_progress("Golden SAML Detector", "complete", progress=96)

        # -- Finalize -------------------------------------------------------
        _scan_results["scan_status"] = "complete"
        _emit_log("[+] Reconnaissance complete. All modules finished.")
        _emit_log("[+] Credentials cleared from memory.")
        _emit_progress("Scan Complete", "complete", progress=100)

        # Clear credentials
        collector.clear_credentials()
        del access_key, secret_key
        gc.collect()

        socketio.emit("scan_complete", {"status": "success"})

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        _emit_log(f"[-] Scan failed: {str(e)}")
        socketio.emit("scan_error", {"message": str(e)})
        _scan_results["scan_status"] = "failed"
    finally:
        _scan_running = False


# ============================================================================
#  DATA SANITIZATION
# ============================================================================

_ARN_RE = re.compile(r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s\"',]+")
_ACCOUNT_RE = re.compile(r"\b(\d{3})\d{6}(\d{3})\b")


def _sanitize_for_frontend(data: Any) -> Any:
    """Recursively sanitize data for frontend consumption.

    Masks 12-digit AWS account IDs and removes full ARNs.
    """
    if isinstance(data, str):
        sanitized = _ARN_RE.sub("[REDACTED_ARN]", data)
        sanitized = _ACCOUNT_RE.sub(r"\1******\2", sanitized)
        return sanitized
    if isinstance(data, dict):
        return {k: _sanitize_for_frontend(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_sanitize_for_frontend(item) for item in data]
    return data


# ============================================================================
#  DATA BUILDERS
# ============================================================================

def _build_graph_data() -> dict:
    """Build graph data from scan results for vis.js rendering."""
    nodes: list[dict] = []
    edges: list[dict] = []
    node_set: set[str] = set()

    users = _scan_results.get("users", [])
    roles = _scan_results.get("roles", [])
    admin_roles = _scan_results.get("admin_roles", [])
    trusts = _scan_results.get("trusts", [])
    shadow_admins = {f.get("identity", "") for f in _scan_results.get("shadow_admin_findings", [])}
    privesc_ids = {f.get("identity", "") for f in _scan_results.get("privesc_findings", [])}

    for u in users:
        if u not in node_set:
            node_set.add(u)
            risk = "critical" if u in shadow_admins else ("high" if u in privesc_ids else "medium")
            nodes.append({
                "id": u, "label": u, "type": "user", "risk": risk,
                "is_shadow_admin": u in shadow_admins,
                "has_privesc": u in privesc_ids,
            })

    for r in roles:
        if r not in node_set:
            node_set.add(r)
            risk = "critical" if r in admin_roles else ("high" if r in shadow_admins else "medium")
            nodes.append({
                "id": r, "label": r, "type": "role", "risk": risk,
            })

    for src, dst, rel in trusts:
        sn = src.split("/")[-1] if "/" in src else src
        dn = dst.split("/")[-1] if "/" in dst else dst

        if sn not in node_set:
            node_set.add(sn)
            ntype = "service" if sn.endswith("amazonaws.com") else "external"
            nodes.append({"id": sn, "label": sn, "type": ntype, "risk": "low"})
        if dn not in node_set:
            node_set.add(dn)
            nodes.append({"id": dn, "label": dn, "type": "role", "risk": "low"})

        edges.append({
            "from": sn, "to": dn, "label": rel,
            "is_attack": rel == "AssumeRole",
        })

    return {"nodes": nodes, "edges": edges}


def _build_mitre_heatmap() -> dict:
    """Build MITRE ATT&CK heatmap data."""
    TACTIC_MAP = {
        "T1078":     ("Initial Access",        "Valid Accounts"),
        "T1078.004": ("Initial Access",        "Valid Accounts: Cloud Accounts"),
        "T1190":     ("Initial Access",        "Exploit Public-Facing Application"),
        "T1098":     ("Persistence",           "Account Manipulation"),
        "T1098.001": ("Persistence",           "Additional Cloud Credentials"),
        "T1525":     ("Persistence",           "Implant Internal Image"),
        "T1068":     ("Privilege Escalation",  "Exploitation for Privilege Escalation"),
        "T1078.004PE": ("Privilege Escalation","Valid Accounts: Cloud"),
        "T1578":     ("Defense Evasion",       "Modify Cloud Compute Infrastructure"),
        "T1562.008": ("Defense Evasion",       "Disable Cloud Logs"),
        "T1562.001": ("Defense Evasion",       "Disable or Modify Tools"),
        "T1552.005": ("Credential Access",     "Cloud Instance Metadata API"),
        "T1528":     ("Credential Access",     "Steal Application Access Token"),
        "T1606":     ("Credential Access",     "Forge Web Credentials"),
        "T1580":     ("Discovery",             "Cloud Infrastructure Discovery"),
        "T1087.004": ("Discovery",             "Cloud Account Discovery"),
        "T1526":     ("Discovery",             "Cloud Service Discovery"),
        "T1530":     ("Collection",            "Data from Cloud Storage Object"),
        "T1537":     ("Exfiltration",          "Transfer Data to Cloud Account"),
        "T1567":     ("Exfiltration",          "Exfiltration to Cloud Storage"),
    }

    TACTICS_ORDER = [
        "Initial Access", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Collection", "Exfiltration",
    ]

    # Gather findings with MITRE IDs
    finding_keys = [
        "shadow_admin_findings", "privesc_findings", "network_findings",
        "cloudtrail_findings", "lambda_findings", "secrets_findings",
        "cross_account_findings", "credential_findings", "ghost_identities",
    ]
    technique_severity: dict[str, dict] = {}
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for key in finding_keys:
        for f in _scan_results.get(key, []):
            t = f.get("mitre", "")
            if not t:
                continue
            sev = f.get("severity", "MEDIUM")
            if t not in technique_severity or severity_order.get(sev, 0) > severity_order.get(technique_severity[t].get("severity", ""), 0):
                technique_severity[t] = {"severity": sev, "types": []}
            technique_severity[t]["types"].append(f.get("type", ""))

    heatmap: dict[str, list] = {tac: [] for tac in TACTICS_ORDER}
    for tech_id, (tactic, name) in TACTIC_MAP.items():
        if tactic in heatmap:
            entry = {
                "id": tech_id, "name": name,
                "hit": tech_id in technique_severity,
                "severity": technique_severity.get(tech_id, {}).get("severity", "NONE"),
                "types": technique_severity.get(tech_id, {}).get("types", []),
            }
            heatmap[tactic].append(entry)

    return {
        "tactics_order": TACTICS_ORDER,
        "heatmap": heatmap,
        "total_techniques_hit": len(technique_severity),
    }


def _build_report_data() -> dict:
    """Build comprehensive data for PDF report generation."""
    risk = _scan_results.get("risk_summary", {})
    return {
        "meta": {
            "timestamp": _scan_results.get("timestamp", "N/A"),
            "region": _scan_results.get("region", "N/A"),
        },
        "risk_summary": risk,
        "shadow_admin_findings": _scan_results.get("shadow_admin_findings", []),
        "privesc_findings": _scan_results.get("privesc_findings", []),
        "privesc_summary": _scan_results.get("privesc_summary", {}),
        "ghost_identities": _scan_results.get("ghost_identities", []),
        "permission_entropy": _scan_results.get("permission_entropy", {}),
        "blast_radius": _scan_results.get("blast_radius", []),
        "kill_chain": _scan_results.get("kill_chain", {}),
        "attack_narrative": _scan_results.get("attack_narrative", {}),
        "network_findings": _scan_results.get("network_findings", []),
        "cloudtrail_findings": _scan_results.get("cloudtrail_findings", []),
        "lambda_findings": _scan_results.get("lambda_findings", []),
        "secrets_findings": _scan_results.get("secrets_findings", []),
        "cross_account_findings": _scan_results.get("cross_account_findings", []),
        "credential_findings": _scan_results.get("credential_findings", []),
        "credential_stats": _scan_results.get("credential_stats", {}),
        "policy_fingerprints": _scan_results.get("policy_fingerprints", {}),
        "remediation_plan": _scan_results.get("remediation_plan", []),
        "mvc_analysis": _scan_results.get("mvc_analysis", {}),
        "ransomware_analysis": _scan_results.get("ransomware_analysis", {}),
        "supply_chain_analysis": _scan_results.get("supply_chain_analysis", {}),
        "golden_saml_analysis": _scan_results.get("golden_saml_analysis", {}),
        "kpis": {
            "iam_users": len(_scan_results.get("users", [])),
            "iam_roles": len(_scan_results.get("roles", [])),
            "shadow_admins": len(_scan_results.get("shadow_admin_findings", [])),
            "privesc_paths": len(_scan_results.get("privesc_findings", [])),
            "ghost_identities": len(_scan_results.get("ghost_identities", [])),
            "network_exposed": len(_scan_results.get("network_findings", [])),
            "lambda_issues": len(_scan_results.get("lambda_findings", [])),
            "secrets_issues": len(_scan_results.get("secrets_findings", [])),
            "cloudtrail_issues": len(_scan_results.get("cloudtrail_findings", [])),
            "credential_issues": len(_scan_results.get("credential_findings", [])),
            "remediation_items": len(_scan_results.get("remediation_plan", [])),
        },
    }

