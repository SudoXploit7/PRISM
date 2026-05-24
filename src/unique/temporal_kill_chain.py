"""
PRISM - Temporal Kill Chain (WORLD-FIRST)
Builds a time-sequenced attack narrative customized to the actual account's
IAM structure and CloudTrail configuration. Shows attacker dwell time,
blind spots, and detection probability per phase.
"""

from typing import Any

from loguru import logger


class TemporalKillChain:
    """Builds a temporal attack kill chain specific to the scanned account.

    Unlike generic kill chain diagrams, this is data-driven: each phase
    uses real IAM permissions, real CloudTrail configuration, and real
    identity data from the scan to estimate attack timing and detection gaps.
    """

    def build(self, scan_results: dict[str, Any]) -> dict[str, Any]:
        """Build the temporal kill chain from scan results.

        Args:
            scan_results: Complete scan results dictionary.

        Returns:
            Temporal kill chain with phases, timing, and detection gaps.
        """
        shadow_admins = scan_results.get("shadow_admin_findings", [])
        privesc = scan_results.get("privesc_findings", [])
        cloudtrail = scan_results.get("cloudtrail_findings", [])
        trails = scan_results.get("trails", [])
        secrets = scan_results.get("secrets_findings", [])
        credential_findings = scan_results.get("credential_findings", [])
        network_findings = scan_results.get("network_findings", [])
        iam_action_map = scan_results.get("iam_action_map", {})

        # Determine CloudTrail coverage
        has_cloudtrail = bool(trails)
        is_logging = any(t.get("IsLogging", False) for t in trails)
        is_multiregion = any(t.get("IsMultiRegion", False) for t in trails)
        has_cloudwatch = any(t.get("CloudWatchLogsLogGroupArn") for t in trails)

        # Find the most likely initial access vector
        initial_identity = self._find_initial_access_identity(
            credential_findings, shadow_admins, iam_action_map
        )

        # Build phases
        phases: list[dict[str, Any]] = []

        # Phase 1: Initial Access
        phase1_logged = has_cloudtrail and is_logging
        phases.append({
            "phase": "Initial Access",
            "duration_minutes": 1,
            "api_calls": [
                "sts:GetCallerIdentity",
                "iam:ListUsers",
                "iam:ListRoles",
            ],
            "logged_by_cloudtrail": phase1_logged,
            "detection_probability": 0.3 if phase1_logged else 0.0,
            "mitre_technique": "T1078 - Valid Accounts",
            "identity_used": initial_identity,
            "description": (
                f"Attacker uses compromised credentials for '{initial_identity}' "
                f"to authenticate and begin reconnaissance."
            ),
        })

        # Phase 2: Discovery
        phases.append({
            "phase": "Discovery",
            "duration_minutes": 3,
            "api_calls": [
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListPolicies",
                "iam:GetPolicyVersion",
                "sts:GetCallerIdentity",
                "ec2:DescribeInstances",
                "s3:ListBuckets",
                "secretsmanager:ListSecrets",
            ],
            "logged_by_cloudtrail": phase1_logged,
            "detection_probability": 0.2 if phase1_logged else 0.0,
            "mitre_technique": "T1087.004 - Cloud Account Discovery",
            "identity_used": initial_identity,
            "description": (
                "Attacker enumerates all IAM users, roles, policies, EC2 instances, "
                "S3 buckets, and secrets to map the attack surface."
            ),
        })

        # Phase 3: Privilege Escalation
        privesc_time = 5
        escalation_method = "Unknown"
        escalation_identity = initial_identity
        escalation_calls: list[str] = []

        if privesc:
            top_privesc = privesc[0]
            escalation_method = top_privesc.get("vector_name", "Unknown")
            escalation_identity = top_privesc.get("identity", initial_identity)
            escalation_calls = top_privesc.get("required_actions", [])
            privesc_time = 5 if "Lambda" in escalation_method else 3

        phases.append({
            "phase": "Privilege Escalation",
            "duration_minutes": privesc_time,
            "api_calls": escalation_calls or ["iam:AttachUserPolicy"],
            "logged_by_cloudtrail": phase1_logged,
            "detection_probability": 0.5 if (phase1_logged and has_cloudwatch) else 0.1,
            "mitre_technique": "T1098 - Account Manipulation",
            "identity_used": escalation_identity,
            "description": (
                f"Attacker exploits {escalation_method} vector using "
                f"'{escalation_identity}' to escalate to administrator access."
            ),
        })

        # Phase 4: Persistence
        phases.append({
            "phase": "Persistence",
            "duration_minutes": 2,
            "api_calls": [
                "iam:CreateAccessKey",
                "iam:CreateUser",
                "iam:AttachUserPolicy",
            ],
            "logged_by_cloudtrail": phase1_logged,
            "detection_probability": 0.4 if (phase1_logged and has_cloudwatch) else 0.05,
            "mitre_technique": "T1098.001 - Additional Cloud Credentials",
            "identity_used": "admin (escalated)",
            "description": (
                "Attacker creates a new IAM user with admin access and generates "
                "access keys for persistent backdoor access."
            ),
        })

        # Phase 5: Defense Evasion
        can_evade_ct = any(
            f.get("type") == "CLOUDTRAIL_EVASION"
            for f in scan_results.get("cloudtrail_findings", [])
        )
        phases.append({
            "phase": "Defense Evasion",
            "duration_minutes": 2,
            "api_calls": [
                "cloudtrail:StopLogging",
                "cloudtrail:DeleteTrail",
                "logs:DeleteLogGroup",
            ] if can_evade_ct else ["(no evasion needed - trails already insufficient)"],
            "logged_by_cloudtrail": phase1_logged and not can_evade_ct,
            "detection_probability": 0.6 if (phase1_logged and has_cloudwatch and not can_evade_ct) else 0.0,
            "mitre_technique": "T1562.008 - Disable Cloud Logs",
            "identity_used": "admin (escalated)",
            "description": (
                "Attacker disables CloudTrail logging and deletes CloudWatch log groups "
                "to cover tracks."
                if can_evade_ct
                else "CloudTrail is already insufficient - no evasion actions needed."
            ),
        })

        # Phase 6: Data Exfiltration
        has_secrets_access = len(secrets) > 0
        phases.append({
            "phase": "Exfiltration",
            "duration_minutes": 5,
            "api_calls": [
                "secretsmanager:GetSecretValue",
                "ssm:GetParameter",
                "s3:GetObject",
                "s3:CopyObject",
            ] if has_secrets_access else [
                "s3:GetObject",
                "s3:ListBuckets",
            ],
            "logged_by_cloudtrail": False if can_evade_ct else phase1_logged,
            "detection_probability": 0.1 if can_evade_ct else 0.3,
            "mitre_technique": "T1537 - Transfer Data to Cloud Account",
            "identity_used": "admin (escalated)",
            "description": (
                "Attacker exfiltrates secrets, SSM parameters, and S3 data "
                "to an attacker-controlled account."
            ),
        })

        # Calculate totals
        total_duration = sum(p["duration_minutes"] for p in phases)
        blind_spots = [
            p["phase"] for p in phases if not p["logged_by_cloudtrail"]
        ]

        # Find earliest detection point
        earliest_detection = "None - attack goes completely undetected"
        for p in phases:
            if p["detection_probability"] >= 0.4:
                earliest_detection = p["phase"]
                break

        # Recommended detections
        recommended_detections = self._build_detection_recommendations(
            has_cloudtrail, is_logging, is_multiregion, has_cloudwatch
        )

        result: dict[str, Any] = {
            "total_attack_duration_minutes": total_duration,
            "phases": phases,
            "blind_spots": blind_spots,
            "earliest_detection_at_phase": earliest_detection,
            "recommended_detections": recommended_detections,
            "cloudtrail_coverage": {
                "has_trail": has_cloudtrail,
                "is_logging": is_logging,
                "is_multiregion": is_multiregion,
                "has_cloudwatch_integration": has_cloudwatch,
            },
        }

        logger.info(f"Temporal kill chain built: {total_duration} min total, {len(blind_spots)} blind spots")
        return result

    def _find_initial_access_identity(
        self,
        credential_findings: list[dict],
        shadow_admins: list[dict],
        iam_action_map: dict[str, list[str]],
    ) -> str:
        """Determine the most likely initial access identity."""
        # Prefer users with old credentials (most likely to be leaked)
        for f in credential_findings:
            if f.get("type") == "CRITICAL_KEY_AGE":
                return f.get("identity", "unknown-user")

        # Then shadow admins
        if shadow_admins:
            return shadow_admins[0].get("identity", "unknown-user")

        # Fallback to first user with most permissions
        if iam_action_map:
            sorted_ids = sorted(iam_action_map.items(), key=lambda x: len(x[1]), reverse=True)
            return sorted_ids[0][0] if sorted_ids else "unknown-user"

        return "unknown-user"

    def _build_detection_recommendations(
        self,
        has_trail: bool,
        is_logging: bool,
        is_multiregion: bool,
        has_cloudwatch: bool,
    ) -> list[str]:
        """Build specific detection recommendations based on gaps."""
        recommendations: list[str] = []

        if not has_trail:
            recommendations.append(
                "CRITICAL: Enable CloudTrail with a multi-region trail immediately."
            )
        elif not is_logging:
            recommendations.append(
                "CRITICAL: Start CloudTrail logging - trail exists but is not active."
            )
        elif not is_multiregion:
            recommendations.append(
                "HIGH: Enable multi-region trail to catch attacks in all regions."
            )

        if not has_cloudwatch:
            recommendations.append(
                "HIGH: Send CloudTrail logs to CloudWatch for real-time alerting."
            )

        recommendations.extend([
            "Create CloudWatch alarm for iam:CreateAccessKey events.",
            "Create CloudWatch alarm for iam:AttachUserPolicy events.",
            "Create CloudWatch alarm for cloudtrail:StopLogging events.",
            "Create CloudWatch alarm for iam:CreateUser events.",
            "Enable GuardDuty for automated threat detection.",
            "Enable AWS Config rules for IAM policy compliance.",
        ])

        return recommendations
