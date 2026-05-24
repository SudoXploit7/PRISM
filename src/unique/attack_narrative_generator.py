"""
PRISM - Attack Narrative Generator (WORLD-FIRST)
Generates realistic, data-driven attacker stories using real scan data.
Not AI-generated - template-driven with precise technical accuracy.
"""

from typing import Any

from loguru import logger


class AttackNarrativeGenerator:
    """Generates customized attack narratives from scan results.

    Each narrative reads like a real red team report chapter, using actual
    identity names, permissions, and attack vectors from the scan.
    """

    def generate(self, scan_results: dict[str, Any]) -> dict[str, Any]:
        """Generate attack narrative from scan results.

        Args:
            scan_results: Complete scan results dictionary.

        Returns:
            Dictionary with executive and technical narratives.
        """
        shadow_admins = scan_results.get("shadow_admin_findings", [])
        privesc = scan_results.get("privesc_findings", [])
        credential_findings = scan_results.get("credential_findings", [])
        cloudtrail = scan_results.get("cloudtrail_findings", [])
        secrets = scan_results.get("secrets_findings", [])
        network = scan_results.get("network_findings", [])
        kill_chain = scan_results.get("kill_chain", {})
        risk = scan_results.get("risk_summary", {})
        entropy = scan_results.get("permission_entropy", {})
        ghosts = scan_results.get("ghost_identities", [])

        # Find initial access identity
        initial_identity = self._find_initial_target(
            credential_findings, shadow_admins, privesc
        )

        # Find escalation method
        escalation_method, escalation_details = self._find_escalation_path(privesc)

        # Determine detection likelihood
        ct_coverage = kill_chain.get("cloudtrail_coverage", {})
        has_logging = ct_coverage.get("is_logging", False)
        has_alerts = ct_coverage.get("has_cloudwatch_integration", False)

        if not has_logging:
            detection_likelihood = "Very Low"
        elif not has_alerts:
            detection_likelihood = "Low"
        elif len(cloudtrail) > 3:
            detection_likelihood = "Low"
        else:
            detection_likelihood = "Moderate"

        # Build attack steps
        attack_steps = self._build_attack_steps(
            initial_identity, escalation_method, escalation_details,
            secrets, cloudtrail, scan_results
        )

        # Calculate time to admin
        time_to_admin = kill_chain.get("total_attack_duration_minutes", 15)

        # Build executive narrative
        executive_narrative = self._build_executive_narrative(
            risk, initial_identity, escalation_method, time_to_admin,
            detection_likelihood, entropy, ghosts
        )

        # Build technical narrative
        technical_narrative = self._build_technical_narrative(
            initial_identity, escalation_method, escalation_details,
            secrets, cloudtrail, attack_steps, time_to_admin,
            detection_likelihood, scan_results
        )

        result = {
            "executive_narrative": executive_narrative,
            "technical_narrative": technical_narrative,
            "attack_steps": attack_steps,
            "initial_access_vector": f"Compromised credentials for '{initial_identity}'",
            "time_to_admin_minutes": time_to_admin,
            "detection_likelihood": detection_likelihood,
        }

        logger.info("Attack narrative generated")
        return result

    def _find_initial_target(
        self,
        credentials: list[dict],
        shadow_admins: list[dict],
        privesc: list[dict],
    ) -> str:
        """Find the most realistic initial access target."""
        # Old credentials are the most likely to be leaked
        for f in credentials:
            if f.get("type") == "CRITICAL_KEY_AGE":
                return f.get("identity", "unknown-user")

        # Shadow admins are high-value targets
        if shadow_admins:
            return shadow_admins[0].get("identity", "unknown-user")

        # Users with privesc paths
        if privesc:
            return privesc[0].get("identity", "unknown-user")

        return "unknown-user"

    def _find_escalation_path(
        self, privesc: list[dict]
    ) -> tuple[str, dict]:
        """Find the most impactful escalation method."""
        if not privesc:
            return "Direct Admin Access", {}

        # Prefer CRITICAL paths
        critical = [p for p in privesc if p.get("severity") == "CRITICAL"]
        target = critical[0] if critical else privesc[0]

        return target.get("vector_name", "Unknown"), target

    def _build_attack_steps(
        self,
        initial_identity: str,
        escalation_method: str,
        escalation_details: dict,
        secrets: list[dict],
        cloudtrail: list[dict],
        scan_results: dict,
    ) -> list[dict]:
        """Build structured attack step list."""
        steps = [
            {
                "step": 1,
                "phase": "Initial Access",
                "time_offset": "T+0:00",
                "action": f"Authenticate as '{initial_identity}'",
                "command": "aws sts get-caller-identity",
                "mitre": "T1078",
            },
            {
                "step": 2,
                "phase": "Discovery",
                "time_offset": "T+0:01",
                "action": "Enumerate IAM users, roles, and policies",
                "command": "aws iam list-users && aws iam list-roles && aws iam list-policies",
                "mitre": "T1087.004",
            },
            {
                "step": 3,
                "phase": "Discovery",
                "time_offset": "T+0:03",
                "action": "Map all permissions for current identity",
                "command": f"aws iam list-attached-user-policies --user-name {initial_identity}",
                "mitre": "T1087.004",
            },
        ]

        # Escalation step
        if escalation_details:
            steps.append({
                "step": 4,
                "phase": "Privilege Escalation",
                "time_offset": "T+0:05",
                "action": f"Exploit {escalation_method} vector",
                "command": escalation_details.get("attack_command", ""),
                "mitre": escalation_details.get("mitre", "T1098"),
            })

        # Persistence step
        steps.append({
            "step": 5,
            "phase": "Persistence",
            "time_offset": "T+0:08",
            "action": "Create backdoor IAM user with admin access",
            "command": (
                "aws iam create-user --user-name backup-service && "
                "aws iam attach-user-policy --user-name backup-service "
                "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess && "
                "aws iam create-access-key --user-name backup-service"
            ),
            "mitre": "T1098.001",
        })

        # Evasion
        can_evade = any(f.get("type") == "CLOUDTRAIL_EVASION" for f in cloudtrail)
        if can_evade:
            steps.append({
                "step": 6,
                "phase": "Defense Evasion",
                "time_offset": "T+0:10",
                "action": "Disable CloudTrail logging",
                "command": "aws cloudtrail stop-logging --name <trail-name>",
                "mitre": "T1562.008",
            })

        # Exfiltration
        if secrets:
            steps.append({
                "step": len(steps) + 1,
                "phase": "Exfiltration",
                "time_offset": "T+0:12",
                "action": "Exfiltrate all secrets and sensitive data",
                "command": (
                    "aws secretsmanager list-secrets --query 'SecretList[].Name' && "
                    "aws secretsmanager get-secret-value --secret-id <each-secret>"
                ),
                "mitre": "T1528",
            })

        return steps

    def _build_executive_narrative(
        self,
        risk: dict,
        initial_identity: str,
        escalation_method: str,
        time_to_admin: int,
        detection_likelihood: str,
        entropy: dict,
        ghosts: list[dict],
    ) -> str:
        """Build 2-paragraph non-technical executive summary."""
        score = risk.get("overall_score", 0)
        rating = risk.get("rating", "UNKNOWN")
        total = risk.get("total_findings", 0)
        chaos = entropy.get("chaos_level", "Unknown")

        p1 = (
            f"This AWS account has been assessed at {rating} risk ({score}/100) with "
            f"{total} security findings identified across IAM, network, credential, "
            f"and infrastructure categories. The IAM permission structure shows "
            f"{chaos} chaos levels, indicating "
            f"{'significant over-provisioning that creates unnecessary attack surface' if chaos in ('HIGH', 'CRITICAL') else 'room for improvement in permission hygiene'}. "
            f"An attacker who obtains credentials for '{initial_identity}' could "
            f"achieve full administrator access within approximately {time_to_admin} minutes."
        )

        ghost_text = ""
        if ghosts:
            ghost_text = (
                f" Additionally, {len(ghosts)} ghost identities were discovered - "
                f"dormant accounts with dangerous permissions that represent invisible attack surfaces."
            )

        p2 = (
            f"The primary attack vector identified is the {escalation_method} "
            f"privilege escalation path. Detection likelihood for this attack is "
            f"{detection_likelihood}, meaning {'the current monitoring setup would likely miss this attack entirely' if detection_likelihood in ('Very Low', 'Low') else 'there is some chance of detection but gaps remain'}. "
            f"Immediate remediation is recommended for all CRITICAL and HIGH severity findings "
            f"to reduce the blast radius of a potential compromise.{ghost_text}"
        )

        return f"{p1}\n\n{p2}"

    def _build_technical_narrative(
        self,
        initial_identity: str,
        escalation_method: str,
        escalation_details: dict,
        secrets: list[dict],
        cloudtrail: list[dict],
        attack_steps: list[dict],
        time_to_admin: int,
        detection_likelihood: str,
        scan_results: dict,
    ) -> str:
        """Build detailed technical attacker story."""
        trails = scan_results.get("trails", [])
        has_ct = any(t.get("IsLogging") for t in trails)
        has_cw = any(t.get("CloudWatchLogsLogGroupArn") for t in trails)
        can_evade = any(
            f.get("type") == "CLOUDTRAIL_EVASION"
            for f in scan_results.get("cloudtrail_findings", [])
        )

        required_actions = escalation_details.get("required_actions", [])
        vector_name = escalation_details.get("vector_name", escalation_method)

        parts = [
            f"An external attacker who obtains the access key for '{initial_identity}' "
            f"(potentially leaked via a GitHub repository, phishing attack, or compromised CI/CD pipeline) "
            f"would first authenticate and enumerate IAM using iam:ListUsers and iam:ListRoles.",

            f"Within 3 minutes, they would discover that this identity has "
            f"{', '.join(required_actions) if required_actions else 'elevated permissions'} - "
            f"the {vector_name} privilege escalation vector.",
        ]

        if "Lambda" in vector_name:
            parts.append(
                f"They would create a Lambda function with an admin execution role, "
                f"invoke it to call iam:AttachUserPolicy, and within {time_to_admin} minutes "
                f"have full AdministratorAccess."
            )
        elif "AttachUserPolicy" in vector_name or "PutUserPolicy" in vector_name:
            parts.append(
                f"They would directly attach AdministratorAccess to their user account, "
                f"gaining full admin access within {time_to_admin} minutes."
            )
        else:
            parts.append(
                f"Using the {vector_name} vector, they would escalate to full "
                f"AdministratorAccess within approximately {time_to_admin} minutes."
            )

        # CloudTrail status
        if not has_ct:
            parts.append(
                "CloudTrail is NOT enabled in this account, so this entire attack "
                "would generate no audit trail whatsoever."
            )
        elif not has_cw:
            parts.append(
                "CloudTrail IS enabled but is not integrated with CloudWatch Logs, "
                "so this attack would generate no real-time alerts."
            )
        elif can_evade:
            parts.append(
                "While CloudTrail is enabled, the attacker has permissions to disable it, "
                "effectively creating a detection blackout before proceeding."
            )

        # Post-escalation
        parts.append(
            "After achieving admin access, the attacker would create a backdoor IAM user "
            "with a new access key for persistent access."
        )

        if secrets:
            secret_names = [s.get("identity", s.get("resource", "")) for s in secrets[:3]]
            parts.append(
                f"They would then exfiltrate {len(secrets)} secrets including "
                f"{', '.join(secret_names)}, potentially containing database credentials, "
                f"API keys, and other sensitive material."
            )

        return " ".join(parts)
