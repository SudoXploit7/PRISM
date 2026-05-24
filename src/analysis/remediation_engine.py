"""
PRISM -- Remediation Engine
Generates prioritized remediation plan from all findings.
"""

from typing import Any

from loguru import logger

# ── Priority scoring ─────────────────────────────────────────────────────
SEVERITY_PRIORITY: dict[str, int] = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
}

EFFORT_MAP: dict[str, str] = {
    "SHADOW_ADMIN": "Medium",
    "PRIVESC_PATH": "Medium",
    "OPEN_SECURITY_GROUP": "Low",
    "ALL_PORTS_OPEN": "Low",
    "PUBLIC_S3_BUCKET": "Low",
    "IMDS_V1_ENABLED": "Low",
    "CLOUDTRAIL_EVASION": "Medium",
    "NO_CLOUDTRAIL": "High",
    "TRAIL_NOT_LOGGING": "Low",
    "LAMBDA_ADMIN_ROLE": "Medium",
    "LAMBDA_HARDCODED_SECRET": "Medium",
    "SECRETS_EXFIL": "Medium",
    "CROSS_ACCOUNT_ROOT_TRUST": "Medium",
    "WILDCARD_TRUST": "Low",
    "CRITICAL_KEY_AGE": "Low",
    "NO_MFA": "Low",
    "GHOST_IDENTITY": "Low",
}


class RemediationEngine:
    """Generates a prioritized, actionable remediation plan."""

    def generate_remediation_plan(self, findings: list[dict]) -> list[dict]:
        """Generate remediation plan from all findings.

        Args:
            findings: Combined list of all scan findings.

        Returns:
            List of remediation items sorted by priority.
        """
        remediation_items: list[dict] = []

        for f in findings:
            finding_type = f.get("type", "UNKNOWN")
            severity = f.get("severity", "MEDIUM")
            identity = f.get("identity", "Unknown")
            remediation_text = f.get("remediation", "")

            if not remediation_text:
                continue

            # Extract CLI command if present in remediation text
            cli_command = ""
            if "aws " in remediation_text:
                # Extract the aws CLI command
                parts = remediation_text.split("aws ")
                if len(parts) > 1:
                    cmd = "aws " + parts[1].split(".")[0].rstrip()
                    cli_command = cmd

            effort = EFFORT_MAP.get(finding_type, "Medium")
            priority_num = SEVERITY_PRIORITY.get(severity, 3)

            # Risk reduction estimate
            risk_reduction = {
                "CRITICAL": "High",
                "HIGH": "High",
                "MEDIUM": "Medium",
                "LOW": "Low",
            }.get(severity, "Medium")

            priority_label = f"P{priority_num}"

            remediation_items.append({
                "priority": priority_label,
                "priority_num": priority_num,
                "severity": severity,
                "type": finding_type,
                "identity": identity,
                "summary": f"[{severity}] {finding_type.replace('_', ' ').title()} - {identity}",
                "detailed_remediation": remediation_text,
                "cli_command": cli_command if cli_command else f.get("attack_command", ""),
                "effort": effort,
                "risk_reduction": risk_reduction,
                "mitre": f.get("mitre", ""),
            })

        # Sort by priority (P1 first)
        remediation_items.sort(key=lambda x: (x["priority_num"], x["severity"]))

        logger.info(f"Remediation plan generated: {len(remediation_items)} items")
        return remediation_items
