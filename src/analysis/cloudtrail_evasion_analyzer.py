"""
PRISM -- CloudTrail Evasion Analyzer
Detects identities capable of disabling or evading CloudTrail logging.
"""

from typing import Any

from loguru import logger

from src.scoring.cvss import score_for_finding, vector_string

# -- Evasion action patterns -----------------------------------------------
EVASION_ACTIONS: dict[str, dict[str, str]] = {
    "cloudtrail:DeleteTrail": {
        "severity": "CRITICAL",
        "description": "Can permanently delete CloudTrail trails, erasing all audit history",
        "mitre": "T1562.008",
        "command": "aws cloudtrail delete-trail --name <TRAIL_NAME>",
    },
    "cloudtrail:StopLogging": {
        "severity": "CRITICAL",
        "description": "Can stop CloudTrail logging, creating a blind spot for all future actions",
        "mitre": "T1562.008",
        "command": "aws cloudtrail stop-logging --name <TRAIL_NAME>",
    },
    "cloudtrail:UpdateTrail": {
        "severity": "HIGH",
        "description": "Can modify trail configuration (redirect logs, disable multi-region)",
        "mitre": "T1562.008",
        "command": "aws cloudtrail update-trail --name <TRAIL_NAME> --no-is-multi-region-trail",
    },
    "cloudtrail:PutEventSelectors": {
        "severity": "HIGH",
        "description": "Can modify event selectors to exclude specific API call types from logging",
        "mitre": "T1562.008",
        "command": "aws cloudtrail put-event-selectors --trail-name <TRAIL_NAME> --event-selectors '[]'",
    },
    "logs:DeleteLogGroup": {
        "severity": "CRITICAL",
        "description": "Can delete CloudWatch log groups containing CloudTrail logs",
        "mitre": "T1562.001",
        "command": "aws logs delete-log-group --log-group-name <LOG_GROUP>",
    },
    "s3:DeleteObject": {
        "severity": "HIGH",
        "description": "Can delete CloudTrail log files from the S3 bucket",
        "mitre": "T1562.008",
        "command": "aws s3 rm s3://<TRAIL_BUCKET>/ --recursive",
    },
    "guardduty:DeleteDetector": {
        "severity": "CRITICAL",
        "description": "Can disable GuardDuty threat detection entirely",
        "mitre": "T1562.001",
        "command": "aws guardduty delete-detector --detector-id <DETECTOR_ID>",
    },
    "securityhub:DisableSecurityHub": {
        "severity": "HIGH",
        "description": "Can disable Security Hub, removing centralized security findings",
        "mitre": "T1562.001",
        "command": "aws securityhub disable-security-hub",
    },
}


class CloudTrailEvasionAnalyzer:
    """Detects identities that can evade or disable CloudTrail logging."""

    def __init__(self) -> None:
        self.findings: list[dict] = []

    def analyze(
        self,
        iam_action_map: dict[str, list[str]],
        trails: list[dict],
    ) -> list[dict]:
        """Analyze for CloudTrail evasion capabilities.

        Args:
            iam_action_map: Mapping of identity to list of allowed actions.
            trails: List of CloudTrail trail configurations.

        Returns:
            List of evasion findings.
        """
        # Check trail health first
        self._check_trail_health(trails)

        # Check each identity for evasion capabilities
        for identity, actions in iam_action_map.items():
            actions_lower = set(a.lower() for a in actions)
            has_wildcard = "*" in actions

            for evasion_action, details in EVASION_ACTIONS.items():
                if has_wildcard or evasion_action.lower() in actions_lower:
                    self.findings.append({
                        "type": "CLOUDTRAIL_EVASION",
                        "severity": details["severity"],
                        "identity": identity,
                        "action": evasion_action,
                        "mitre": details["mitre"],
                        "description": (
                            f"Identity '{identity}' has {evasion_action} permission. "
                            f"{details['description']}."
                        ),
                        "attack_command": details["command"],
                        "remediation": (
                            f"Remove {evasion_action} permission from '{identity}'. "
                            f"Apply an SCP to deny CloudTrail modifications at the organization level."
                        ),
                    })

        logger.info(f"CloudTrail evasion analysis complete: {len(self.findings)} findings")
        return self.findings

    def _check_trail_health(self, trails: list[dict]) -> None:
        """Check for unhealthy CloudTrail configurations."""
        if not trails:
            self.findings.append({
                "type": "NO_CLOUDTRAIL",
                "severity": "CRITICAL",
                "identity": "ACCOUNT",
                "action": "N/A",
                "mitre": "T1562.008",
                "description": (
                    "No CloudTrail trails are configured in this account. "
                    "All API activity is completely unmonitored."
                ),
                "remediation": (
                    "Create a multi-region trail immediately: "
                    "aws cloudtrail create-trail --name prism-audit "
                    "--s3-bucket-name <BUCKET> --is-multi-region-trail"
                ),
            })
            return

        for trail in trails:
            name = trail.get("Name", "")
            if not trail.get("IsLogging", False):
                self.findings.append({
                    "type": "TRAIL_NOT_LOGGING",
                    "severity": "CRITICAL",
                    "identity": "ACCOUNT",
                    "action": "N/A",
                    "mitre": "T1562.008",
                    "description": (
                        f"CloudTrail trail '{name}' exists but is NOT actively logging. "
                        f"API calls are not being recorded."
                    ),
                    "remediation": f"aws cloudtrail start-logging --name {name}",
                })

            if not trail.get("IsMultiRegion", False):
                self.findings.append({
                    "type": "SINGLE_REGION_TRAIL",
                    "severity": "HIGH",
                    "identity": "ACCOUNT",
                    "action": "N/A",
                    "mitre": "T1562.008",
                    "description": (
                        f"Trail '{name}' only covers one region. "
                        f"API calls in other regions are not logged."
                    ),
                    "remediation": (
                        f"Enable multi-region: aws cloudtrail update-trail "
                        f"--name {name} --is-multi-region-trail"
                    ),
                })

            if not trail.get("HasLogFileValidation", False):
                self.findings.append({
                    "type": "NO_LOG_VALIDATION",
                    "severity": "MEDIUM",
                    "identity": "ACCOUNT",
                    "action": "N/A",
                    "mitre": "T1562.008",
                    "description": (
                        f"Trail '{name}' does not have log file validation enabled. "
                        f"An attacker can modify logs without detection."
                    ),
                    "remediation": (
                        f"Enable validation: aws cloudtrail update-trail "
                        f"--name {name} --enable-log-file-validation"
                    ),
                })
