"""
PRISM -- Credential Age Analyzer
Analyzes access key age, rotation status, and MFA enrollment.
"""

from datetime import datetime, timezone
from typing import Any

from loguru import logger

# ── Thresholds ───────────────────────────────────────────────────────────
KEY_AGE_CRITICAL_DAYS: int = 365
KEY_AGE_WARNING_DAYS: int = 180
KEY_AGE_INFO_DAYS: int = 90


class CredentialAgeAnalyzer:
    """Analyzes IAM credential health: key age, rotation, and MFA."""

    def __init__(self) -> None:
        self.findings: list[dict] = []
        self.stats: dict[str, Any] = {
            "total_keys": 0,
            "active_keys": 0,
            "critical_keys": 0,
            "warning_keys": 0,
            "oldest_key_days": 0,
            "avg_key_age_days": 0,
            "users_without_mfa": 0,
            "total_users": 0,
        }

    def analyze(
        self,
        access_key_metadata: list[dict],
        mfa_status: dict[str, bool],
    ) -> list[dict]:
        """Analyze credential health.

        Args:
            access_key_metadata: List of user access key data.
            mfa_status: Mapping of username to MFA enrollment status.

        Returns:
            List of credential health findings.
        """
        now = datetime.now(timezone.utc)
        all_ages: list[int] = []

        for user_data in access_key_metadata:
            username = user_data.get("UserName", "")
            keys = user_data.get("AccessKeys", [])

            for key in keys:
                self.stats["total_keys"] += 1
                if key.get("Status") == "Active":
                    self.stats["active_keys"] += 1

                create_str = key.get("CreateDate", "")
                try:
                    create_date = datetime.fromisoformat(create_str.replace("Z", "+00:00"))
                    age_days = (now - create_date).days
                    all_ages.append(age_days)

                    if age_days > self.stats["oldest_key_days"]:
                        self.stats["oldest_key_days"] = age_days

                    if age_days >= KEY_AGE_CRITICAL_DAYS:
                        self.stats["critical_keys"] += 1
                        self.findings.append({
                            "type": "CRITICAL_KEY_AGE",
                            "severity": "CRITICAL",
                            "identity": username,
                            "resource": key.get("AccessKeyId", ""),
                            "mitre": "T1078",
                            "description": (
                                f"Access key {key.get('AccessKeyId', '')} for '{username}' "
                                f"is {age_days} days old (>{KEY_AGE_CRITICAL_DAYS}d threshold). "
                                f"Long-lived keys are a primary attack vector for credential theft."
                            ),
                            "remediation": (
                                f"Rotate immediately: aws iam create-access-key --user-name {username} "
                                f"&& aws iam delete-access-key --user-name {username} "
                                f"--access-key-id {key.get('AccessKeyId', '')}"
                            ),
                        })
                    elif age_days >= KEY_AGE_WARNING_DAYS:
                        self.stats["warning_keys"] += 1
                        self.findings.append({
                            "type": "OLD_ACCESS_KEY",
                            "severity": "HIGH",
                            "identity": username,
                            "resource": key.get("AccessKeyId", ""),
                            "mitre": "T1078",
                            "description": (
                                f"Access key {key.get('AccessKeyId', '')} for '{username}' "
                                f"is {age_days} days old. Key rotation is recommended every "
                                f"{KEY_AGE_INFO_DAYS} days."
                            ),
                            "remediation": (
                                f"Rotate key: aws iam create-access-key --user-name {username}"
                            ),
                        })
                except (ValueError, TypeError):
                    pass

        # MFA analysis
        self.stats["total_users"] = len(mfa_status)
        for username, has_mfa in mfa_status.items():
            if not has_mfa:
                self.stats["users_without_mfa"] += 1
                self.findings.append({
                    "type": "NO_MFA",
                    "severity": "HIGH",
                    "identity": username,
                    "resource": "MFA",
                    "mitre": "T1078",
                    "description": (
                        f"IAM user '{username}' does not have MFA enabled. "
                        f"Without MFA, stolen credentials provide direct access."
                    ),
                    "remediation": (
                        f"Enable MFA for '{username}' using a virtual MFA device or hardware key."
                    ),
                })

        if all_ages:
            self.stats["avg_key_age_days"] = round(sum(all_ages) / len(all_ages))

        logger.info(f"Credential age analysis complete: {len(self.findings)} findings")
        return self.findings

    def get_stats(self) -> dict[str, Any]:
        """Return credential statistics summary."""
        return self.stats
