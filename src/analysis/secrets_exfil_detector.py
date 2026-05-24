"""
PRISM -- Secrets Exfiltration Detector
Detects identities that can access sensitive secrets and SSM parameters.
"""

from typing import Any

from loguru import logger

# ── Dangerous secrets actions ────────────────────────────────────────────
SECRETS_READ_ACTIONS: set[str] = {
    "secretsmanager:getsecretvalue",
    "secretsmanager:listsecrets",
    "secretsmanager:*",
}

SSM_READ_ACTIONS: set[str] = {
    "ssm:getparameter",
    "ssm:getparameters",
    "ssm:getparameterbypath",
    "ssm:*",
}


class SecretsExfilDetector:
    """Detects identities capable of exfiltrating secrets."""

    def __init__(self) -> None:
        self.findings: list[dict] = []

    def analyze(
        self,
        iam_action_map: dict[str, list[str]],
        secrets: list[dict],
        ssm_params: list[dict],
    ) -> list[dict]:
        """Analyze for secrets exfiltration paths.

        Args:
            iam_action_map: Identity to actions mapping.
            secrets: List of Secrets Manager entries.
            ssm_params: List of SSM Parameter Store entries.

        Returns:
            List of exfiltration findings.
        """
        secret_count = len(secrets)
        ssm_count = len(ssm_params)

        for identity, actions in iam_action_map.items():
            actions_lower = set(a.lower() for a in actions)
            has_wildcard = "*" in actions

            # Check Secrets Manager access
            can_read_secrets = has_wildcard or bool(actions_lower & SECRETS_READ_ACTIONS)
            if can_read_secrets and secret_count > 0:
                self.findings.append({
                    "type": "SECRETS_EXFIL",
                    "severity": "CRITICAL",
                    "identity": identity,
                    "resource": f"{secret_count} secrets",
                    "mitre": "T1528",
                    "description": (
                        f"Identity '{identity}' can read {secret_count} secrets from "
                        f"AWS Secrets Manager. This includes: "
                        f"{', '.join(s['Name'] for s in secrets[:5])}"
                        f"{'...' if secret_count > 5 else ''}."
                    ),
                    "remediation": (
                        f"Restrict secretsmanager:GetSecretValue for '{identity}' "
                        f"to specific secret ARNs using resource-level permissions."
                    ),
                })

            # Check SSM Parameter access
            can_read_ssm = has_wildcard or bool(actions_lower & SSM_READ_ACTIONS)
            if can_read_ssm and ssm_count > 0:
                secure_params = [p for p in ssm_params if p.get("Type") == "SecureString"]
                if secure_params:
                    self.findings.append({
                        "type": "SSM_EXFIL",
                        "severity": "HIGH",
                        "identity": identity,
                        "resource": f"{len(secure_params)} secure parameters",
                        "mitre": "T1528",
                        "description": (
                            f"Identity '{identity}' can read {len(secure_params)} SecureString "
                            f"SSM parameters. These often contain database passwords, API keys, "
                            f"and other sensitive credentials."
                        ),
                        "remediation": (
                            f"Restrict ssm:GetParameter for '{identity}' "
                            f"using resource conditions on parameter paths."
                        ),
                    })

            # Combined attack: read secrets + create access keys = credential harvesting
            can_create_keys = has_wildcard or "iam:createaccesskey" in actions_lower
            if can_read_secrets and can_create_keys:
                self.findings.append({
                    "type": "CREDENTIAL_HARVESTER",
                    "severity": "CRITICAL",
                    "identity": identity,
                    "resource": "COMBINED_VECTOR",
                    "mitre": "T1528",
                    "description": (
                        f"Identity '{identity}' can both read secrets AND create IAM access keys. "
                        f"This is a complete credential harvesting capability - the attacker can "
                        f"steal all application secrets and create persistent access keys."
                    ),
                    "remediation": (
                        f"Remove either secretsmanager:GetSecretValue or iam:CreateAccessKey "
                        f"from '{identity}'. Apply permission boundaries."
                    ),
                })

        logger.info(f"Secrets exfiltration analysis complete: {len(self.findings)} findings")
        return self.findings
