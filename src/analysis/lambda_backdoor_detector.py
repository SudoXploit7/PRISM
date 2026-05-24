"""
PRISM -- Lambda Backdoor Detector
Detects Lambda functions that could serve as backdoors or privilege escalation vectors.
"""

from typing import Any

from loguru import logger


class LambdaBackdoorDetector:
    """Detects Lambda-based privilege escalation and backdoor risks."""

    def __init__(self) -> None:
        self.findings: list[dict] = []

    def analyze(
        self,
        lambda_functions: list[dict],
        iam_action_map: dict[str, list[str]],
        admin_roles: list[str],
    ) -> list[dict]:
        """Analyze Lambda functions for backdoor and escalation risks.

        Args:
            lambda_functions: List of Lambda function configurations.
            iam_action_map: Identity to actions mapping.
            admin_roles: List of admin role names.

        Returns:
            List of Lambda backdoor findings.
        """
        for fn in lambda_functions:
            fn_name = fn.get("FunctionName", "")
            fn_role = fn.get("Role", "")
            role_name = fn_role.split("/")[-1] if "/" in fn_role else fn_role

            # Check if Lambda uses an admin role
            if role_name in admin_roles:
                self.findings.append({
                    "type": "LAMBDA_ADMIN_ROLE",
                    "severity": "CRITICAL",
                    "identity": fn_name,
                    "resource": fn_role,
                    "mitre": "T1098",
                    "description": (
                        f"Lambda function '{fn_name}' uses admin role '{role_name}'. "
                        f"An attacker who can modify this function gains full admin access."
                    ),
                    "remediation": (
                        f"Create a least-privilege execution role for '{fn_name}'. "
                        f"Remove AdministratorAccess from '{role_name}'."
                    ),
                })

            # Check for sensitive environment variables
            env_vars = fn.get("Environment", {}).get("Variables", {})
            sensitive_keys = {"AWS_ACCESS_KEY", "AWS_SECRET", "PASSWORD", "SECRET", "TOKEN", "API_KEY"}
            for key in env_vars:
                if any(s in key.upper() for s in sensitive_keys):
                    self.findings.append({
                        "type": "LAMBDA_HARDCODED_SECRET",
                        "severity": "HIGH",
                        "identity": fn_name,
                        "resource": key,
                        "mitre": "T1528",
                        "description": (
                            f"Lambda '{fn_name}' has sensitive environment variable '{key}'. "
                            f"Hardcoded secrets are exfiltrable by anyone with lambda:GetFunction."
                        ),
                        "remediation": (
                            f"Move secrets to AWS Secrets Manager or SSM Parameter Store. "
                            f"Remove '{key}' from Lambda environment variables."
                        ),
                    })

        # Check for identities that can modify Lambda functions
        for identity, actions in iam_action_map.items():
            actions_lower = set(a.lower() for a in actions)
            if "lambda:updatefunctioncode" in actions_lower:
                self.findings.append({
                    "type": "LAMBDA_CODE_INJECTION",
                    "severity": "HIGH",
                    "identity": identity,
                    "resource": "ALL_FUNCTIONS",
                    "mitre": "T1525",
                    "description": (
                        f"Identity '{identity}' can modify Lambda function code "
                        f"(lambda:UpdateFunctionCode). This enables code injection "
                        f"into any existing Lambda function."
                    ),
                    "remediation": (
                        f"Remove lambda:UpdateFunctionCode from '{identity}' "
                        f"or restrict to specific function ARNs via resource conditions."
                    ),
                })

        logger.info(f"Lambda backdoor analysis complete: {len(self.findings)} findings")
        return self.findings
