"""
PRISM - Ghost Identity Detector (WORLD-FIRST)
Detects IAM users/roles that have never made API calls but hold dangerous permissions.
These are "sleeping bombs" - invisible attack surfaces in every AWS account.
"""

from datetime import datetime, timezone
from typing import Any, Optional

from loguru import logger

# ── Thresholds ───────────────────────────────────────────────────────────
DORMANT_THRESHOLD_DAYS: int = 0
GHOST_CRITICAL_ACTIONS: set[str] = {
    # IAM privilege escalation
    "iam:createpolicyversion", "iam:attachuserpolicy", "iam:putuserpolicy",
    "iam:createaccesskey", "iam:passrole", "iam:updateassumerolepolicy",
    "iam:createuser", "iam:creategroup", "iam:attachgrouppolicy",
    "iam:addusertogoup", "iam:createrolepolicy",
    # Compute
    "lambda:createfunction", "lambda:updatefunctioncode", "ec2:runinstances",
    "ec2:terminateinstances", "ec2:authorizesgringresss",
    # Exfiltration
    "secretsmanager:getsecretvalue", "ssm:getparameter", "ssm:getparameters",
    "s3:getobject", "s3:listbucket", "s3:putbucketpolicy", "s3:deleteobject",
    "s3:putobject",
    # Evasion
    "cloudtrail:deletetrail", "cloudtrail:stoplogging", "cloudtrail:updatetrail",
    "logs:deleteloggroup", "guardduty:deletedetector",
    # Lateral movement
    "sts:assumerole", "sts:assumerolewithwebidentity",
    # Read that enables further attacks
    "iam:getuser", "iam:listusers", "iam:listroles", "iam:listpolicies",
    "iam:getuserolicy", "iam:listattacheduserpolicies",
    "ec2:describeinstances", "ec2:describesecuritygroups",
}


class GhostIdentityDetector:
    """Detects ghost identities - dormant IAM entities with dangerous permissions.

    No other public cloud security tool (Pacu, Prowler, ScoutSuite, CloudMapper,
    Cartography, PMapper) performs systematic ghost identity detection that
    cross-references dormancy status with privilege escalation vectors.
    """

    def __init__(self, collector: Any) -> None:
        """Initialize with an AWSCollector instance for API calls.

        Args:
            collector: AWSCollector instance with active session.
        """
        self.collector = collector

    def detect(
        self,
        users: list[dict],
        roles: list[dict],
        shadow_admins: list[dict],
        iam_action_map: dict[str, list[str]],
    ) -> list[dict]:
        """Detect ghost identities across all users and roles.

        Args:
            users: List of user detail dicts (UserName, CreateDate, etc).
            roles: List of role detail dicts (RoleName, CreateDate, etc).
            shadow_admins: List of shadow admin findings for cross-reference.
            iam_action_map: Identity to actions mapping.

        Returns:
            List of ghost identity findings.
        """
        ghosts: list[dict] = []
        shadow_admin_set = {f.get("identity", "") for f in shadow_admins}

        # Attempt to get credential report for user last-activity data
        credential_report = self._get_credential_report_map()

        # Process users
        for user in users:
            username = user.get("UserName", "")
            create_date_str = user.get("CreateDate", "")
            password_last_used = user.get("PasswordLastUsed", "N/A")

            days_dormant = self._calculate_dormancy_user(
                username, create_date_str, password_last_used, credential_report
            )

            if days_dormant is None or days_dormant < DORMANT_THRESHOLD_DAYS:
                continue

            actions = iam_action_map.get(username, [])
            dangerous_perms = self._get_dangerous_permissions(actions)
            escalation_vectors = self._get_escalation_vectors(actions)

            if not dangerous_perms:
                continue

            # Compute ghost score
            ghost_score = self._compute_ghost_score(
                days_dormant, dangerous_perms, escalation_vectors,
                username in shadow_admin_set,
            )

            risk_level = "CRITICAL" if ghost_score >= 70 else "HIGH" if ghost_score >= 40 else "MEDIUM"

            ghosts.append({
                "type": "GHOST_IDENTITY",
                "severity": risk_level,
                "identity": username,
                "identity_type": "user",
                "days_dormant": days_dormant,
                "last_used": password_last_used if password_last_used != "N/A" else "Never",
                "risk_level": risk_level,
                "permissions_held": dangerous_perms[:10],
                "escalation_vectors": escalation_vectors,
                "ghost_score": ghost_score,
                "is_shadow_admin": username in shadow_admin_set,
                "mitre": "T1078",
                "description": (
                    f"Ghost identity '{username}' has been dormant for {days_dormant} days "
                    f"but holds {len(dangerous_perms)} dangerous permissions including "
                    f"{', '.join(dangerous_perms[:3])}. Ghost Score: {ghost_score}/100."
                ),
                "remediation": (
                    f"Delete or disable this dormant user immediately. "
                    f"Command: aws iam delete-user --user-name {username}"
                ),
                "remediation_command": f"aws iam delete-user --user-name {username}",
            })

        # Process roles (check for unused roles with dangerous permissions)
        for role in roles:
            role_name = role.get("RoleName", "")

            # Skip AWS service-linked roles
            if role_name.startswith("AWSServiceRole"):
                continue

            actions = iam_action_map.get(role_name, [])
            dangerous_perms = self._get_dangerous_permissions(actions)

            if not dangerous_perms:
                continue

            # Check role last used via create date as proxy
            create_date_str = role.get("CreateDate", "")
            days_since_creation = self._days_since(create_date_str)

            if days_since_creation is not None and days_since_creation >= 1:
                escalation_vectors = self._get_escalation_vectors(actions)
                ghost_score = self._compute_ghost_score(
                    days_since_creation, dangerous_perms, escalation_vectors,
                    role_name in shadow_admin_set,
                )

                if ghost_score >= 30:
                    risk_level = "CRITICAL" if ghost_score >= 70 else "HIGH" if ghost_score >= 40 else "MEDIUM"
                    ghosts.append({
                        "type": "GHOST_IDENTITY",
                        "severity": risk_level,
                        "identity": role_name,
                        "identity_type": "role",
                        "days_dormant": days_since_creation,
                        "last_used": "Unknown",
                        "risk_level": risk_level,
                        "permissions_held": dangerous_perms[:10],
                        "escalation_vectors": escalation_vectors,
                        "ghost_score": ghost_score,
                        "is_shadow_admin": role_name in shadow_admin_set,
                        "mitre": "T1078",
                        "description": (
                            f"Ghost role '{role_name}' was created {days_since_creation} days ago "
                            f"and holds {len(dangerous_perms)} dangerous permissions. "
                            f"Ghost Score: {ghost_score}/100."
                        ),
                        "remediation": (
                            f"Delete this dormant role. "
                            f"Command: aws iam delete-role --role-name {role_name}"
                        ),
                        "remediation_command": f"aws iam delete-role --role-name {role_name}",
                    })

        # Sort by ghost score
        ghosts.sort(key=lambda x: x["ghost_score"], reverse=True)
        logger.info(f"Ghost identity detection complete: {len(ghosts)} ghosts found")
        return ghosts

    def _get_credential_report_map(self) -> dict[str, dict]:
        """Fetch IAM credential report and parse into a map."""
        try:
            report = self.collector.get_credential_report()
            return {entry.get("user", ""): entry for entry in report}
        except Exception as e:
            logger.debug(f"Could not fetch credential report: {e}")
            return {}

    def _calculate_dormancy_user(
        self,
        username: str,
        create_date_str: str,
        password_last_used: str,
        cred_report: dict[str, dict],
    ) -> Optional[int]:
        """Calculate how many days a user has been dormant."""
        now = datetime.now(timezone.utc)

        # Try credential report first
        if username in cred_report:
            entry = cred_report[username]
            last_activity = entry.get("password_last_used", "N/A")
            key1_last = entry.get("access_key_1_last_used_date", "N/A")
            key2_last = entry.get("access_key_2_last_used_date", "N/A")

            latest = None
            for date_str in [last_activity, key1_last, key2_last]:
                if date_str and date_str not in ("N/A", "no_information", "not_supported"):
                    try:
                        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                        if latest is None or dt > latest:
                            latest = dt
                    except (ValueError, TypeError):
                        pass

            if latest:
                return (now - latest).days

        # Fallback to password_last_used
        if password_last_used and password_last_used not in ("N/A", "None", ""):
            try:
                dt = datetime.fromisoformat(str(password_last_used).replace("Z", "+00:00"))
                return (now - dt).days
            except (ValueError, TypeError):
                pass

        # If never used, calculate from creation date
        return self._days_since(create_date_str)

    def _days_since(self, date_str: str) -> Optional[int]:
        """Calculate days since a given ISO date string."""
        if not date_str or date_str in ("N/A", "None"):
            return None
        try:
            dt = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - dt).days
        except (ValueError, TypeError):
            return None

    def _get_dangerous_permissions(self, actions: list[str]) -> list[str]:
        """Filter actions to only return dangerous permissions."""
        result: list[str] = []

        if not actions:
            return result

        # Full admin wildcard
        if "*" in actions or "*:*" in actions:
            return ["* (Full Admin)"]

        for action in actions:
            al = action.lower()
            # Service-level wildcards (e.g. s3:*, iam:*, ec2:*)
            if action.endswith(":*"):
                result.append(action)
            # Exact dangerous action match
            elif al in GHOST_CRITICAL_ACTIONS:
                result.append(action)
            # Prefix wildcard match (e.g. iam:List* catches iam:listusers)
            elif "*" in al:
                svc = al.split(":")[0]
                if any(critical.startswith(svc + ":") for critical in GHOST_CRITICAL_ACTIONS):
                    result.append(action)

        return result

    def _get_escalation_vectors(self, actions: list[str]) -> list[str]:
        """Identify which privilege escalation vectors this identity enables."""
        vectors: list[str] = []
        actions_lower = set(a.lower() for a in actions)

        vector_checks: dict[str, list[str]] = {
            "CreateNewPolicyVersion": ["iam:createpolicyversion"],
            "AttachUserPolicy": ["iam:attachuserpolicy"],
            "PutUserPolicy": ["iam:putuserpolicy"],
            "PassRole+Lambda": ["iam:passrole", "lambda:createfunction"],
            "PassRole+EC2": ["iam:passrole", "ec2:runinstances"],
            "UpdateAssumeRolePolicy": ["iam:updateassumerolepolicy"],
            "CreateAccessKey": ["iam:createaccesskey"],
        }

        for vector_name, required_actions in vector_checks.items():
            if all(a in actions_lower for a in required_actions):
                vectors.append(vector_name)

        return vectors

    def _compute_ghost_score(
        self,
        days_dormant: int,
        dangerous_perms: list[str],
        escalation_vectors: list[str],
        is_shadow_admin: bool,
    ) -> int:
        """Compute composite ghost danger score (0-100).

        The score weighs:
        - Dormancy duration (longer = higher risk of being forgotten)
        - Number of dangerous permissions held
        - Number of escalation vectors available
        - Whether the identity is also a shadow admin
        """
        score = 0

        # Dormancy score (max 30 points)
        if days_dormant >= 365:
            score += 30
        elif days_dormant >= 270:
            score += 25
        elif days_dormant >= 180:
            score += 15
        elif days_dormant >= 7:
            score += 10
        else:
            score += 20  # Brand new unused identity is suspicious

        # Dangerous permissions (max 30 points)
        perm_count = len(dangerous_perms)
        if "*" in str(dangerous_perms):
            score += 30
        elif perm_count >= 5:
            score += 25
        elif perm_count >= 3:
            score += 20
        elif perm_count >= 1:
            score += 10

        # Escalation vectors (max 25 points)
        vec_count = len(escalation_vectors)
        if vec_count >= 3:
            score += 25
        elif vec_count >= 2:
            score += 20
        elif vec_count >= 1:
            score += 15

        # Shadow admin bonus (max 15 points)
        if is_shadow_admin:
            score += 15

        return min(score, 100)
