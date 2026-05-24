"""
PRISM - 3D Blast Radius Calculator (WORLD-FIRST)
Computes multi-dimensional blast radius for each compromised identity across
5 dimensions: Data, Compute, Identity, Billing, and Logging.
"""

from typing import Any

from loguru import logger

# ── EC2 Pricing for billing blast estimate ───────────────────────────────
# Hourly rates for expensive instance types (USD)
EXPENSIVE_INSTANCES: dict[str, float] = {
    "p4d.24xlarge": 32.77,
    "p3.16xlarge": 24.48,
    "p3dn.24xlarge": 31.22,
    "g5.48xlarge": 16.29,
    "inf1.24xlarge": 12.92,
    "x2idn.32xlarge": 13.34,
    "r5.24xlarge": 6.048,
}
HOURS_PER_MONTH: int = 720

# ── Service Action Categories ────────────────────────────────────────────
DATA_ACTIONS: set[str] = {
    "s3:getobject", "s3:putobject", "s3:deleteobject", "s3:listbucket",
    "s3:putbucketpolicy", "s3:*",
    "secretsmanager:getsecretvalue", "secretsmanager:*",
    "ssm:getparameter", "ssm:getparameters", "ssm:*",
    "dynamodb:getitem", "dynamodb:scan", "dynamodb:query", "dynamodb:*",
    "rds:*",
}

COMPUTE_ACTIONS: set[str] = {
    "ec2:runinstances", "ec2:terminateinstances", "ec2:stopinstances",
    "ec2:*", "lambda:createfunction", "lambda:invokefunction",
    "lambda:deletefunction", "lambda:updatefunctioncode", "lambda:*",
    "ecs:runtask", "ecs:*", "eks:*",
}

IDENTITY_ACTIONS: set[str] = {
    "iam:createuser", "iam:deleteuser", "iam:attachuserpolicy",
    "iam:putuserpolicy", "iam:createaccesskey", "iam:createloginprofile",
    "iam:updateloginprofile", "iam:addusertogroup", "iam:createrole",
    "iam:attachrolepolicy", "iam:putrolepolicy", "iam:passrole",
    "iam:updateassumerolepolicy", "iam:createpolicyversion", "iam:*",
    "sts:assumerole", "sts:*",
}

BILLING_ACTIONS: set[str] = {
    "ec2:runinstances", "ec2:*",
    "lambda:createfunction", "lambda:*",
    "rds:createdbinstance", "rds:*",
    "sagemaker:createnotebookinstance", "sagemaker:*",
    "redshift:createcluster", "redshift:*",
    "elasticache:createcachecluster", "elasticache:*",
}

LOGGING_ACTIONS: set[str] = {
    "cloudtrail:deletetrail", "cloudtrail:stoplogging",
    "cloudtrail:updatetrail", "cloudtrail:*",
    "logs:deleteloggroup", "logs:*",
    "cloudwatch:deletealarms", "cloudwatch:*",
    "guardduty:deletedetector", "guardduty:*",
    "config:stopconfigurationrecorder", "config:*",
}


class BlastRadius3D:
    """Computes multi-dimensional blast radius for IAM identities.

    Dimensions:
    1. Data - S3, Secrets, SSM, DynamoDB access
    2. Compute - EC2, Lambda, ECS workload disruption
    3. Identity - IAM user/role creation/modification
    4. Billing - maximum fraudulent cost potential
    5. Logging - ability to destroy audit trails
    """

    def compute(
        self,
        identity: str,
        actions: list[str],
        scan_results: dict[str, Any],
    ) -> dict[str, Any]:
        """Compute blast radius for a single identity.

        Args:
            identity: IAM identity name.
            actions: List of allowed actions for this identity.
            scan_results: Full scan results for resource counts.

        Returns:
            Blast radius analysis with scores per dimension.
        """
        actions_lower = set(a.lower() for a in actions)
        has_wildcard = "*" in actions

        # Count affected resources
        s3_count = len(scan_results.get("s3_buckets", []))
        secrets_count = len(scan_results.get("secrets", []))
        ssm_count = len(scan_results.get("ssm_params", []))
        ec2_count = len(scan_results.get("ec2_instances", []))
        lambda_count = len(scan_results.get("lambda_functions", []))
        users_count = len(scan_results.get("users", []))
        roles_count = len(scan_results.get("roles", []))

        # Compute each dimension
        data_dim = self._compute_data_blast(
            actions_lower, has_wildcard, s3_count, secrets_count, ssm_count
        )
        compute_dim = self._compute_compute_blast(
            actions_lower, has_wildcard, ec2_count, lambda_count
        )
        identity_dim = self._compute_identity_blast(
            actions_lower, has_wildcard, users_count, roles_count
        )
        billing_dim = self._compute_billing_blast(actions_lower, has_wildcard)
        logging_dim = self._compute_logging_blast(actions_lower, has_wildcard)

        # Overall score (weighted)
        overall = (
            data_dim["score"] * 0.25 +
            compute_dim["score"] * 0.20 +
            identity_dim["score"] * 0.25 +
            billing_dim["score"] * 0.15 +
            logging_dim["score"] * 0.15
        )
        overall_score = min(round(overall), 1000)

        # Generate worst-case narrative
        worst_case = self._generate_worst_case(
            identity, data_dim, compute_dim, identity_dim, billing_dim, logging_dim
        )

        return {
            "identity": identity,
            "overall_blast_score": overall_score,
            "dimensions": {
                "data": data_dim,
                "compute": compute_dim,
                "identity": identity_dim,
                "billing": billing_dim,
                "logging": logging_dim,
            },
            "worst_case_scenario": worst_case,
            "has_wildcard": has_wildcard,
        }

    def _compute_data_blast(
        self, actions: set[str], wildcard: bool, s3: int, secrets: int, ssm: int
    ) -> dict[str, Any]:
        """Compute data dimension blast radius."""
        score = 0
        affected: list[str] = []

        if wildcard or actions & {"s3:*", "s3:getobject", "s3:deleteobject"}:
            score += min(s3 * 50, 400)
            affected.append(f"{s3} S3 buckets")

        if wildcard or actions & {"secretsmanager:getsecretvalue", "secretsmanager:*"}:
            score += min(secrets * 100, 300)
            affected.append(f"{secrets} secrets")

        if wildcard or actions & {"ssm:getparameter", "ssm:*"}:
            score += min(ssm * 30, 200)
            affected.append(f"{ssm} SSM parameters")

        can_delete = wildcard or bool(actions & {"s3:deleteobject", "s3:*"})

        return {
            "score": min(score, 1000),
            "details": f"Can access {', '.join(affected) if affected else 'no data resources'}.",
            "affected_resources": affected,
            "can_delete": can_delete,
        }

    def _compute_compute_blast(
        self, actions: set[str], wildcard: bool, ec2: int, lambdas: int
    ) -> dict[str, Any]:
        """Compute compute dimension blast radius."""
        score = 0
        affected: list[str] = []

        if wildcard or actions & {"ec2:terminateinstances", "ec2:stopinstances", "ec2:*"}:
            score += min(ec2 * 100, 500)
            affected.append(f"{ec2} EC2 instances")

        if wildcard or actions & {"lambda:deletefunction", "lambda:updatefunctioncode", "lambda:*"}:
            score += min(lambdas * 80, 400)
            affected.append(f"{lambdas} Lambda functions")

        return {
            "score": min(score, 1000),
            "details": f"Can disrupt {', '.join(affected) if affected else 'no compute workloads'}.",
            "affected_resources": affected,
        }

    def _compute_identity_blast(
        self, actions: set[str], wildcard: bool, users: int, roles: int
    ) -> dict[str, Any]:
        """Compute identity dimension blast radius."""
        score = 0
        affected: list[str] = []

        matched = actions & IDENTITY_ACTIONS if not wildcard else IDENTITY_ACTIONS
        if wildcard or matched:
            score += min(len(matched) * 80, 600)
            if wildcard or actions & {"iam:createuser", "iam:*"}:
                affected.append("Create new admin users")
                score += 200
            if wildcard or actions & {"iam:createaccesskey", "iam:*"}:
                affected.append(f"Create keys for {users} users")
                score += 150
            if wildcard or actions & {"iam:passrole", "iam:*"}:
                affected.append(f"Pass {roles} roles to services")

        return {
            "score": min(score, 1000),
            "details": f"{'Can ' + ', '.join(affected[:3]) if affected else 'No identity modification capability'}.",
            "affected_resources": affected,
        }

    def _compute_billing_blast(
        self, actions: set[str], wildcard: bool
    ) -> dict[str, Any]:
        """Compute billing/financial blast radius."""
        max_cost = 0.0
        details_parts: list[str] = []

        can_launch = wildcard or actions & {"ec2:runinstances", "ec2:*"}
        if can_launch:
            # Worst case: 10 x p4d.24xlarge for a month
            cost = 10 * EXPENSIVE_INSTANCES["p4d.24xlarge"] * HOURS_PER_MONTH
            max_cost += cost
            details_parts.append(f"EC2 crypto-mining: ${cost:,.0f}/month")

        can_create_lambda = wildcard or actions & {"lambda:createfunction", "lambda:*"}
        if can_create_lambda:
            lambda_cost = 50000  # Estimated max Lambda abuse cost
            max_cost += lambda_cost
            details_parts.append(f"Lambda abuse: ${lambda_cost:,.0f}/month")

        score = min(int(max_cost / 500), 1000) if max_cost > 0 else 0

        return {
            "score": score,
            "max_fraudulent_cost_usd": round(max_cost, 2),
            "details": "; ".join(details_parts) if details_parts else "No significant billing blast.",
        }

    def _compute_logging_blast(
        self, actions: set[str], wildcard: bool
    ) -> dict[str, Any]:
        """Compute logging/audit trail blast radius."""
        matched = actions & LOGGING_ACTIONS if not wildcard else LOGGING_ACTIONS
        can_cover_tracks = bool(matched) or wildcard

        score = 0
        details_parts: list[str] = []

        if wildcard or actions & {"cloudtrail:deletetrail", "cloudtrail:stoplogging", "cloudtrail:*"}:
            score += 500
            details_parts.append("Can delete/stop CloudTrail")

        if wildcard or actions & {"logs:deleteloggroup", "logs:*"}:
            score += 300
            details_parts.append("Can delete CloudWatch logs")

        if wildcard or actions & {"guardduty:deletedetector", "guardduty:*"}:
            score += 200
            details_parts.append("Can disable GuardDuty")

        return {
            "score": min(score, 1000),
            "can_cover_tracks": can_cover_tracks,
            "details": "; ".join(details_parts) if details_parts else "Cannot destroy audit trails.",
        }

    def _generate_worst_case(
        self,
        identity: str,
        data: dict, compute: dict, ident: dict, billing: dict, logging: dict,
    ) -> str:
        """Generate plain-English worst-case scenario narrative."""
        parts: list[str] = []

        parts.append(
            f"If '{identity}' is compromised, an attacker could:"
        )

        if data["score"] > 0:
            parts.append(f"Access and potentially exfiltrate {data['details']}")

        if compute["score"] > 0:
            parts.append(f"Disrupt compute: {compute['details']}")

        if ident["score"] > 0:
            parts.append(f"Modify IAM: {ident['details']}")

        if billing["score"] > 0:
            cost = billing.get("max_fraudulent_cost_usd", 0)
            parts.append(f"Incur up to ${cost:,.0f} in fraudulent charges")

        if logging.get("can_cover_tracks"):
            parts.append("Cover their tracks by destroying audit logs")

        return " ".join(parts)
