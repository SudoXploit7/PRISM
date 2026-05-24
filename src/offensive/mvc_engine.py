"""
PRISM -- Minimum Viable Compromise (MVC) Engine
Finds the shortest attack path from any identity to full admin using BFS.
The attacker's core question: given this leaked key, fastest path to owning the account?
"""
from __future__ import annotations
from typing import Any
from loguru import logger
from collections import deque

ACTION_COST = {
    "AssumeRole": 15, "CreatePolicyVersion": 20, "AttachUserPolicy": 10,
    "PutUserPolicy": 10, "AttachRolePolicy": 10, "PutRolePolicy": 10,
    "CreateFunction_PassRole": 45, "UpdateFunctionCode": 30,
    "CreateLoginProfile": 15, "CreateAccessKey": 10, "default": 30,
}
MITRE_MAP = {
    "AssumeRole": "T1098", "CreatePolicyVersion": "T1098",
    "AttachUserPolicy": "T1098", "PutUserPolicy": "T1098",
    "CreateFunction_PassRole": "T1648", "CreateAccessKey": "T1098.001",
    "CreateLoginProfile": "T1136.003",
}
LOGGED_ACTIONS = {
    "AssumeRole", "CreatePolicyVersion", "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "CreateFunction_PassRole", "CreateAccessKey", "CreateLoginProfile",
}

class MVCEngine:
    """Minimum Viable Compromise Engine - shortest path to admin."""

    def analyze(self, iam_action_map, trusts, admin_roles, shadow_findings, privesc_findings):
        admin_set = set(admin_roles)
        for f in shadow_findings:
            if f.get("identity"):
                admin_set.add(f["identity"])
        for identity, actions in iam_action_map.items():
            aset = set(a.lower() for a in actions)
            if "*" in aset or "iam:*" in aset:
                admin_set.add(identity)

        all_paths = []
        for identity in iam_action_map:
            if identity in admin_set:
                all_paths.append(self._already_admin(identity))
                continue
            path = self._bfs(identity, iam_action_map, trusts, admin_set, privesc_findings)
            if path:
                all_paths.append(path)

        all_paths.sort(key=lambda p: (p.get("hops", 99), p.get("total_seconds", 9999)))
        zero = [p for p in all_paths if p.get("hops") == 0]
        one  = [p for p in all_paths if p.get("hops") == 1]
        two  = [p for p in all_paths if p.get("hops") == 2]
        fastest = min(
            (p for p in all_paths if p.get("hops", 0) > 0),
            key=lambda p: p.get("total_seconds", 9999), default=None
        )
        return {
            "paths": all_paths[:20],
            "total_paths": len(all_paths),
            "zero_hop_count": len(zero),
            "one_hop_count": len(one),
            "two_hop_count": len(two),
            "fastest_path": fastest,
            "fastest_seconds": fastest["total_seconds"] if fastest else None,
            "account_rating": self._rate(all_paths),
        }

    def _already_admin(self, identity):
        return {
            "start_identity": identity, "hops": 0, "total_seconds": 0,
            "steps": [{"action": "Already Administrator", "target": "ACCOUNT_ROOT",
                       "via": "Direct admin policy", "seconds": 0,
                       "logged": True, "mitre": "T1078.004",
                       "command": "# Identity already has administrator access"}],
            "logged_steps": 1, "blind_steps": 0, "severity": "CRITICAL", "cvss_score": 10.0,
        }

    def _bfs(self, start, iam_action_map, trusts, admin_set, privesc_findings):
        adj = self._adj(iam_action_map, trusts, admin_set, privesc_findings)
        queue = deque([(start, [], 0)])
        visited = {start}
        while queue:
            cur, path_so_far, cost = queue.popleft()
            for nxt, action, act_cost, cmd in adj.get(cur, []):
                step = {"action": action, "target": nxt, "via": f"{cur} -> {nxt}",
                        "seconds": act_cost, "logged": action in LOGGED_ACTIONS,
                        "mitre": MITRE_MAP.get(action, "T1078"), "command": cmd}
                new_path = path_so_far + [step]
                new_cost = cost + act_cost
                if nxt in admin_set or nxt == "ADMIN":
                    blind = sum(1 for s in new_path if not s["logged"])
                    return {
                        "start_identity": start, "hops": len(new_path),
                        "total_seconds": new_cost, "steps": new_path,
                        "logged_steps": len(new_path) - blind, "blind_steps": blind,
                        "severity": "CRITICAL" if new_cost < 60 else "HIGH",
                        "cvss_score": 9.9 if len(new_path) <= 2 else 8.8,
                        "end_identity": nxt,
                    }
                if nxt not in visited and len(new_path) < 4:
                    visited.add(nxt)
                    queue.append((nxt, new_path, new_cost))
        return None

    # Maps dangerous IAM actions directly to an (edge_label, cost, command) tuple.
    # This lets BFS discover paths even when PrivescPathDetector found nothing
    # or when trust relationships are absent.
    _ACTION_EDGES: dict = {
        "iam:createpolicyversion":       ("CreatePolicyVersion",      20, "aws iam create-policy-version --policy-arn <ARN> --policy-document file://admin.json --set-as-default"),
        "iam:setdefaultpolicyversion":   ("SetDefaultPolicyVersion",  20, "aws iam set-default-policy-version --policy-arn <ARN> --version-id v<N>"),
        "iam:attachuserpolicy":          ("AttachUserPolicy",         10, "aws iam attach-user-policy --user-name <USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"),
        "iam:attachrolepolicy":          ("AttachRolePolicy",         10, "aws iam attach-role-policy --role-name <ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"),
        "iam:putuserupolicy":            ("PutUserPolicy",            10, "aws iam put-user-policy --user-name <USER> --policy-name bd --policy-document file://admin.json"),
        "iam:putrolepolicy":             ("PutRolePolicy",            10, "aws iam put-role-policy --role-name <ROLE> --policy-name bd --policy-document file://admin.json"),
        "iam:updateassumerolepolicy":    ("UpdateAssumeRolePolicy",   15, "aws iam update-assume-role-policy --role-name <ADMIN_ROLE> --policy-document file://trust.json"),
        "iam:createaccesskey":           ("CreateAccessKey",          10, "aws iam create-access-key --user-name <ADMIN_USER>"),
        "iam:createloginprofile":        ("CreateLoginProfile",       15, "aws iam create-login-profile --user-name <USER> --password 'P@ss!' --no-password-reset-required"),
        "iam:updateloginprofile":        ("UpdateLoginProfile",       15, "aws iam update-login-profile --user-name <ADMIN_USER> --password 'NewP@ss!'"),
        "lambda:updatefunctioncode":     ("UpdateFunctionCode",       30, "aws lambda update-function-code --function-name <FN> --zip-file fileb://payload.zip"),
        "iam:attachgrouppolicy":         ("AttachGroupPolicy",        10, "aws iam attach-group-policy --group-name <GROUP> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"),
        "iam:putgrouppolicy":            ("PutGroupPolicy",           10, "aws iam put-group-policy --group-name <GROUP> --policy-name bd --policy-document file://admin.json"),
        "iam:addusertogroup":            ("AddUserToGroup",           10, "aws iam add-user-to-group --group-name <ADMIN_GROUP> --user-name <USER>"),
    }

    def _adj(self, iam_action_map, trusts, admin_set, privesc_findings):
        adj = {}
        def add(s, d, a, c, cmd): adj.setdefault(s, []).append((d, a, c, cmd))

        # 1. Trust-based lateral movement (AssumeRole chains)
        for src, dst, rel in trusts:
            sn = src.split("/")[-1] if "/" in src else src
            if rel in ("AssumeRole", "sts:AssumeRole"):
                add(sn, dst, "AssumeRole", ACTION_COST["AssumeRole"],
                    f"aws sts assume-role --role-arn <ARN_OF_{dst}> --role-session-name attack")

        # 2. Direct privilege escalation from PrivescPathDetector findings
        for f in privesc_findings:
            identity, vector = f.get("identity", ""), f.get("vector_name", "")
            if identity and vector:
                cost = ACTION_COST.get(vector.replace(" ", ""), ACTION_COST["default"])
                add(identity, "ADMIN", vector, cost,
                    f.get("attack_command", f"# {vector} exploit"))

        # 3. Direct IAM-action-to-ADMIN edges built from the action map itself.
        #    This is the critical path for accounts where PrivescPathDetector
        #    produced no findings and no trust relationships exist.
        for identity, actions in iam_action_map.items():
            aset = set(a.lower() for a in actions)
            wildcard = "*" in aset or "iam:*" in aset

            if wildcard:
                # Already handled in analyze() as admin_set; add edge anyway
                # so BFS can reach ADMIN from identities not yet in admin_set
                add(identity, "ADMIN", "ExplicitAdmin", 0, "# Identity already has administrator access")
                continue

            # Check every dangerous single-action vector
            for action_lower, (label, cost, cmd) in self._ACTION_EDGES.items():
                svc_wildcard = action_lower.split(":")[0] + ":*"
                if action_lower in aset or svc_wildcard in aset:
                    add(identity, "ADMIN", label, cost, cmd)
                    break  # One edge per identity is enough for BFS to find the path

            # PassRole + service combos (2-action vectors)
            if "iam:passrole" in aset or "iam:*" in aset:
                for svc_action, label, cost, cmd in [
                    ("lambda:createfunction", "PassRole+Lambda",      45, "aws lambda create-function --function-name bd --runtime python3.12 --role <ADMIN_ROLE_ARN> --handler h.handler --zip-file fileb://p.zip"),
                    ("ec2:runinstances",       "PassRole+EC2",         60, "aws ec2 run-instances --image-id <AMI> --instance-type t3.micro --iam-instance-profile Name=<ADMIN_PROFILE>"),
                    ("cloudformation:createstack", "PassRole+CFN",    90, "aws cloudformation create-stack --stack-name bd --template-body file://admin.yaml --capabilities CAPABILITY_NAMED_IAM"),
                    ("glue:createdevendpoint", "PassRole+Glue",        90, "aws glue create-dev-endpoint --endpoint-name bd --role-arn <ADMIN_ROLE_ARN>"),
                    ("sagemaker:createnotebookinstance", "PassRole+SageMaker", 120, "aws sagemaker create-notebook-instance --notebook-instance-name bd --instance-type ml.t2.medium --role-arn <ADMIN_ROLE_ARN>"),
                ]:
                    if svc_action in aset or svc_action.split(":")[0] + ":*" in aset:
                        add(identity, "ADMIN", label, cost, cmd)
                        break

        return adj

    def _rate(self, paths):
        if sum(1 for p in paths if p.get("hops") == 0) and sum(1 for p in paths if p.get("hops") == 1):
            return "CATASTROPHIC"
        if any(p.get("hops") == 0 for p in paths): return "CRITICAL"
        if any(p.get("hops") == 1 for p in paths): return "HIGH"
        if any(p.get("hops") == 2 for p in paths): return "MEDIUM"
        return "LOW"