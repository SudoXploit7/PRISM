"""
PRISM -- Assumed Breach Simulator
Maps every possible attacker move from a given compromised identity.
"""
from __future__ import annotations
from typing import Any
from loguru import logger

CATALOG = [
    {"action":"iam:CreatePolicyVersion",   "category":"Privilege Escalation","impact":"Create admin policy version",          "cvss":9.9,"logged":True, "mitre":"T1098"},
    {"action":"iam:AttachUserPolicy",       "category":"Privilege Escalation","impact":"Attach AdministratorAccess to self",   "cvss":9.9,"logged":True, "mitre":"T1098"},
    {"action":"iam:PutUserPolicy",          "category":"Privilege Escalation","impact":"Inject inline admin policy",           "cvss":9.9,"logged":True, "mitre":"T1098"},
    {"action":"iam:AttachRolePolicy",       "category":"Privilege Escalation","impact":"Attach admin policy to assumable role","cvss":8.8,"logged":True, "mitre":"T1098"},
    {"action":"lambda:CreateFunction",      "category":"Privilege Escalation","impact":"Deploy Lambda with admin role via PassRole","cvss":9.5,"logged":True,"mitre":"T1648"},
    {"action":"sts:AssumeRole",             "category":"Lateral Movement",    "impact":"Assume higher-privilege role",         "cvss":8.8,"logged":True, "mitre":"T1098"},
    {"action":"iam:CreateAccessKey",        "category":"Persistence",         "impact":"Create persistent backdoor access key","cvss":8.5,"logged":True, "mitre":"T1098.001"},
    {"action":"iam:CreateLoginProfile",     "category":"Persistence",         "impact":"Create console login for target user", "cvss":8.5,"logged":True, "mitre":"T1136.003"},
    {"action":"iam:CreateUser",             "category":"Persistence",         "impact":"Create new backdoor admin user",       "cvss":9.0,"logged":True, "mitre":"T1136.003"},
    {"action":"cloudtrail:StopLogging",     "category":"Defense Evasion",     "impact":"Stop all CloudTrail logging",         "cvss":9.1,"logged":True, "mitre":"T1562.008"},
    {"action":"cloudtrail:DeleteTrail",     "category":"Defense Evasion",     "impact":"Permanently delete audit trail",      "cvss":9.1,"logged":True, "mitre":"T1562.008"},
    {"action":"logs:DeleteLogGroup",        "category":"Defense Evasion",     "impact":"Erase CloudWatch log groups",         "cvss":7.5,"logged":False,"mitre":"T1562.008"},
    {"action":"guardduty:DeleteDetector",   "category":"Defense Evasion",     "impact":"Disable GuardDuty threat detection",  "cvss":8.0,"logged":True, "mitre":"T1562.001"},
    {"action":"s3:GetObject",               "category":"Exfiltration",        "impact":"Read all S3 bucket contents",         "cvss":7.5,"logged":False,"mitre":"T1530"},
    {"action":"secretsmanager:GetSecretValue","category":"Exfiltration",      "impact":"Read all secrets and credentials",    "cvss":8.5,"logged":True, "mitre":"T1552"},
    {"action":"ssm:GetParameter",           "category":"Exfiltration",        "impact":"Read SSM Parameter Store values",     "cvss":7.5,"logged":True, "mitre":"T1552"},
    {"action":"rds:CreateDBSnapshot",       "category":"Exfiltration",        "impact":"Snapshot database for exfiltration",  "cvss":7.5,"logged":True, "mitre":"T1537"},
    {"action":"iam:ListUsers",              "category":"Discovery",           "impact":"Enumerate all IAM users",             "cvss":5.0,"logged":False,"mitre":"T1087.004"},
    {"action":"ec2:DescribeInstances",      "category":"Discovery",           "impact":"Enumerate all EC2 instances",         "cvss":5.0,"logged":False,"mitre":"T1580"},
    {"action":"s3:ListAllMyBuckets",        "category":"Discovery",           "impact":"Enumerate all S3 buckets",            "cvss":5.0,"logged":False,"mitre":"T1580"},
    {"action":"ec2:TerminateInstances",     "category":"Impact",              "impact":"Terminate all EC2 instances",         "cvss":8.6,"logged":True, "mitre":"T1529"},
    {"action":"s3:DeleteObject",            "category":"Impact",              "impact":"Delete all S3 data (ransomware)",     "cvss":9.0,"logged":True, "mitre":"T1485"},
    {"action":"kms:ScheduleKeyDeletion",    "category":"Impact",              "impact":"Schedule deletion of encryption keys","cvss":9.0,"logged":True, "mitre":"T1485"},
]
CATEGORIES = ["Discovery","Privilege Escalation","Lateral Movement","Persistence","Defense Evasion","Exfiltration","Impact"]
CAT_COLORS = {"Discovery":"#3b82f6","Privilege Escalation":"#ef4444","Lateral Movement":"#f59e0b",
              "Persistence":"#8b5cf6","Defense Evasion":"#06b6d4","Exfiltration":"#ec4899","Impact":"#ef4444"}

class AssumedBreachSimulator:
    def simulate(self, start_identity, iam_action_map, trusts, scan_results):
        actions = iam_action_map.get(start_identity, [])
        aset = set(a.lower() for a in actions)
        wildcard = "*" in aset or "iam:*" in aset

        available = []
        for item in CATALOG:
            al = item["action"].lower()
            ap = al.split(":")[0] + ":*"
            avail = wildcard or al in aset or ap in aset
            available.append({**item, "available": avail})

        by_cat = {c: [] for c in CATEGORIES}
        for m in available:
            cat = m.get("category","Discovery")
            if cat in by_cat: by_cat[cat].append(m)

        avail_moves = [m for m in available if m["available"]]
        critical = [m for m in avail_moves if m["cvss"] >= 9.0]
        high     = [m for m in avail_moves if 7.0 <= m["cvss"] < 9.0]
        timeline = self._timeline(avail_moves)
        return {
            "start_identity": start_identity,
            "total_moves": len(available),
            "available_moves": len(avail_moves),
            "critical_moves": len(critical),
            "high_moves": len(high),
            "has_wildcard": wildcard,
            "by_category": by_cat,
            "category_colors": CAT_COLORS,
            "timeline": timeline,
            "worst_case": self._narrative(start_identity, avail_moves, critical),
            "risk_rating": "CRITICAL" if critical else ("HIGH" if high else "MEDIUM"),
            "time_to_impact_minutes": timeline[-1]["cumulative_minutes"] if timeline else 0,
        }

    def get_all_identities(self, iam_action_map):
        return sorted(iam_action_map.keys())

    def _timeline(self, avail_moves):
        phases = [("Discovery",2),("Privilege Escalation",5),("Lateral Movement",3),
                  ("Persistence",5),("Defense Evasion",5),("Exfiltration",10),("Impact",5)]
        timeline, minutes = [], 0
        for cat, dur in phases:
            moves = [m for m in avail_moves if m["category"] == cat]
            if not moves: continue
            minutes += dur
            best = max(moves, key=lambda m: m["cvss"])
            timeline.append({"phase":cat,"action":best["action"],"impact":best["impact"],
                              "duration_minutes":dur,"cumulative_minutes":minutes,
                              "logged":best["logged"],"mitre":best["mitre"],"cvss":best["cvss"]})
        return timeline

    def _narrative(self, identity, avail_moves, critical):
        if not avail_moves: return f"Identity '{identity}' has minimal permissions."
        parts = [f"An attacker who compromises '{identity}' can immediately begin reconnaissance."]
        if critical: parts.append(f"They can escalate to administrator within minutes using {len(critical)} critical vector(s).")
        if any(m["category"]=="Defense Evasion" for m in avail_moves): parts.append("They can blind the security team by stopping CloudTrail and deleting log groups.")
        if any(m["category"]=="Exfiltration" for m in avail_moves): parts.append("All secrets, SSM parameters, and S3 data are accessible for exfiltration.")
        if any(m["category"]=="Impact" for m in avail_moves): parts.append("Maximum impact includes terminating compute, deleting data, and scheduling KMS key deletion.")
        return " ".join(parts)
