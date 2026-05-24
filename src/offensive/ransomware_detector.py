"""
PRISM -- S3 Ransomware Readiness Detector
Measures whether cloud ransomware (encrypt-and-ransom) is executable.
Based on Royal ransomware and Scattered Spider attack patterns.
"""
from __future__ import annotations
from typing import Any
from loguru import logger

RANSOM_PHASES = {
    "disable_versioning":        {"actions":["s3:PutBucketVersioning"],                 "cvss":8.6,"mitre":"T1485","severity":"HIGH"},
    "delete_objects":            {"actions":["s3:DeleteObject","s3:DeleteObjects"],      "cvss":9.0,"mitre":"T1485","severity":"CRITICAL"},
    "encrypt_with_attacker_kms": {"actions":["s3:PutObject","kms:CreateKey"],           "cvss":9.5,"mitre":"T1486","severity":"CRITICAL"},
    "destroy_backups":           {"actions":["s3:DeleteBucket"],                        "cvss":9.0,"mitre":"T1485","severity":"CRITICAL"},
    "block_recovery":            {"actions":["s3:PutBucketPolicy"],                     "cvss":8.5,"mitre":"T1485","severity":"HIGH"},
    "exfiltrate_before_encrypt": {"actions":["s3:GetObject"],                           "cvss":7.5,"mitre":"T1530","severity":"HIGH"},
}

class RansomwareDetector:
    def analyze(self, s3_buckets, iam_action_map, scan_results):
        id_results  = self._identities(iam_action_map)
        bkt_results = self._buckets(s3_buckets)
        score = self._score(id_results, bkt_results)
        dangerous = max(id_results, key=lambda x: x["phases_available"], default=None)
        unprotected = [b for b in bkt_results if b["ransomware_risk"] in ("CRITICAL","HIGH")]
        return {
            "overall_score": score, "risk_rating": self._rating(score),
            "identity_results": id_results[:15], "bucket_results": bkt_results[:15],
            "unprotected_buckets": len(unprotected), "total_buckets": len(s3_buckets),
            "most_dangerous_identity": dangerous,
            "recovery_time_estimate": self._recovery(bkt_results),
            "mitre": "T1486", "cvss_score": 9.5 if score >= 70 else (8.0 if score >= 40 else 5.0),
            "real_world_reference": "Royal ransomware (2023) and Scattered Spider S3 encryption attacks (2024).",
        }

    def _identities(self, iam_action_map):
        results = []
        for identity, actions in iam_action_map.items():
            aset = set(a.lower() for a in actions)
            wildcard = "*" in aset
            phases = []
            for phase_name, phase_info in RANSOM_PHASES.items():
                if wildcard or any(r.lower() in aset or r.lower().split(":")[0]+":*" in aset for r in phase_info["actions"]):
                    phases.append(phase_name)
            if not phases: continue
            full = len(phases) >= 4
            results.append({
                "identity": identity, "phases_available": len(phases), "phases": phases,
                "full_ransom_capable": full, "severity": "CRITICAL" if full else "HIGH",
                "cvss_score": 9.5 if full else 7.5, "mitre": "T1486",
                "description": f"Identity '{identity}' can execute {len(phases)}/6 ransomware phases" + (" -- sufficient for a complete ransomware attack." if full else "."),
            })
        results.sort(key=lambda x: x["phases_available"], reverse=True)
        return results

    def _buckets(self, s3_buckets):
        results = []
        for bucket in s3_buckets:
            name = bucket.get("Name", "unknown"); issues = []; risk = "LOW"
            if bucket.get("versioning","Disabled") != "Enabled":
                issues.append("Versioning disabled -- no recovery from deletion"); risk = "HIGH"
            if not bucket.get("object_lock", False):
                issues.append("Object Lock not enabled -- objects can be permanently deleted"); risk = "HIGH"
            bpa = bucket.get("block_public_access", {})
            if not all([bpa.get("BlockPublicAcls"),bpa.get("RestrictPublicBuckets"),bpa.get("BlockPublicPolicy"),bpa.get("IgnorePublicAcls")]):
                issues.append("Block Public Access not fully enabled")
            if not bucket.get("replication", False):
                issues.append("No cross-region replication")
            if len(issues) >= 3: risk = "CRITICAL"
            results.append({"bucket_name":name,"ransomware_risk":risk,"issues":issues,
                "versioning":bucket.get("versioning","Disabled")=="Enabled","object_lock":bucket.get("object_lock",False),
                "replication":bucket.get("replication",False),"severity":risk,
                "recovery_possible":bucket.get("versioning","Disabled")=="Enabled" or bucket.get("object_lock",False)})
        results.sort(key=lambda x: {"CRITICAL":3,"HIGH":2,"MEDIUM":1,"LOW":0}.get(x["ransomware_risk"],0), reverse=True)
        return results

    def _score(self, id_results, bkt_results):
        score = min(sum(1 for r in id_results if r.get("full_ransom_capable"))*30, 50)
        score += min(sum(1 for r in id_results if not r.get("full_ransom_capable"))*10, 20)
        if bkt_results:
            score += int((sum(1 for b in bkt_results if not b.get("versioning") and not b.get("object_lock"))/len(bkt_results))*30)
        return min(score, 100)

    def _rating(self, score):
        return "CRITICAL" if score >= 80 else ("HIGH" if score >= 55 else ("MEDIUM" if score >= 30 else "LOW"))

    def _recovery(self, bkt_results):
        total = len(bkt_results)
        if total == 0: return "N/A"
        no_v = sum(1 for b in bkt_results if not b.get("versioning"))
        if no_v == total: return "72+ hours (full data loss likely)"
        if no_v > total//2: return "48-72 hours (partial recovery only)"
        return "4-24 hours (protected buckets recoverable)"
