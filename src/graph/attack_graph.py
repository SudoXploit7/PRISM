"""
PRISM -- Attack Graph Builder
Builds a NetworkX graph of IAM relationships and attack paths.
"""

from typing import Any

import networkx as nx
from loguru import logger


class AttackGraph:
    """Builds a directed graph representing IAM attack surfaces."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def build(
        self,
        users: list[str],
        roles: list[str],
        trusts: list[tuple[str, str, str]],
        admin_roles: list[str],
        shadow_findings: list[dict],
        privesc_findings: list[dict],
        iam_action_map: dict[str, list[str]],
    ) -> None:
        """Build the attack graph from collected data."""
        shadow_ids = {f.get("identity", "") for f in shadow_findings}
        privesc_ids = {f.get("identity", "") for f in privesc_findings}

        # -- User nodes ----------------------------------------------------
        for u in users:
            risk = "critical" if u in shadow_ids else ("high" if u in privesc_ids else "medium")
            self.graph.add_node(u, type="user", risk=risk, actions=len(iam_action_map.get(u, [])))

        # -- Role nodes ----------------------------------------------------
        for r in roles:
            risk = "critical" if r in admin_roles else ("high" if r in shadow_ids else "medium")
            self.graph.add_node(r, type="role", risk=risk, is_admin=r in admin_roles)

        # -- Trust edges (backbone -- always present) ----------------------
        for src, dst, rel in trusts:
            src_name = src.split("/")[-1] if "/" in src else src

            # Classify source node type
            if src_name == "*":
                if not self.graph.has_node("INTERNET"):
                    self.graph.add_node("INTERNET", type="internet", risk="critical")
                src_name = "INTERNET"
            elif src_name.endswith("amazonaws.com"):
                if not self.graph.has_node(src_name):
                    service_short = src_name.split(".")[0].upper()
                    self.graph.add_node(src_name, type="service", risk="low", label=service_short)
            elif not self.graph.has_node(src_name):
                ntype = "external"
                self.graph.add_node(src_name, type=ntype, risk="low")

            if not self.graph.has_node(dst):
                self.graph.add_node(dst, type="role", risk="low")

            self.graph.add_edge(src_name, dst, type=rel, is_attack=rel == "AssumeRole")

        # -- Privilege escalation edges ------------------------------------
        for finding in privesc_findings:
            identity = finding.get("identity", "")
            vector = finding.get("vector_name", "")
            if identity and self.graph.has_node(identity):
                target = f"ADMIN_via_{vector}"
                if not self.graph.has_node(target):
                    self.graph.add_node(target, type="admin_target", risk="critical")
                self.graph.add_edge(identity, target, type="privesc", vector=vector, is_attack=True)

        # -- Policy nodes (top admin policies) -----------------------------
        for identity, actions in iam_action_map.items():
            if "*" in actions and self.graph.has_node(identity):
                policy_node = f"POLICY:AdministratorAccess"
                if not self.graph.has_node(policy_node):
                    self.graph.add_node(policy_node, type="policy", risk="critical")
                self.graph.add_edge(identity, policy_node, type="has_policy", is_attack=False)

        # -- Build Log -----------------------------------------------------
        logger.info(
            f"Attack graph built: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to dict for JSON transmission."""
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            nodes.append({"id": node_id, "label": data.get("label", node_id), **data})
        edges = []
        for src, dst, data in self.graph.edges(data=True):
            edges.append({"from": src, "to": dst, **data})
        return {"nodes": nodes, "edges": edges}
