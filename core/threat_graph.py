import os
from typing import Dict, List


class ThreatGraphVisualizer:
    """Generate Mermaid attack-chain graphs from investigation results."""

    def build_mermaid(self, investigation: Dict) -> str:
        fraud = investigation.get("fraud_impact", {})
        meta = investigation.get("metadata", {})
        package = meta.get("package_name", "APK")

        nodes = [f"A[\"{package}\"]"]
        edges = []
        step = 1
        node_id = "B"

        if fraud.get("can_impersonate_bank"):
            nodes.append(f"{node_id}[\"Impersonate Bank\"]")
            edges.append(f"A --> {node_id}")
            step += 1
            node_id = chr(ord(node_id) + 1)

        if fraud.get("can_capture_credentials"):
            nodes.append(f"{node_id}[\"Capture Credentials\"]")
            edges.append(f"{chr(ord(node_id)-1)} --> {node_id}" if step > 1 else f"A --> {node_id}")
            step += 1
            node_id = chr(ord(node_id) + 1)

        if fraud.get("can_steal_otp"):
            nodes.append(f"{node_id}[\"Intercept OTP/SMS\"]")
            edges.append(f"{chr(ord(node_id)-1)} --> {node_id}" if step > 1 else f"A --> {node_id}")
            step += 1
            node_id = chr(ord(node_id) + 1)

        if fraud.get("can_bypass_mfa") or fraud.get("can_overlay_banking_apps"):
            nodes.append(f"{node_id}[\"Bypass MFA / Overlay\"]")
            edges.append(f"{chr(ord(node_id)-1)} --> {node_id}" if step > 1 else f"A --> {node_id}")
            step += 1
            node_id = chr(ord(node_id) + 1)

        nodes.append(f"{node_id}[\"Fraud / Account Takeover\"]")
        edges.append(f"{chr(ord(node_id)-1)} --> {node_id}" if step > 1 else f"A --> {node_id}")

        return "graph TD\n" + "\n".join(nodes) + "\n" + "\n".join(edges)

    def save_mermaid(self, investigation: Dict, out_dir: str) -> str:
        os.makedirs(out_dir, exist_ok=True)
        apk_name = investigation["metadata"]["file_name"]
        path = os.path.join(out_dir, f"{apk_name}_attack_chain.mmd")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.build_mermaid(investigation))
        return path
