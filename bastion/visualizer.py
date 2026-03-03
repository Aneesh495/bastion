"""ASCII visualizer for attack graphs, timelines, and risk topologies."""

from typing import Any, Dict, List


class TerminalVisualizer:
    """Renders high-fidelity ASCII terminal graphs, timelines, and matrices."""

    @staticmethod
    def render_banner() -> str:
        return """
  ____             _   _             
 | __ )  __ _ ___| |_(_) ___  _ __  
 |  _ \\ / _` / __| __| |/ _ \\| '_ \\ 
 | |_) | (_| \\__ \\ |_| | (_) | | | |
 |____/ \\__,_|___/\\__|_|\\___/|_| |_|
 Autonomous Zero-Trust Security Kernel
"""

    @staticmethod
    def render_attack_path(hops: List[Dict[str, Any]]) -> str:
        """Renders an ASCII directed graph of a multi-hop attack path."""
        if not hops:
            return "No attack path detected."

        lines = ["\n[ATTACK PATH RECONSTRUCTION]"]
        for idx, hop in enumerate(hops):
            source = hop.get("source_node", "UNKNOWN")
            target = hop.get("target_node", "UNKNOWN")
            action = hop.get("action", "TRANSIT")
            protocol = hop.get("protocol", "TCP")
            risk = hop.get("risk_score", 0.0)

            node_box = f"[{idx + 1}] Node: {source}"
            lines.append("  +------------------------------------------------------+")
            lines.append(f"  | {node_box.ljust(52)} |")
            lines.append("  +------------------------------------------------------+")
            lines.append("          |")
            lines.append(f"          |-- [Action: {action}] ({protocol}) Risk: {risk:.1f}")
            lines.append("          v")

        last_node = hops[-1].get("target_node", "CROWN_JEWEL")
        lines.append("  +------------------------------------------------------+")
        lines.append(f"  | [*] Target: {last_node.ljust(50)} |")
        lines.append("  +------------------------------------------------------+\n")
        return "\n".join(lines)

    @staticmethod
    def render_incident_card(incident: Dict[str, Any]) -> str:
        """Renders a structured summary card for a security incident."""
        inc_id = incident.get("incident_id", "INC-0000")
        title = incident.get("title", "Unknown Anomaly")
        severity = incident.get("severity", "LOW")
        state = incident.get("state", "DETECTED")
        score = incident.get("composite_risk_score", 0.0)
        tactic = incident.get("primary_tactic", "TA0001")

        lines = [
            "+====================================================================+",
            f"| INCIDENT: {inc_id.ljust(15)} [{severity.center(10)}] Status: {state.ljust(12)} |",
            "+--------------------------------------------------------------------+",
            f"| Title:        {title[:52].ljust(52)} |",
            f"| MITRE Tactic: {tactic.ljust(52)} |",
            f"| Risk Score:   {f'{score:.2f} / 100.0'.ljust(52)} |",
            "+====================================================================+"
        ]
        return "\n".join(lines)
