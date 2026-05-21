"""Network Agent — focuses on lateral-movement containment.

Uses the existing https-detector model (when present) to inspect any URLs
mentioned in IOC evidence, and proposes isolating hosts within `blast_radius`
hops of confirmed infected hosts.
"""
from __future__ import annotations

import logging
import os
import sys
import warnings
from typing import Set

from .base_agent import BaseAgent, AgentProposal
from ..network.topology import NetworkTopology

# Silence the noisy "version mismatch on pickle" + "can't refresh public suffix
# list" output when we lazy-load the existing https-detector.
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
logging.getLogger("tldextract").setLevel(logging.CRITICAL)
logging.getLogger("filelock").setLevel(logging.CRITICAL)

_URL_DETECTOR = None
_DETECTOR_LOAD_TRIED = False


def _try_load_url_detector():
    """Lazily import the existing https-detector if the trained model exists."""
    global _URL_DETECTOR, _DETECTOR_LOAD_TRIED
    if _URL_DETECTOR is not None or _DETECTOR_LOAD_TRIED:
        return _URL_DETECTOR
    _DETECTOR_LOAD_TRIED = True
    try:
        # Add https-detector/src to sys.path so we can import its inference module
        here = os.path.dirname(os.path.abspath(__file__))
        # amcds/agents -> AMCDS root
        repo_root = os.path.abspath(os.path.join(here, "..", ".."))
        detector_src = os.path.join(repo_root, "https-detector", "src")
        model_path = os.path.join(detector_src, "model.pkl")
        if not os.path.exists(model_path):
            return None
        if detector_src not in sys.path:
            sys.path.insert(0, detector_src)
        # Importing inference triggers tldextract to try to refresh the public
        # suffix list. We swallow stderr during that import so the demo log is
        # clean even on machines with no internet.
        import io
        import contextlib
        with contextlib.redirect_stderr(io.StringIO()), \
             contextlib.redirect_stdout(io.StringIO()):
            from inference import URLThreatDetector  # type: ignore
            _URL_DETECTOR = URLThreatDetector(model_dir=detector_src)
        return _URL_DETECTOR
    except Exception:
        return None


class NetworkAgent(BaseAgent):
    name = "Network"

    def __init__(self, blast_radius: int = 1) -> None:
        self.blast_radius = blast_radius

    def propose(self, topology: NetworkTopology, scenario: dict) -> AgentProposal:
        infected: Set[str] = set(scenario.get("infected_hosts", []))
        attack_type = scenario.get("attack_type", "unknown")
        suspicious_urls = scenario.get("ioc_evidence", {}).get("urls", [])

        # URL inspection (uses the existing https-detector model if trained)
        url_findings = []
        detector = _try_load_url_detector()
        if detector and suspicious_urls:
            for url in suspicious_urls[:10]:
                try:
                    is_mal, conf, _ = detector.predict(url)
                    if is_mal and conf > 0.6:
                        url_findings.append((url, conf))
                except Exception:
                    pass

        # Lateral-movement containment: isolate everything within `blast_radius` hops.
        # For ransomware we go aggressive (radius=2); for insider threats, radius=1.
        radius = 2 if attack_type == "ransomware" else self.blast_radius
        isolate: Set[str] = set(infected)
        frontier = set(infected)
        for _ in range(radius):
            nxt = set()
            for h in frontier:
                for nbr in topology.neighbors(h):
                    if nbr not in isolate:
                        # Don't blanket-isolate DCs — that kills identity org-wide
                        if topology.hosts[nbr].host_type != "domain_controller":
                            nxt.add(nbr)
            isolate.update(nxt)
            frontier = nxt

        # If URL evidence is strong, also flag any host whose name suggests it
        # served those URLs (web tier).
        web_concerns = set()
        if url_findings:
            for hid, host in topology.hosts.items():
                if host.host_type == "web_server":
                    web_concerns.add(hid)
            isolate.update(web_concerns)

        reasoning = (
            f"Lateral-movement containment at radius={radius} from "
            f"{len(infected)} infected host(s) → isolate {len(isolate)} host(s). "
        )
        if url_findings:
            reasoning += (
                f"URL detector flagged {len(url_findings)} malicious URL(s) "
                f"(top confidence {max(c for _, c in url_findings):.2f}); "
                f"adding {len(web_concerns)} web-tier host(s) to isolation set. "
            )
        elif suspicious_urls and not detector:
            reasoning += "(URL detector not trained — skipping URL inspection.) "

        return AgentProposal(
            agent_name=self.name,
            isolate=isolate,
            reasoning=reasoning,
            confidence=0.85 if infected else 0.4,
        )
