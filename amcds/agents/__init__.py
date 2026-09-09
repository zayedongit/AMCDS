from .base_agent import (AgentProposal, BaseAgent, Critique, NegotiationContext,
                         VetoDecision)
from .business_impact_agent import BusinessImpactAgent
from .data_agent import DataAgent
from .endpoint_agent import EndpointAgent
from .identity_agent import IdentityAgent
from .network_agent import NetworkAgent


def default_agents():
    """The five specialist agents, in their canonical order.

    Four domain specialists plus the Business Impact agent, which is also a
    specialist (its domain is service continuity) and additionally holds the
    formal veto.
    """
    return [IdentityAgent(), NetworkAgent(), DataAgent(), EndpointAgent(),
            BusinessImpactAgent()]


__all__ = [
    "AgentProposal", "BaseAgent", "Critique", "NegotiationContext", "VetoDecision",
    "IdentityAgent", "NetworkAgent", "DataAgent", "EndpointAgent",
    "BusinessImpactAgent", "default_agents",
]
