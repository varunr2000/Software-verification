from dataclasses import dataclass
from typing import Dict, List, Optional
import z3

from src.encoder.z3_encoder import (
    SymbolicPacket,
    encode_effective_rules,
    encode_policy_allowed,
    encode_rule_match,
)
from src.parser.intervals import int_to_ipv4
from src.parser.loader import FirewallPolicy, NormalizedRule


@dataclass
class CounterexamplePacket:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: int


def _extract_packet(model: z3.ModelRef, pkt: SymbolicPacket) -> CounterexamplePacket:
    src_val = model.eval(pkt.src_ip, model_completion=True).as_long()
    dst_val = model.eval(pkt.dst_ip, model_completion=True).as_long()
    port_val = model.eval(pkt.dst_port, model_completion=True).as_long()
    proto_val = model.eval(pkt.proto, model_completion=True).as_long()
    return CounterexamplePacket(
        src_ip=int_to_ipv4(src_val),
        dst_ip=int_to_ipv4(dst_val),
        dst_port=port_val,
        protocol=proto_val,
    )


def find_shadowed_rules(policy: FirewallPolicy) -> List[NormalizedRule]:
    """
    Feature 1: Shadowing & Dead-Rule Detection.
    A rule R_i is completely unreachable iff Effective(R_i, p) is UNSAT.
    """
    pkt = SymbolicPacket.create("shadow_pkt")
    effective_rules = encode_effective_rules(policy, pkt)
    dead_rules: List[NormalizedRule] = []

    for rule, eff_expr in effective_rules:
        if rule.rule_id == "IMPLICIT_DEFAULT_DENY":
            continue
        solver = z3.Solver()
        solver.add(pkt.domain_constraints())
        solver.add(eff_expr)
        if solver.check() == z3.unsat:
            dead_rules.append(rule)

    return dead_rules


def verify_safety_invariant(
    policy: FirewallPolicy, forbidden_traffic: NormalizedRule
) -> Optional[CounterexamplePacket]:
    """
    Feature 2: Safety Invariant Verification.
    Checks if Allowed(P, p) AND Forbidden(p) is SAT.
    Returns None if safe (UNSAT), or a CounterexamplePacket if violated (SAT).
    """
    pkt = SymbolicPacket.create("safety_pkt")
    solver = z3.Solver()
    solver.add(pkt.domain_constraints())
    solver.add(encode_policy_allowed(policy, pkt))
    solver.add(encode_rule_match(forbidden_traffic, pkt))

    if solver.check() == z3.sat:
        return _extract_packet(solver.model(), pkt)
    return None


def check_policy_equivalence(
    policy_a: FirewallPolicy, policy_b: FirewallPolicy
) -> Optional[Dict[str, object]]:
    """
    Feature 3: Policy Equivalence Checking.
    Checks if Allowed(P1, p) != Allowed(P2, p) is SAT.
    Returns None if equivalent, or a differential counterexample dict.
    """
    pkt = SymbolicPacket.create("equiv_pkt")
    allow_a = encode_policy_allowed(policy_a, pkt)
    allow_b = encode_policy_allowed(policy_b, pkt)

    solver = z3.Solver()
    solver.add(pkt.domain_constraints())
    solver.add(z3.Xor(allow_a, allow_b))

    if solver.check() == z3.sat:
        model = solver.model()
        return {
            "packet": _extract_packet(model, pkt),
            "policy_a_allows": bool(z3.is_true(model.eval(allow_a, model_completion=True))),
            "policy_b_allows": bool(z3.is_true(model.eval(allow_b, model_completion=True))),
        }
    return None