from dataclasses import dataclass
from typing import List
import z3

from src.parser.loader import FirewallPolicy, NormalizedRule


@dataclass
class SymbolicPacket:
    src_ip: z3.ArithRef
    dst_ip: z3.ArithRef
    dst_port: z3.ArithRef
    proto: z3.ArithRef

    @classmethod
    def create(cls, prefix: str = "pkt") -> "SymbolicPacket":
        return cls(
            src_ip=z3.Int(f"{prefix}_src_ip"),
            dst_ip=z3.Int(f"{prefix}_dst_ip"),
            dst_port=z3.Int(f"{prefix}_dst_port"),
            proto=z3.Int(f"{prefix}_proto"),
        )

    def domain_constraints(self) -> z3.BoolRef:
        return z3.And(
            self.src_ip >= 0,
            self.src_ip <= 0xFFFFFFFF,
            self.dst_ip >= 0,
            self.dst_ip <= 0xFFFFFFFF,
            self.dst_port >= 0,
            self.dst_port <= 65535,
            self.proto >= 0,
            self.proto <= 255,
        )


def encode_rule_match(rule: NormalizedRule, pkt: SymbolicPacket) -> z3.BoolRef:
    return z3.And(
        pkt.src_ip >= rule.src_ip.min_val,
        pkt.src_ip <= rule.src_ip.max_val,
        pkt.dst_ip >= rule.dst_ip.min_val,
        pkt.dst_ip <= rule.dst_ip.max_val,
        pkt.dst_port >= rule.dst_port.min_val,
        pkt.dst_port <= rule.dst_port.max_val,
        pkt.proto >= rule.protocol.min_val,
        pkt.proto <= rule.protocol.max_val,
    )


def encode_effective_rules(policy: FirewallPolicy, pkt: SymbolicPacket) -> List[tuple[NormalizedRule, z3.BoolRef]]:
    """
    Encodes First-Match Semantics:
    Effective(R_i, p) = Match(R_i, p) AND (AND_{j < i} NOT Match(R_j, p))
    """
    effective_list: List[tuple[NormalizedRule, z3.BoolRef]] = []
    prior_negations: List[z3.BoolRef] = []

    for rule in policy.rules:
        match_expr = encode_rule_match(rule, pkt)
        effective_expr = z3.And(match_expr, *prior_negations) if prior_negations else match_expr
        effective_list.append((rule, effective_expr))
        prior_negations.append(z3.Not(match_expr))

    return effective_list


def encode_policy_allowed(policy: FirewallPolicy, pkt: SymbolicPacket) -> z3.BoolRef:
    effective_rules = encode_effective_rules(policy, pkt)
    allow_formulas = [expr for rule, expr in effective_rules if rule.action == "ALLOW"]
    return z3.Or(*allow_formulas) if allow_formulas else z3.BoolVal(False)