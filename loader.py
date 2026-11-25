import json
from dataclasses import dataclass
from pathlib import Path
from typing import List
import yaml

from src.parser.intervals import (
    Interval,
    parse_cidr,
    parse_port_range,
    parse_protocol,
)


@dataclass(frozen=True)
class NormalizedRule:
    rule_id: str
    action: str  # "ALLOW" or "DENY"
    protocol: Interval
    src_ip: Interval
    dst_ip: Interval
    dst_port: Interval

    def is_catch_all(self) -> bool:
        return (
            self.protocol == Interval(0, 255)
            and self.src_ip == Interval(0, 0xFFFFFFFF)
            and self.dst_ip == Interval(0, 0xFFFFFFFF)
            and self.dst_port == Interval(0, 65535)
        )


@dataclass
class FirewallPolicy:
    name: str
    rules: List[NormalizedRule]


def load_policy(file_path: str | Path, append_default_deny: bool = True) -> FirewallPolicy:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    raw_text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        data = yaml.safe_load(raw_text)
    elif path.suffix.lower() == ".json":
        data = json.loads(raw_text)
    else:
        raise ValueError(f"Unsupported policy file extension: {path.suffix}")

    if not isinstance(data, dict) or "rules" not in data:
        raise ValueError("Policy file must be an object containing a 'rules' list.")

    policy_name = data.get("policy_name", path.stem)
    normalized_rules: List[NormalizedRule] = []

    for idx, raw_rule in enumerate(data["rules"], start=1):
        rule_id = str(raw_rule.get("rule_id", f"R{idx}"))
        action = str(raw_rule.get("action", "")).strip().upper()
        if action not in ("ALLOW", "DENY"):
            raise ValueError(f"Rule {rule_id}: invalid action '{action}'. Must be ALLOW or DENY.")

        proto_iv = parse_protocol(raw_rule.get("protocol", "ALL"))
        src_iv = parse_cidr(raw_rule.get("src_cidr", "ANY"))
        dst_iv = parse_cidr(raw_rule.get("dst_cidr", "ANY"))
        port_iv = parse_port_range(raw_rule.get("port_range", "ANY"))

        normalized_rules.append(
            NormalizedRule(
                rule_id=rule_id,
                action=action,
                protocol=proto_iv,
                src_ip=src_iv,
                dst_ip=dst_iv,
                dst_port=port_iv,
            )
        )

    if append_default_deny and (not normalized_rules or not normalized_rules[-1].is_catch_all()):
        normalized_rules.append(
            NormalizedRule(
                rule_id="IMPLICIT_DEFAULT_DENY",
                action="DENY",
                protocol=Interval(0, 255),
                src_ip=Interval(0, 0xFFFFFFFF),
                dst_ip=Interval(0, 0xFFFFFFFF),
                dst_port=Interval(0, 65535),
            )
        )

    return FirewallPolicy(name=policy_name, rules=normalized_rules)
