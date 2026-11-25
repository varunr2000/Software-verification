from src.parser.intervals import parse_cidr, parse_port_range, parse_protocol
from src.parser.loader import NormalizedRule, load_policy
from src.verifier.checker import find_shadowed_rules, verify_safety_invariant


def main():
    policy = load_policy("policies/shadowing_bug.yaml")
    print(f"Loaded policy '{policy.name}' with {len(policy.rules)} normalized rules.\n")

    # 1. Shadowing & Dead-Rule Detection
    dead_rules = find_shadowed_rules(policy)
    print("=== 1. Shadowed / Dead-Rule Check ===")
    if dead_rules:
        for r in dead_rules:
            print(f"[BUG] Rule '{r.rule_id}' ({r.action}) is completely shadowed and unreachable!")
    else:
        print("[OK] No shadowed rules detected.")

    # 2. Safety Invariant Verification
    print("\n=== 2. Safety Invariant Check ===")
    forbidden_db_access = NormalizedRule(
        rule_id="SAFETY_DB_5432",
        action="DENY",
        protocol=parse_protocol("TCP"),
        src_ip=parse_cidr("10.0.5.0/24"),
        dst_ip=parse_cidr("10.0.10.50/32"),
        dst_port=parse_port_range("5432"),
    )
    cex = verify_safety_invariant(policy, forbidden_db_access)
    if cex:
        print(f"[VIOLATION] Forbidden traffic allowed! Counterexample packet: {cex}")
    else:
        print("[SAFE] Invariant holds across 100% of the packet space.")


if __name__ == "__main__":
    main()