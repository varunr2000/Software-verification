from dataclasses import dataclass
from typing import Tuple

PROTOCOL_MAP = {
    "ICMP": (1, 1),
    "TCP": (6, 6),
    "UDP": (17, 17),
    "ALL": (0, 255),
    "ANY": (0, 255),
    "*": (0, 255),
}


@dataclass(frozen=True)
class Interval:
    min_val: int
    max_val: int

    def __post_init__(self):
        if self.min_val > self.max_val:
            raise ValueError(f"Invalid interval: min ({self.min_val}) > max ({self.max_val})")


def ipv4_to_int(ip_str: str) -> int:
    octets = ip_str.strip().split(".")
    if len(octets) != 4:
        raise ValueError(f"Invalid IPv4 address: {ip_str}")
    result = 0
    for octet in octets:
        if not octet.isdigit():
            raise ValueError(f"Non-numeric octet in IPv4 address: {ip_str}")
        val = int(octet)
        if val < 0 or val > 255:
            raise ValueError(f"Octet out of range [0, 255] in IPv4 address: {ip_str}")
        result = (result << 8) | val
    return result


def int_to_ipv4(ip_int: int) -> str:
    return ".".join(str((ip_int >> (8 * i)) & 0xFF) for i in reversed(range(4)))


def parse_cidr(cidr_str: str) -> Interval:
    token = cidr_str.strip().upper()
    if token in ("ANY", "*", "0.0.0.0/0"):
        return Interval(0, 0xFFFFFFFF)

    if "/" not in token:
        ip_val = ipv4_to_int(token)
        return Interval(ip_val, ip_val)

    ip_part, prefix_part = token.split("/", 1)
    if not prefix_part.isdigit():
        raise ValueError(f"Invalid CIDR prefix: {cidr_str}")

    prefix = int(prefix_part)
    if prefix < 0 or prefix > 32:
        raise ValueError(f"CIDR prefix out of range [0, 32]: {cidr_str}")

    ip_base = ipv4_to_int(ip_part)
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix > 0 else 0
    ip_min = ip_base & mask
    ip_max = ip_min | (~mask & 0xFFFFFFFF)
    return Interval(ip_min, ip_max)


def parse_port_range(port_spec: str | int) -> Interval:
    token = str(port_spec).strip().upper()
    if token in ("ANY", "*"):
        return Interval(0, 65535)

    if ".." in token:
        parts = token.split("..", 1)
    elif "-" in token:
        parts = token.split("-", 1)
    else:
        if not token.isdigit():
            raise ValueError(f"Invalid port value: {port_spec}")
        port = int(token)
        if port < 0 or port > 65535:
            raise ValueError(f"Port out of range [0, 65535]: {port_spec}")
        return Interval(port, port)

    if not (parts[0].isdigit() and parts[1].isdigit()):
        raise ValueError(f"Invalid port range: {port_spec}")

    p_min, p_max = int(parts[0]), int(parts[1])
    if p_min < 0 or p_max > 65535 or p_min > p_max:
        raise ValueError(f"Invalid port range bounds: {port_spec}")
    return Interval(p_min, p_max)


def parse_protocol(proto_spec: str | int) -> Interval:
    token = str(proto_spec).strip().upper()
    if token in PROTOCOL_MAP:
        lo, hi = PROTOCOL_MAP[token]
        return Interval(lo, hi)
    if token.isdigit():
        val = int(token)
        if 0 <= val <= 255:
            return Interval(val, val)
    raise ValueError(f"Unsupported protocol specification: {proto_spec}")
