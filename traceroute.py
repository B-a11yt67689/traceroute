#!/usr/bin/env python3
import argparse
import ipaddress
import random
import re
import socket
import sys
import time
from typing import Optional

from scapy.all import (
    IP, IPv6,
    ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach,
    TCP, UDP,
    Raw,
    sr1,
    conf,
)

conf.verb = 0


def whois_query(server: str, query: str, timeout: float) -> str:
    data = []
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data.append(chunk)
    return b"".join(data).decode("utf-8", errors="ignore")


def iana_referral(ip: str, timeout: float) -> str:
    text = whois_query("whois.iana.org", ip, timeout)
    m = re.search(r"(?im)^\s*(refer|whois):\s*(\S+)\s*$", text)
    if m:
        return m.group(2).strip()
    return "whois.arin.net"


def rir_format_query(rir_server: str, ip: str) -> str:
    s = rir_server.lower()
    if "arin.net" in s:
        return f"n + {ip}"
    if "apnic.net" in s:
        return f"-V Md5.5.7 {ip}"
    return ip


ASN_REGEXES = [
    re.compile(r"(?im)^\s*originas:\s*(AS\d+)\s*$"),
    re.compile(r"(?im)^\s*origin:\s*(AS\d+)\s*$"),
    re.compile(r"(?im)^\s*aut-num:\s*(AS\d+)\s*$"),
    re.compile(r"(?im)^\s*origin\s*:\s*(\d+)\s*$"),
    re.compile(r"(?im)\bAS(\d{1,10})\b"),
]


def parse_asn(whois_text: str) -> Optional[str]:
    for rx in ASN_REGEXES:
        m = rx.search(whois_text)
        if m:
            val = m.group(1)
            if val.isdigit():
                return f"AS{val}"
            if val.upper().startswith("AS"):
                return val.upper()
            if val:
                return f"AS{val}"
    return None


_asn_cache: dict[str, Optional[str]] = {}


def get_asn(ip: str, timeout: float) -> Optional[str]:
    if ip in _asn_cache:
        return _asn_cache[ip]
    try:
        rir = iana_referral(ip, timeout)
        q = rir_format_query(rir, ip)
        text = whois_query(rir, q, timeout)
        m = re.search(r"(?im)^\s*ReferralServer:\s*whois://(\S+)\s*$", text)
        if m:
            second = m.group(1).strip()
            q2 = rir_format_query(second, ip)
            text2 = whois_query(second, q2, timeout)
            asn = parse_asn(text2) or parse_asn(text)
        else:
            asn = parse_asn(text)
        _asn_cache[ip] = asn
        return asn
    except Exception:
        _asn_cache[ip] = None
        return None


_rdns_cache: dict[str, Optional[str]] = {}


def reverse_dns(ip: str) -> Optional[str]:
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
        _rdns_cache[ip] = name
        return name
    except Exception:
        _rdns_cache[ip] = None
        return None


def is_ipv6(addr: str) -> bool:
    return isinstance(ipaddress.ip_address(addr), ipaddress.IPv6Address)


def extract_reply_ip(reply) -> Optional[str]:
    if reply is None:
        return None
    if reply.haslayer(IP):
        return reply[IP].src
    if reply.haslayer(IPv6):
        return reply[IPv6].src
    return None


def reached_destination(reply, dst: str, proto: str) -> bool:
    if reply is None:
        return False
    v6 = is_ipv6(dst)
    if proto == "icmp":
        if v6:
            return reply.haslayer(ICMPv6EchoReply)
        return reply.haslayer(ICMP) and int(reply[ICMP].type) == 0
    if proto == "udp":
        if v6:
            if reply.haslayer(ICMPv6DestUnreach):
                return True
        else:
            if reply.haslayer(ICMP) and int(reply[ICMP].type) == 3:
                return True
        rip = extract_reply_ip(reply)
        return rip == dst
    if proto == "tcp":
        if reply.haslayer(TCP):
            rip = extract_reply_ip(reply)
            if rip == dst:
                flags = int(reply[TCP].flags)
                if (flags & 0x12) == 0x12 or (flags & 0x04) == 0x04:
                    return True
        return False
    return False


def make_payload(size: int, payload_text: Optional[str], payload_hex: Optional[str]) -> bytes:
    if payload_hex is not None:
        s = payload_hex.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        if len(s) % 2 != 0:
            raise ValueError("payload_hex must have even number of hex digits")
        return bytes.fromhex(s)
    if payload_text is not None:
        return payload_text.encode("utf-8", errors="ignore")
    if size < 0:
        size = 0
    return b"x" * size


def build_packet(dst: str, proto: str, port: int, ttl: int, seq: int, source: Optional[str], payload: bytes):
    v6 = is_ipv6(dst)
    if v6:
        ip_layer = IPv6(dst=dst, hlim=ttl)
        if source:
            ip_layer.src = source
        if proto == "icmp":
            l4 = ICMPv6EchoRequest(id=0xBEEF, seq=seq)
        elif proto == "udp":
            l4 = UDP(sport=random.randint(1024, 65535), dport=port)
        else:
            l4 = TCP(sport=random.randint(1024, 65535), dport=port, flags="S", seq=random.randint(0, 2**32 - 1))
        return ip_layer / l4 / Raw(payload)
    else:
        ip_layer = IP(dst=dst, ttl=ttl)
        if source:
            ip_layer.src = source
        if proto == "icmp":
            l4 = ICMP(type=8, id=0xBEEF, seq=seq)
        elif proto == "udp":
            l4 = UDP(sport=random.randint(1024, 65535), dport=port)
        else:
            l4 = TCP(sport=random.randint(1024, 65535), dport=port, flags="S", seq=random.randint(0, 2**32 - 1))
        return ip_layer / l4 / Raw(payload)


def trace(dst: str, proto: str, port: int, timeout: float, max_ttl: int, probes: int, interval: float,
          show_asn: bool, show_dns: bool, debug: bool, source: Optional[str], payload: bytes):
    for ttl in range(1, max_ttl + 1):
        hop_ip: Optional[str] = None
        times: list[Optional[float]] = []
        dst_reached = False

        for p in range(probes):
            seq = (ttl << 8) | (p & 0xFF)
            pkt = build_packet(dst, proto, port, ttl, seq, source, payload)

            if debug:
                print(f"[debug] send ttl={ttl} probe={p+1} seq={seq} {pkt.summary()}", file=sys.stderr)

            t0 = time.perf_counter()
            reply = sr1(pkt, timeout=timeout)
            t1 = time.perf_counter()

            if debug:
                if reply is None:
                    print(f"[debug] recv ttl={ttl} probe={p+1} <timeout>", file=sys.stderr)
                else:
                    print(f"[debug] recv ttl={ttl} probe={p+1} {reply.summary()}", file=sys.stderr)

            if reply is None:
                times.append(None)
            else:
                rip = extract_reply_ip(reply)
                if rip and hop_ip is None:
                    hop_ip = rip
                times.append((t1 - t0) * 1000.0)
                if reached_destination(reply, dst, proto):
                    dst_reached = True

            if interval > 0 and p != probes - 1:
                time.sleep(interval)

        if hop_ip is None:
            line = [str(ttl), "*"]
        else:
            line = [str(ttl), hop_ip]
            if show_dns:
                name = reverse_dns(hop_ip)
                if name:
                    line.append(name)
            if show_asn:
                asn = get_asn(hop_ip, timeout) or "AS?"
                line.append(asn)

        for t in times:
            if t is None:
                line.append("*")
            else:
                line.append(f"[{t:.1f}ms]")

        print(" ".join(line))

        if dst_reached:
            break


def main():
    parser = argparse.ArgumentParser(prog="traceroute")
    parser.add_argument("-t", type=float, default=2.0)
    parser.add_argument("-p", type=int, default=80)
    parser.add_argument("-m", type=int, default=30)
    parser.add_argument("-q", type=int, default=3)
    parser.add_argument("-i", type=float, default=0.0)
    parser.add_argument("--size", type=int, default=40)
    parser.add_argument("-v", action="store_true")
    parser.add_argument("-r", "--resolve", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("-s", "--source", type=str, default=None)
    parser.add_argument("--payload", type=str, default=None)
    parser.add_argument("--payload-hex", type=str, default=None)
    parser.add_argument("ip_address")
    parser.add_argument("proto", choices=["tcp", "udp", "icmp"])
    args = parser.parse_args()

    ipaddress.ip_address(args.ip_address)

    if args.source is not None:
        src_ip = ipaddress.ip_address(args.source)
        dst_ip = ipaddress.ip_address(args.ip_address)
        if src_ip.version != dst_ip.version:
            raise SystemExit("source and destination IP versions must match (both v4 or both v6)")

    if args.q <= 0:
        raise SystemExit("q must be >= 1")
    if args.m <= 0:
        raise SystemExit("m must be >= 1")
    if args.t <= 0:
        raise SystemExit("t must be > 0")
    if args.i < 0:
        raise SystemExit("i must be >= 0")

    payload = make_payload(args.size, args.payload, args.payload_hex)

    trace(
        dst=args.ip_address,
        proto=args.proto,
        port=args.p,
        timeout=args.t,
        max_ttl=args.m,
        probes=args.q,
        interval=args.i,
        show_asn=args.v,
        show_dns=args.resolve,
        debug=args.debug,
        source=args.source,
        payload=payload,
    )


if __name__ == "__main__":
    main()
