import argparse
import socket
import struct
import time
import select
from collections import deque

DEFAULT_MAX_HOPS = 30
DEFAULT_TIMEOUT = 2.0
DEFAULT_PROBES = 3
DEFAULT_HIGH_RTT_MS = 200.0

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise SystemExit(f"Не удалось разрешить {host}: {e}")

def hostname_or_ip(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return f"{name} ({ip})"
    except (socket.herror, socket.gaierror):
        return ip

def traceroute(
    dest_name: str,
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_TIMEOUT,
    probes: int = DEFAULT_PROBES,
    high_rtt_ms: float = DEFAULT_HIGH_RTT_MS,
):
    dest_addr = resolve_host(dest_name)
    print(f"traceroute to {dest_name} ({dest_addr}), {max_hops} hops max")

    last_ips = deque(maxlen=5)

    port = 33434
    icmp_proto = socket.getprotobyname("icmp")
    udp_proto = socket.getprotobyname("udp")

    for ttl in range(1, max_hops + 1):
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
        recv_sock.settimeout(timeout)
        recv_sock.bind(("", port))

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp_proto)
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        print(f"{ttl:2d} ", end="", flush=True)

        hop_ip = None
        rtts = []

        for probe in range(probes):
            try:
                send_time = time.time()
                send_sock.sendto(b"", (dest_addr, port))
                ready, _, _ = select.select([recv_sock], [], [], timeout)

                if not ready:
                    print(" *", end="", flush=True)
                    continue

                recv_time = time.time()
                packet, addr = recv_sock.recvfrom(512)
                rtt_ms = (recv_time - send_time) * 1000.0
                rtts.append(rtt_ms)

                hop_ip = addr[0]
                if probe == 0:
                    print(f"{hostname_or_ip(hop_ip):>40} ", end="", flush=True)

                if rtt_ms > high_rtt_ms:
                    print(f"{rtt_ms:7.3f} ms(HIGH_RTT)", end="", flush=True)
                else:
                    print(f"{rtt_ms:7.3f} ms", end="", flush=True)

            except socket.timeout:
                print(" *", end="", flush=True)
            except OSError as e:
                print(f" ошибка({e})", end="", flush=True)
                break

        send_sock.close()
        recv_sock.close()
        print()

        if hop_ip is not None:
            last_ips.append(hop_ip)
            if list(last_ips).count(hop_ip) >= 3:
                print(f"    >>> ВОЗМОЖНЫЙ ЦИКЛ: IP {hop_ip} встречается на нескольких хопах подряд (LOOP?)")

        if hop_ip == dest_addr:
            print("    Целевой хост достигнут.")
            break

def main():
    parser = argparse.ArgumentParser(description="Простейшая реализация traceroute на Python.")
    parser.add_argument("host", help="доменное имя или IP назначения")
    parser.add_argument("-m", "--max-hops", type=int, default=DEFAULT_MAX_HOPS, help="максимальное количество хопов")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="таймаут одного запроса (сек)")
    parser.add_argument("-p", "--probes", type=int, default=DEFAULT_PROBES, help="число попыток на каждый хоп")
    parser.add_argument(
        "--high-rtt",
        type=float,
        default=DEFAULT_HIGH_RTT_MS,
        help="порог RTT в миллисекундах для отметки HIGH_RTT",
    )

    args = parser.parse_args()

    try:
        traceroute(
            args.host,
            max_hops=args.max_hops,
            timeout=args.timeout,
            probes=args.probes,
            high_rtt_ms=args.high_rtt,
        )
    except PermissionError:
        print("PermissionError: для raw-сокетов нужны root/админ права. Запусти через sudo/от имени администратора.")

if __name__ == "__main__":
    main()
