import os
import random
import socket
import threading
import time
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional

try:
    import pyshark  # optional
except ImportError:
    pyshark = None


# Shared state
src_counter: Counter = Counter()
dst_counter: Counter = Counter()
packet_counts: Counter = Counter()
port_activity: defaultdict = defaultdict(set)

_dns_cache: Dict[str, str] = {}
_alerts: List[str] = []

lock = threading.Lock()

# Config (tunable)
SUSPICIOUS_PORTS = {4444, 1337, 31337, 5555}
WINDOW_SECONDS = int(os.getenv("PV_WINDOW_SECONDS", "5"))
MAX_PKTS_PER_WINDOW = int(os.getenv("PV_MAX_PKTS", "200"))
MAX_PORTS_PER_WINDOW = int(os.getenv("PV_MAX_PORTS", "20"))
MAX_ICMP_PER_WINDOW = int(os.getenv("PV_MAX_ICMP", "100"))
MAX_DNS_LEN = int(os.getenv("PV_MAX_DNS_LEN", "60"))

_icmp_count = 0
_last_reset = time.time()


def resolve_ip(ip: str) -> str:
    if ip in _dns_cache:
        return _dns_cache[ip]
    try:
        host = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        host = ip
    _dns_cache[ip] = host
    return host


def register_alert(message: str) -> None:
    with lock:
        ts = time.strftime("%H:%M:%S")
        _alerts.append(f"[{ts}] {message}")
        del _alerts[:-50]


def _reset_window(now: float) -> None:
    global _icmp_count, _last_reset
    packet_counts.clear()
    port_activity.clear()
    _icmp_count = 0
    _last_reset = now


def inspect_packet(packet) -> None:
    """Inspect a packet-like object (PyShark packet) and register suspicious activity."""
    global _icmp_count, _last_reset

    now = time.time()
    if now - _last_reset > WINDOW_SECONDS:
        _reset_window(now)

    if "IP" not in packet:
        return

    src = packet.ip.src
    packet_counts[src] += 1

    if packet_counts[src] > MAX_PKTS_PER_WINDOW:
        register_alert(
            f"High packet rate: {src} ({packet_counts[src]}/{WINDOW_SECONDS}s)"
        )

    if "TCP" in packet or "UDP" in packet:
        try:
            dport = int(packet[packet.transport_layer].dstport)
        except Exception:
            dport = None

        if dport is not None:
            port_activity[src].add(dport)

            if len(port_activity[src]) > MAX_PORTS_PER_WINDOW:
                register_alert(
                    f"Port scan suspected: {src} hit {len(port_activity[src])} ports/{WINDOW_SECONDS}s"
                )

            if dport in SUSPICIOUS_PORTS:
                register_alert(f"Traffic to suspicious port {dport} from {src}")

    if "ICMP" in packet:
        _icmp_count += 1
        if _icmp_count > MAX_ICMP_PER_WINDOW:
            register_alert(f"Possible ICMP flood ({_icmp_count}/{WINDOW_SECONDS}s)")

    if "DNS" in packet and hasattr(packet.dns, "qry_name"):
        qname = str(packet.dns.qry_name)
        if len(qname) > MAX_DNS_LEN:
            register_alert(f"Long DNS query ({len(qname)} chars): {qname}")


def capture_packets(interface: str, stop_event: threading.Event) -> None:
    if pyshark is None:
        register_alert("PyShark not installed; capture disabled. Set PV_DEMO=1 for demo mode.")
        return

    try:
        capture = pyshark.LiveCapture(interface=interface, bpf_filter="ip")
    except Exception as exc:
        register_alert(f"Packet capture unavailable: {exc}")
        return

    # PyShark sniff_continuously() isn't stop_event-aware; we check stop_event each loop.
    for packet in capture.sniff_continuously():
        if stop_event.is_set():
            break
        try:
            if "IP" not in packet:
                continue

            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_host = resolve_ip(src_ip)
            dst_host = resolve_ip(dst_ip)

            with lock:
                src_counter[src_host] += 1
                dst_counter[dst_host] += 1

            inspect_packet(packet)
        except Exception as exc:
            register_alert(f"Error processing packet: {exc}")


def simulate_traffic(stop_event: threading.Event) -> None:
    def random_ip() -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    hosts = [
        "api.internal",
        "db.internal",
        "cache.internal",
        "cdn.example.com",
        "users.example.com",
        "auth.example.com",
    ]

    register_alert("Demo mode enabled (synthetic traffic).")

    while not stop_event.is_set():
        src = random.choice(hosts)
        dst = random.choice(hosts)
        src_ip = random_ip()
        dst_ip = random_ip()

        with lock:
            src_counter[src] += 1
            dst_counter[dst] += 1

        if random.random() < 0.05:
            register_alert(f"Demo alert: unusual traffic {src_ip} -> {dst_ip}")

        time.sleep(0.5)


def get_stats() -> Dict:
    def top(counter: Counter) -> Tuple[List[str], List[int]]:
        with lock:
            items = counter.most_common()
        return [k for k, _ in items], [v for _, v in items]

    src_labels, src_values = top(src_counter)
    dst_labels, dst_values = top(dst_counter)

    with lock:
        alerts = list(reversed(_alerts))

    return {
        "sources": {"labels": src_labels, "values": src_values},
        "destinations": {"labels": dst_labels, "values": dst_values},
        "alerts": alerts,
    }


def start_monitor_thread(stop_event: threading.Event) -> threading.Thread:
    demo_mode = os.getenv("PV_DEMO", "0") == "1"
    interface = os.getenv("PV_INTERFACE", "Wi-Fi")

    if demo_mode:
        target = simulate_traffic
        args = (stop_event,)
    else:
        target = capture_packets
        args = (interface, stop_event)

    t = threading.Thread(target=target, args=args, daemon=True)
    t.start()
    return t
