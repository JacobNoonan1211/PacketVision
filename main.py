import pyshark
import socket
import matplotlib.pyplot as plt
import pandas as pd
import time
from collections import Counter

plt.ion()

src_counter = Counter()
dst_counter = Counter()
dns_cache = {}



def resolve_ip(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        host = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        host = ip
    dns_cache[ip] = host
    return host


from collections import defaultdict
import time

packet_counts = Counter()
port_activity = defaultdict(set)
icmp_count = 0
last_reset = time.time()

SUSPICIOUS_PORTS = {4444, 1337, 31337, 5555}

def is_suspicious(packet):
    global icmp_count, last_reset

    now = time.time()

    # reset every 5 seconds
    if now - last_reset > 5:
        packet_counts.clear()
        port_activity.clear()
        icmp_count = 0
        last_reset = now


    if 'IP' not in packet:
        return False

    src = packet.ip.src


    packet_counts[src] += 1


    if packet_counts[src] > 200:
        return f"high packet volume from {src} "


    if 'TCP' in packet or 'UDP' in packet:
        dport = int(packet[packet.transport_layer].dstport)
        port_activity[src].add(dport)

        if len(port_activity[src]) > 20:
            return f"port scan suspected from {src} (hit {len(port_activity[src])} ports)."


        if dport in SUSPICIOUS_PORTS:
            return f"traffic to susicious port {dport} from {src}."


    if 'ICMP' in packet:
        icmp_count += 1
        if icmp_count > 100:
            return "possible icmp flood detected."


    if 'DNS' in packet:
        if hasattr(packet.dns, 'qry_name'):
            qname = packet.dns.qry_name
            if len(qname) > 60:
                return f"suspisciosu long dns query ({len(qname)} chars): {qname}"

    return False


fig, ax = plt.subplots(figsize=(7,7))
fig2, ax2 = plt.subplots(figsize=(7,7))

pie_chart = None
last_update = time.time()

try:
    capture = pyshark.LiveCapture(interface='Wi-Fi', bpf_filter='ip')

    for packet in capture.sniff_continuously():
        if 'IP' not in packet:
            continue
        src_ip = packet.ip.src
        src_host = resolve_ip(src_ip)

        dst_ip = packet.ip.dst
        dst_host = resolve_ip(dst_ip)

        src_counter[src_host] += 1
        dst_counter[dst_host] += 1


        if time.time() - last_update >= 1.0:
            last_update = time.time()

            labels = list(src_counter.keys())
            values = list(src_counter.values())

            ax.clear()
            ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
            ax.set_title("src hosts")
            plt.draw()
            plt.pause(0.001)

            labels = list(dst_counter.keys())
            values = list(dst_counter.values())

            ax2.clear()
            ax2.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
            ax2.set_title("dst hosts")
            plt.draw()
            plt.pause(0.001)

except KeyboardInterrupt:
    capture.close()
    plt.ioff()
    plt.show()
