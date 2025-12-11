import pyshark
import matplotlib.pyplot as plt
from collections import Counter
import time

plt.ion()


proto_counts = Counter()


fig, ax = plt.subplots(figsize=(7, 7))
last_update = time.time()

print("scanning")

try:
    capture = pyshark.LiveCapture(interface='Wi-Fi', bpf_filter='ip')

    for packet in capture.sniff_continuously():


        if 'TCP' in packet:
            proto_counts['TCP'] += 1
        elif 'UDP' in packet:
            proto_counts['UDP'] += 1
        elif 'ICMP' in packet:
            proto_counts['ICMP'] += 1
        else:
            proto_counts['Other'] += 1


        if time.time() - last_update >= 1.0:
            last_update = time.time()

            labels = list(proto_counts.keys())
            values = list(proto_counts.values())

            ax.clear()
            ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
            ax.set_title("Protocols Distribution")

            plt.draw()
            plt.pause(0.001)

except KeyboardInterrupt:
    capture.close()
    plt.ioff()
    plt.show()
