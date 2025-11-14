import pyshark
import socket
import matplotlib.pyplot as plt
import pandas as pd

src_data = []
dst_data = []


try:
    capture = pyshark.LiveCapture(interface='Wi-Fi')

    print("Listening for requests...")
    for packet in capture.sniff_continuously():
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            try:
                hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(src_ip)
                destination = socket.gethostbyaddr(dst_ip)[0]
                print(f"Packet captured: Source IP: {src_ip} ({hostname}) -> Dest IP: {dst_ip} ({destination})")
                src_data.append(hostname)
                dst_data.append(destination)
            except socket.herror:
                # No DNS name found for this IP
                print(f"Packet captured: Source IP: {src_ip} -> Dest IP: {dst_ip} (No reverse DNS)")
        else:
            continue
except KeyboardInterrupt:
    print("A key was pressed")
    src_df = pd.DataFrame(src_data, columns=['Source'])
    dst_df = pd.DataFrame(dst_data, columns=['Destination'])

    src_counts = src_df['Source'].value_counts()
    dst_counts = dst_df['Destination'].value_counts()

    plt.figure(figsize=[10, 5])
    plt.bar(src_counts.index, src_counts.values, align='center')
    plt.xlabel('Source IP')
    plt.ylabel('Number of packets')
    plt.title('Abundance of Source IPs')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=[10, 5])
    plt.bar(dst_counts.index, dst_counts.values, align='center')
    plt.xlabel('Destination IP')
    plt.ylabel('Number of packets')
    plt.title('Abundance of Destination IPs')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

    capture.close()





