from scapy.all import *
from datetime import datetime
import csv


packet_count = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0
}


csv_file = open("captured_packets.csv", "a", newline="")
writer = csv.writer(csv_file)

writer.writerow([
    "Time",
    "Source MAC",
    "Destination MAC",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Length"
])


def packet_callback(packet):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    src_mac = packet.src
    dst_mac = packet.dst

    src_ip = "N/A"
    dst_ip = "N/A"

    protocol = "OTHER"


    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst


        if packet.haslayer(TCP):
            protocol = "TCP"
            packet_count["TCP"] += 1

        elif packet.haslayer(UDP):
            protocol = "UDP"
            packet_count["UDP"] += 1

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            packet_count["ICMP"] += 1

        else:
            packet_count["OTHER"] += 1


    print("\n==============================")
    print("Packet Captured")
    print("==============================")
    print("Time            :", timestamp)
    print("Source MAC      :", src_mac)
    print("Destination MAC :", dst_mac)
    print("Source IP       :", src_ip)
    print("Destination IP  :", dst_ip)
    print("Protocol        :", protocol)
    print("Packet Size     :", len(packet), "bytes")


    writer.writerow([
        timestamp,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        protocol,
        len(packet)
    ])



print("Network Sniffer Started...")
print("Capturing 50 packets...\n")


sniff(
    prn=packet_callback,
    count=50
)


csv_file.close()


print("\n========== Statistics ==========")
print(packet_count)