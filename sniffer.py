#!/usr/bin/env python3
"""Capture and summarize packets on an authorized network interface."""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from scapy.all import ARP, Ether, ICMP, ICMPv6, IP, IPv6, TCP, UDP, get_if_list, sniff
from scapy.error import Scapy_Exception
from scapy.packet import Packet


CSV_HEADER = (
    "Timestamp (UTC)",
    "Packet #",
    "Source MAC",
    "Destination MAC",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Length (bytes)",
)

# These exclusive buckets sum to the number of captured frames. Transport
# protocols are counted in their own bucket instead of also counting as IPv4/6.
PROTOCOLS = ("TCP", "UDP", "ICMP", "ICMPv6", "ARP", "IPv4", "IPv6", "OTHER")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture packets, print a live summary, and append rows to CSV."
    )
    parser.add_argument("-i", "--interface", help="capture interface (default: Scapy's default)")
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=50,
        metavar="N",
        help="number of packets to capture; use 0 for unlimited (default: 50)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("captured_packets.csv"),
        help="CSV output path (default: captured_packets.csv)",
    )
    parser.add_argument(
        "-f",
        "--filter",
        dest="capture_filter",
        help="optional libpcap/BPF capture filter, for example 'tcp port 443'",
    )
    parser.add_argument("--list-interfaces", action="store_true", help="list capture interfaces and exit")
    parser.add_argument("-q", "--quiet", action="store_true", help="hide per-packet output")
    args = parser.parse_args(argv)
    if args.count < 0:
        parser.error("--count must be zero or a positive integer")
    return args


def identify_protocol(packet: Packet) -> str:
    """Return one mutually exclusive bucket for every captured frame."""
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMPv6):
        return "ICMPv6"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(IP):
        return "IPv4"
    return "OTHER"


def packet_addresses(packet: Packet) -> tuple[str, str, str, str]:
    """Extract link-layer and IP/ARP endpoints without assuming every layer exists."""
    source_mac = packet[Ether].src if packet.haslayer(Ether) else "N/A"
    destination_mac = packet[Ether].dst if packet.haslayer(Ether) else "N/A"

    if packet.haslayer(ARP):
        source_ip = packet[ARP].psrc or "N/A"
        destination_ip = packet[ARP].pdst or "N/A"
    elif packet.haslayer(IPv6):
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst
    elif packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
    else:
        source_ip = destination_ip = "N/A"

    return source_mac, destination_mac, source_ip, destination_ip


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def prepare_csv(path: Path) -> tuple[TextIO, Any]:
    """Open CSV in append mode and write its header only when it has no content."""
    path.parent.mkdir(parents=True, exist_ok=True)
    output = path.open("a+", newline="", encoding="utf-8")
    try:
        output.seek(0, 2)
        size = output.tell()
        if size == 0:
            writer = csv.writer(output)
            writer.writerow(CSV_HEADER)
            output.flush()
        else:
            # Avoid joining a new CSV row onto a final row left without a newline.
            with path.open("rb") as existing:
                existing.seek(-1, 2)
                last_byte = existing.read(1)
            if last_byte not in (b"\n", b"\r"):
                output.seek(0, 2)
                output.write("\n")
            writer = csv.writer(output)
        return output, writer
    except BaseException:
        output.close()
        raise


def make_packet_callback(writer: Any, output: TextIO, counts: Counter[str], quiet: bool):
    def packet_callback(packet: Packet) -> None:
        packet_number = counts["TOTAL"] + 1
        timestamp = utc_timestamp()
        protocol = identify_protocol(packet)
        source_mac, destination_mac, source_ip, destination_ip = packet_addresses(packet)
        packet_length = len(packet)

        counts["TOTAL"] = packet_number
        counts[protocol] += 1
        writer.writerow(
            (
                timestamp,
                packet_number,
                source_mac,
                destination_mac,
                source_ip,
                destination_ip,
                protocol,
                packet_length,
            )
        )
        # Flushing each completed row keeps Ctrl+C captures useful and readable.
        output.flush()

        if not quiet:
            source = source_ip if source_ip != "N/A" else source_mac
            destination = destination_ip if destination_ip != "N/A" else destination_mac
            print(
                f"{packet_number:>5}  {timestamp}  {protocol:<6}  "
                f"{source} -> {destination}  {packet_length} B",
                flush=True,
            )

    return packet_callback


def print_summary(counts: Counter[str], output_path: Path) -> None:
    print("\nCapture summary")
    print("---------------")
    print(f"Total packets : {counts['TOTAL']}")
    for protocol in PROTOCOLS:
        print(f"{protocol:<13}: {counts[protocol]}")
    print(f"CSV file      : {output_path}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.list_interfaces:
        for interface in get_if_list():
            print(interface)
        return 0

    counts: Counter[str] = Counter()
    output: TextIO | None = None
    interrupted = False
    try:
        output, writer = prepare_csv(args.output)
        callback = make_packet_callback(writer, output, counts, args.quiet)
        target = args.interface or "Scapy default interface"
        limit = str(args.count) if args.count else "until interrupted"
        print(f"Capturing on {target}; limit: {limit}; CSV: {args.output}")
        if args.capture_filter:
            print(f"Capture filter: {args.capture_filter}")
        sniff(
            iface=args.interface,
            filter=args.capture_filter,
            count=args.count,
            prn=callback,
            store=False,
        )
    except KeyboardInterrupt:
        interrupted = True
        print("\nCapture interrupted; closing the CSV cleanly.")
    except (OSError, Scapy_Exception) as error:
        print(f"Capture failed: {error}", file=sys.stderr)
        return 1
    finally:
        if output is not None:
            output.close()

    print_summary(counts, args.output)
    if interrupted:
        print("Capture stopped by user.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
