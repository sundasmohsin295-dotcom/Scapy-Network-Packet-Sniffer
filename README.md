# Scapy Network Packet Sniffer

A compact command-line packet capture tool built with Python and Scapy. It prints a live packet summary, writes each captured frame to CSV, and reports protocol totals when the requested packet count is reached or you stop it with Ctrl+C.

## Features

- Counts every captured frame, including ARP and other non-IP traffic.
- Supports IPv4 and IPv6, with exclusive TCP, UDP, ICMP, and ICMPv6 buckets.
- Keeps protocol bucket totals aligned with the total packet count.
- Appends CSV rows and writes the header only for a new or empty file.
- Flushes each row and closes the file cleanly on Ctrl+C.
- Selects an interface, packet count, output path, and optional BPF capture filter from the CLI.
- Uses UTC timestamps and avoids storing captured packets in memory.

## Requirements

- Python 3.9 or newer
- Scapy
- Npcap on Windows, or libpcap on Linux/macOS
- Permission to capture on the selected interface

## Install

Create and activate a virtual environment, then install the dependency:

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Windows also needs [Npcap](https://npcap.com/#download). Linux may require installing libpcap using your distribution's package manager. Run packet capture with the least privilege required by your operating system; avoid running unrelated commands as administrator/root.

## Use

List interfaces:

```bash
python sniffer.py --list-interfaces
```

Capture 50 packets (default):

```bash
python sniffer.py --interface eth0
```

Capture 200 packets to a chosen CSV file:

```bash
python sniffer.py -i eth0 -c 200 -o captures/session.csv
```

Capture until Ctrl+C, with an optional BPF filter:

```bash
python sniffer.py -i eth0 -c 0 -f "tcp port 443"
```

On Windows, interface names can differ from `eth0`; use `--list-interfaces` to find the correct name. Omit `--interface` to let Scapy choose its default. Use `--quiet` to suppress per-packet console lines while keeping the CSV and final summary.

Press Ctrl+C to stop early. Completed CSV rows are flushed as they are captured, and the final summary reports the number actually recorded. Packet numbers restart at 1 for each run; records from later runs append to the same file.

## CSV columns

`Timestamp (UTC)`, `Packet #`, `Source MAC`, `Destination MAC`, `Source IP`, `Destination IP`, `Protocol`, and `Length (bytes)`. MAC/IP values are `N/A` when that layer is not present. Protocol buckets are mutually exclusive, so their counts add up to `Total packets`.

## Authorization and privacy

Capture only traffic on networks and interfaces you own or are explicitly authorized to monitor. Packet captures can contain private or sensitive information. Store CSV files securely and remove them when no longer needed. A BPF filter limits which packets Scapy captures, so filtered totals describe only packets matching that filter.

## Screenshot

![Packet sniffer output](sniffer-output.png)
