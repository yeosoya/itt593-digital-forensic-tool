import argparse
from digital_forensic_tool import run_forensic_tool

parser = argparse.ArgumentParser(
    description="Digital Forensic CLI Tool (ITT593)"
)

parser.add_argument(
    "--pcap",
    required=True,
    help="Path to network data CSV"
)

parser.add_argument(
    "--logs",
    required=True,
    help="Path to authentication log CSV"
)

args = parser.parse_args()

print("\n[CLI MODE] Starting forensic analysis...\n")

run_forensic_tool(
    pcap_file=args.pcap,
    log_file=args.logs
)
