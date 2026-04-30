import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor

from clients.abuseipdb import AbuseIPDBClient
from clients.virustotal import VirusTotalClient
from clients.alienvault import AlienVaultClient
from utils.formatter import format_markdown




def fetch_all(ip):
    clients = [
        AbuseIPDBClient(),
        VirusTotalClient(),
        AlienVaultClient()
    ]

    results = []

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(client.get_report, ip) for client in clients]

        for future in futures:
            try:
                results.append(future.result(timeout=10))
            except Exception as e:
                results.append({"error": str(e)})  # keep going even if one client fails

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence CLI Tool"
    )
    parser.add_argument(
        "ip",
        help="IPv4 address to investigate"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save report to file (markdown)",
        required=False
    )
    args = parser.parse_args()
    ip_str = args.ip.strip()
    try:
        ipaddress.IPv4Address(args.ip)
    except ValueError:
        print(f"[!] Invalid IPv4 address: {args.ip}")
        exit(1)




    print(f"\n[+] Gathering intelligence for {args.ip}...\n")

    results = fetch_all(args.ip)

    markdown = format_markdown(args.ip, results)

    print(markdown)

    if args.output:
        with open(args.output, "w") as f:
            f.write(markdown)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
