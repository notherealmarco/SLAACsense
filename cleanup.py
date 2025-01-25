import os
import logging
import requests
import urllib3
import ipaddress

# Environment variables
TECHNITIUM_URL = os.getenv("TECHNITIUM_URL", None)
TECHNITIUM_TOKEN = os.getenv("TECHNITIUM_TOKEN", None)
VERIFY_HTTPS = (os.getenv("VERIFY_HTTPS", "true").lower() == "true")
DNS_ZONE_SUBNETS = os.getenv("DNS_ZONE_SUBNETS", None)

def get_existing_records(domain, zone):
    url = f"{TECHNITIUM_URL}/api/zones/records/get?token={TECHNITIUM_TOKEN}&domain={domain}.{zone}"
    r = requests.get(url=url, verify=VERIFY_HTTPS)
    if r.status_code != 200:
        logging.error(f"Error fetching records for {domain}.{zone}: {r.status_code} - {r.text}")
        return []
    return r.json().get("response", {}).get("records", [])

def delete_record(zone, domain, record_type, value):
    url = f"{TECHNITIUM_URL}/api/zones/records/delete?token={TECHNITIUM_TOKEN}&domain={domain}.{zone}&zone={zone}&type={record_type}&value={value}"
    r = requests.get(url=url, verify=VERIFY_HTTPS)
    if r.status_code != 200:
        logging.error(f"Error deleting {record_type} record {value} in {domain}.{zone}: {r.status_code} - {r.text}")
    else:
        logging.info(f"Deleted {record_type} record {value} in {domain}.{zone}")

def cleanup_zone(zone, subnet):
    logging.info(f"Cleaning up zone: {zone} for subnet: {subnet}")
    ip_network = ipaddress.ip_network(subnet)

    # Loop through all possible addresses in the subnet
    for ip in ip_network:
        domain = str(ip.reverse_pointer)[2:]  # PTR-like domain
        existing_records = get_existing_records(domain, zone)

        # Delete all A/AAAA records for the domain
        for record in existing_records:
            record_type = record["type"]
            if record_type in ["A", "AAAA"]:
                delete_record(zone, domain, record_type, record["rData"]["ipAddress"])

def run_cleanup():
    if not VERIFY_HTTPS:
        urllib3.disable_warnings()

    if not TECHNITIUM_URL or not TECHNITIUM_TOKEN or not DNS_ZONE_SUBNETS:
        logging.error("Missing mandatory environment variables.")
        exit(1)

    zones = []
    for z in DNS_ZONE_SUBNETS.split(","):
        subnet, zone = z.split("=")
        zones.append((subnet, zone))

    for subnet, zone in zones:
        cleanup_zone(zone, subnet)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting DNS cleanup script...")
    run_cleanup()
