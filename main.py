import logging
import os
import time
import requests
import ipaddress
import urllib3

# Environment variables
OPNSENSE_URL = os.getenv("OPNSENSE_URL", None)
OPNSENSE_API_KEY = os.getenv("OPNSENSE_API_KEY", None)
OPNSENSE_API_SECRET = os.getenv("OPNSENSE_API_SECRET", None)
TECHNITIUM_URL = os.getenv("TECHNITIUM_URL", None)
TECHNITIUM_TOKEN = os.getenv("TECHNITIUM_TOKEN", None)
DNS_ZONE_SUBNETS = os.getenv("DNS_ZONE_SUBNETS", None)
DO_V4 = (os.getenv("DO_V4", "false").lower() == "true")
VERIFY_HTTPS = (os.getenv("VERIFY_HTTPS", "true").lower() == "true")
CLOCK = int(os.getenv("CLOCK", "30"))

def get_opnsense_data(path):
    r = requests.get(url=OPNSENSE_URL + path, verify=VERIFY_HTTPS, auth=(OPNSENSE_API_KEY, OPNSENSE_API_SECRET))
    if r.status_code != 200:
        logging.error("Error occurred" + str(r.status_code) + ": " + r.text)
        return None
    return r.json()

def get_ndp():
    return get_opnsense_data("/api/diagnostics/interface/search_ndp")

def get_dhcp4_leases():
    return get_opnsense_data("/api/dhcpv4/leases/searchLease")

def build_matches(ndp, leases):
    matches = set()
    for e in leases["rows"]:
        ip6s = tuple(x["ip"].split("%")[0] for x in ndp["rows"] if x["mac"] == e["mac"])
        if len(ip6s) == 0 and not DO_V4:
            continue
        matches.add((e["address"], ip6s, e["hostname"]))
    return matches

def find_zone(zones, ip4):
    for zone in zones:
        if ip4 in zone[0]: return zone[1]
    return None

def get_existing_records(domain, zone):
    url = f"{TECHNITIUM_URL}/api/zones/records/get?token={TECHNITIUM_TOKEN}&domain={domain}.{zone}"
    r = requests.get(url=url, verify=VERIFY_HTTPS)
    if r.status_code != 200:
        logging.error("Error fetching existing records: " + str(r.status_code) + ": " + r.text)
        return []
    return r.json().get("response", {}).get("records", [])

def delete_record(zone, domain, record_type, value):
    url = f"{TECHNITIUM_URL}/api/zones/records/delete?token={TECHNITIUM_TOKEN}&domain={domain}.{zone}&zone={zone}&type={record_type}&value={value}"
    r = requests.get(url=url, verify=VERIFY_HTTPS)
    if r.status_code != 200:
        logging.error("Error deleting record: " + str(r.status_code) + ": " + r.text)
    else:
        logging.info(f"Deleted {record_type} record for {value} in {domain}.{zone}")

def add_record(zone, domain, record_type, ip):
    url = f"{TECHNITIUM_URL}/api/zones/records/add?token={TECHNITIUM_TOKEN}&domain={domain}.{zone}&type={record_type}&ttl=5&expiryTtl=604800&overwrite=false&ptr=true&ipAddress={ip}"
    r = requests.get(url=url, verify=VERIFY_HTTPS)
    if r.status_code != 200:
        logging.error("Error adding record: " + str(r.status_code) + ": " + r.text)
    else:
        logging.info(f"Added {record_type} record for {ip} in {domain}.{zone}")

def sync_records(zones, match):
    zone = find_zone(zones, ipaddress.ip_address(match[0]))
    if zone is None:
        logging.warning("Could not find a DNS zone for " + match[0])
        return

    ip4 = match[0]
    ip6s = [ipaddress.ip_address(x).compressed for x in match[1]]
    hostname = match[2]

    if hostname == "":
        logging.warning("No hostname found for " + match[0])
        return

    existing_records = get_existing_records(hostname, zone)
    existing_ips = {ipaddress.ip_address(r["rData"]["ipAddress"]).compressed for r in existing_records if r["type"] in ["A", "AAAA"]}
    current_ips = set([ipaddress.ip_address(ip4).compressed] if DO_V4 else []) | set(ip6s)

    # Delete outdated records
    for ip in existing_ips - current_ips:
        record_type = "A" if "." in ip else "AAAA"
        delete_record(zone, hostname, record_type, ip)

    # Add missing records
    for ip in current_ips - existing_ips:
        record_type = "A" if "." in ip else "AAAA"
        add_record(zone, hostname, record_type, ip)

def run():
    if not VERIFY_HTTPS:
        urllib3.disable_warnings()

    previous_matches = set()
    zones = []
    for z in DNS_ZONE_SUBNETS.split(","):
        zone = z.split("=")
        zones.append((ipaddress.ip_network(zone[0]), zone[1]))

    while True:
        ndp = get_ndp()
        if ndp is None:
            logging.error("Error retrieving NDP table")
            continue
        leases = get_dhcp4_leases()
        if leases is None:
            logging.error("Error retrieving DHCPv4 leases")
            continue
        matches = build_matches(ndp, leases)
        new_matches = matches - previous_matches
        previous_matches = matches

        for match in new_matches:
            sync_records(zones, match)
        time.sleep(CLOCK)

def verify_env() -> bool:
    if not OPNSENSE_URL: return False
    if not OPNSENSE_API_KEY: return False
    if not OPNSENSE_API_SECRET: return False
    if not TECHNITIUM_URL: return False
    if not TECHNITIUM_TOKEN: return False
    if not DNS_ZONE_SUBNETS: return False
    return True

if __name__ == "__main__":
    logging.getLogger().setLevel(os.getenv("LOG_LEVEL", "INFO"))
    logging.info("loading environment...")

    if not verify_env():
        logging.error("Missing mandatory environment variables")
        exit(0)

    logging.info("Starting SLAACsense...")
    logging.info("OPNSENSE_URL: {}".format(OPNSENSE_URL))
    logging.info("TECHNITIUM_URL: {}".format(TECHNITIUM_URL))
    logging.info("VERIFY_HTTPS: {}".format(VERIFY_HTTPS))
    run()
