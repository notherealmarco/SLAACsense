# SLAACsense

SLAACsense streamlines the process of configuring DNS records on OPNsense routers using Technitium DNS Server.

Designed to enhance network management, the tool automatically defines DNS A, AAAA, and PTR records for each device connected to the network based on its DHCPv4 hostname.

By leveraging the (dnsmasq) DHCPv4 lease information and mapping it to the MAC address, the tool navigates the NDP table to retrieve IPv6 addresses associated with each host. Subsequently, it configures the DNS records accordingly, providing a seamless solution for maintaining an up-to-date and accurate DNS configuration.

## Usage:

Define the environment variables in the docker-compose file, then run: `docker compose up -d`

### Environment variables:

| Variable Name         | Description                                                                              | Example Value                                                          |
|-----------------------|------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `OPNSENSE_URL`        | The base URL of your OPNsense instance                                                   | http://192.168.1.1 (required)                                          
| `OPNSENSE_API_KEY`    | OPNsense API key                                                                         | `your_opnsense_api_key` (required)                                     |
| `OPNSENSE_API_SECRET` | OPNsense API secret                                                                      | `a_very_secret_token` (required)                                       |
| `TECHNITIUM_URL`      | The base URL of your Technitium DNS instance                                             | `dns.myawesomehome.home.arpa` (required)                               |
| `TECHNITIUM_TOKEN`    | Technitium DNS token                                                                     | `another_very_secret_token` (required)                                 |
| `DNS_ZONE_SUBNETS`    | Comma separated DNS zones and IPv4 subnet                                                | `192.168.1.0/24=lan.home.arpa,192.168.2.0/24=dmz.home.arpa` (required) |
| `DO_V4`               | If set to true, A records will be configured, otherwise only AAAA records are configured | `false` (defaults to false)                                            |
| `PTR_ONLY`            | If set to true, only PTR records will be created/updated, no A/AAAA records              | `false` (defaults to false)                                            |
| `REVERSE_ZONES`       | Comma separated subnet prefixes for which to create PTR records (both IPv4 and IPv6)     | `2001:db8:abcd::/48,192.168.10.0/24` (required when `PTR_ONLY=true`)   |
| `IGNORE_LINK_LOCAL`   | If set to true, link local IPv6 addresses wil be ignored                                 | `true` (defaults to true)                                              |
| `VERIFY_HTTPS`        | Verify OPNsense and Technitium's SSL certificates                                        | `true` (defaults to true)                                              |
| `CLOCK`               | Interval between updates (in seconds)                                                    | `30` (defaults to 30)                                                  |
| `REFRESH_CYCLE`       | How often to refresh all DNS records (in cycles)                                         | `120` (defaults to 1440, 12 hours with default CLOCK)                    |

### Note
You have to create the corresponding DNS zones in the Technitium dashboard, you can configure them as primary or conditional forwarder zones.
If DNS records are not being added, make sure that the corresponding forward and reverse zones exist in Technitium DNS, otherwise the script will fail silently.
For each prefix listed in `REVERSE_ZONES`, the corresponding reverse zone (e.g. `d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa` for `2001:db8:abcd::/48`) must exist in Technitium; the prefix's length must match the reverse zone boundary you configured.

Records are created with an expiration TTL and re-added only when needed (missing, changed, or within `CLOCK * REFRESH_CYCLE + 60` seconds of expiring), so no redundant write is made while keeping records alive. Stale PTR records are intentionally left in place for historical reference.

### Contributing:
I welcome contributions! Feel free to submit issues, feature requests, or pull requests.

For example, you may add the support for other DNS servers, like Bind, and other routing platforms, like pfSense and OpenWrt. 

### License:
This tool is released under the MIT license. See the LICENSE file for details.