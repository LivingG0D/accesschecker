#!/usr/bin/env python3
"""
Check-Host TCP Scanner — Iran Connectivity Filter
Uses https://check-host.net/about/api to TCP-check IPs and find those
reachable from Iran but unreachable (or < 3 countries) outside Iran.
"""

import json
import os
import sys
import time
import ipaddress
import urllib.request
import urllib.error
import urllib.parse

# Enable ANSI colors on Windows 10+
if sys.platform == "win32":
    os.system("")

# ── Constants ────────────────────────────────────────────────────────────────
API_BASE = "https://check-host.net"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
MAX_NODES = 40
POLL_INTERVAL = 3        # seconds between result polls
POLL_TIMEOUT = 20        # max seconds to wait for results
REQUEST_DELAY = 1.5      # delay between check requests (rate-limit)
IRAN_CODE = "ir"
NON_IRAN_COUNTRY_THRESHOLD = 3  # fewer than this = "filtered/blocked"

# ── Colors (ANSI) ────────────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    MAGENTA = "\033[95m"
    WHITE  = "\033[97m"
    BG_GREEN = "\033[42m"
    BG_RED   = "\033[41m"


def banner():
    print(f"""
{C.CYAN}{C.BOLD}+----------------------------------------------------------+
|   Check-Host TCP Scanner - Iran Connectivity Filter      |
|   API: https://check-host.net                            |
+----------------------------------------------------------+{C.RESET}
""")


# ── IP Parsing ───────────────────────────────────────────────────────────────
def parse_ips(raw: str) -> list[str]:
    """Parse comma-separated IPs and/or CIDR ranges into a flat list."""
    ips = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            try:
                network = ipaddress.ip_network(token, strict=False)
                for addr in network.hosts():
                    ips.append(str(addr))
            except ValueError:
                print(f"{C.RED}  [!] Invalid CIDR range: {token}{C.RESET}")
        else:
            try:
                ipaddress.ip_address(token)
                ips.append(token)
            except ValueError:
                print(f"{C.RED}  [!] Invalid IP address: {token}{C.RESET}")
    return ips


# ── API Helpers ──────────────────────────────────────────────────────────────
def api_get(path: str) -> dict | None:
    """Make a GET request to the check-host.net API."""
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"{C.RED}  [!] HTTP {e.code}: {e.reason} -- {url}{C.RESET}")
        return None
    except urllib.error.URLError as e:
        print(f"{C.RED}  [!] Network error: {e.reason}{C.RESET}")
        return None
    except Exception as e:
        print(f"{C.RED}  [!] Error: {e}{C.RESET}")
        return None


def start_tcp_check(ip: str, port: int) -> tuple[str | None, dict]:
    """Start a TCP check and return (request_id, nodes_map)."""
    host_param = f"{ip}:{port}"
    path = f"/check-tcp?host={urllib.parse.quote(host_param)}&max_nodes={MAX_NODES}"
    data = api_get(path)
    if not data or not data.get("ok"):
        return None, {}
    return data.get("request_id"), data.get("nodes", {})


def poll_results(request_id: str) -> dict:
    """Poll the API until all nodes respond or we time out."""
    deadline = time.time() + POLL_TIMEOUT
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        data = api_get(f"/check-result/{request_id}")
        if data is None:
            continue
        # Check if all nodes have responded (no None values)
        if all(v is not None for v in data.values()):
            return data
    # Return whatever we have on timeout
    return data if data else {}


# ── Analysis ─────────────────────────────────────────────────────────────────
def is_connected(result) -> bool:
    """Check if a node's TCP result indicates a successful connection."""
    if result is None:
        return False
    if isinstance(result, list) and len(result) > 0:
        entry = result[0]
        if isinstance(entry, dict):
            return "time" in entry and "error" not in entry
    return False


def analyze_results(nodes_map: dict, results: dict) -> dict:
    """
    Analyze TCP results.
    Returns {
        "iran_connected": bool,
        "iran_nodes": [(node, connected_bool), ...],
        "non_iran_countries_connected": set of country codes,
        "all_countries": { country_code: { "name": ..., "connected": int, "total": int } }
    }
    """
    iran_connected = False
    iran_nodes = []
    non_iran_connected = set()
    all_countries = {}

    for node, info in nodes_map.items():
        country_code = info[0] if isinstance(info, list) and len(info) > 0 else "??"
        country_name = info[1] if isinstance(info, list) and len(info) > 1 else "Unknown"

        if country_code not in all_countries:
            all_countries[country_code] = {"name": country_name, "connected": 0, "total": 0}

        all_countries[country_code]["total"] += 1
        connected = is_connected(results.get(node))

        if connected:
            all_countries[country_code]["connected"] += 1

        if country_code == IRAN_CODE:
            iran_nodes.append((node, connected))
            if connected:
                iran_connected = True
        else:
            if connected:
                non_iran_connected.add(country_code)

    return {
        "iran_connected": iran_connected,
        "iran_nodes": iran_nodes,
        "non_iran_countries_connected": non_iran_connected,
        "all_countries": all_countries,
    }


# ── Display ──────────────────────────────────────────────────────────────────
def print_ip_result(ip: str, port: int, analysis: dict, match: bool):
    """Print a formatted result block for one IP."""
    tag = f"{C.BG_GREEN}{C.WHITE}{C.BOLD} ★ MATCH {C.RESET}" if match else f"{C.GRAY}  SKIP  {C.RESET}"
    iran_status = f"{C.GREEN}✔ Connected{C.RESET}" if analysis["iran_connected"] else f"{C.RED}✗ No connection{C.RESET}"
    non_iran_count = len(analysis["non_iran_countries_connected"])

    print(f"\n{C.BOLD}{'─' * 60}{C.RESET}")
    print(f"  {tag}  {C.BOLD}{C.CYAN}{ip}:{port}{C.RESET}")
    print(f"  {C.BOLD}Iran:{C.RESET} {iran_status}    {C.BOLD}Other countries connected:{C.RESET} {non_iran_count}")

    # Show country breakdown
    for code, info in sorted(analysis["all_countries"].items()):
        conn_ratio = f"{info['connected']}/{info['total']}"
        if code == IRAN_CODE:
            color = C.GREEN if info["connected"] > 0 else C.RED
            label = f"  🇮🇷 "
        else:
            color = C.GREEN if info["connected"] > 0 else C.GRAY
            label = f"     "
        status = f"{color}{conn_ratio}{C.RESET}"
        print(f"  {label}{info['name']:20s}  ({code})  {status}")


def print_summary(matches: list[str], port: int):
    """Print the final summary of matching IPs."""
    print(f"\n{C.BOLD}{'═' * 60}{C.RESET}")
    if matches:
        print(f"\n  {C.GREEN}{C.BOLD}★ {len(matches)} IP(s) matched the filter:{C.RESET}")
        print(f"  {C.GRAY}(Iran connected + fewer than {NON_IRAN_COUNTRY_THRESHOLD} other countries connected){C.RESET}\n")
        for ip in matches:
            print(f"    {C.GREEN}{C.BOLD}→ {ip}:{port}{C.RESET}")
    else:
        print(f"\n  {C.YELLOW}No IPs matched the filter criteria.{C.RESET}")
    print(f"\n{C.BOLD}{'═' * 60}{C.RESET}\n")


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    banner()

    # ── Input ────────────────────────────────────────────────────────────
    if len(sys.argv) >= 3:
        raw_ips = sys.argv[1]
        port = int(sys.argv[2])
    else:
        print(f"  {C.BOLD}Enter IPs{C.RESET} (comma-separated, CIDR ranges OK)")
        print(f"  {C.GRAY}Example: 1.2.3.4,5.6.7.8,10.0.0.0/30{C.RESET}")
        raw_ips = input(f"  {C.CYAN}>{C.RESET} ").strip()

        print(f"\n  {C.BOLD}Enter TCP port:{C.RESET}")
        port_str = input(f"  {C.CYAN}>{C.RESET} ").strip()
        try:
            port = int(port_str)
        except ValueError:
            print(f"{C.RED}  ✗ Invalid port number.{C.RESET}")
            sys.exit(1)

    ips = parse_ips(raw_ips)
    if not ips:
        print(f"{C.RED}  ✗ No valid IPs provided.{C.RESET}")
        sys.exit(1)

    print(f"\n  {C.BOLD}Checking {len(ips)} IP(s) on port {port}...{C.RESET}\n")

    # ── Process ──────────────────────────────────────────────────────────
    matches = []

    for idx, ip in enumerate(ips, 1):
        print(f"  {C.CYAN}[{idx}/{len(ips)}]{C.RESET} Checking {C.BOLD}{ip}:{port}{C.RESET} ...", end=" ", flush=True)

        request_id, nodes_map = start_tcp_check(ip, port)
        if not request_id:
            print(f"{C.RED}Failed to start check.{C.RESET}")
            if idx < len(ips):
                time.sleep(REQUEST_DELAY)
            continue

        # Check if there are any Iran nodes in this check
        iran_node_count = sum(1 for info in nodes_map.values()
                              if isinstance(info, list) and len(info) > 0 and info[0] == IRAN_CODE)

        print(f"{C.GREEN}started{C.RESET} ({len(nodes_map)} nodes, {iran_node_count} Iran)", flush=True)
        print(f"         {C.GRAY}Waiting for results...{C.RESET}", flush=True)

        results = poll_results(request_id)
        analysis = analyze_results(nodes_map, results)

        non_iran_count = len(analysis["non_iran_countries_connected"])
        is_match = analysis["iran_connected"] and non_iran_count < NON_IRAN_COUNTRY_THRESHOLD

        print_ip_result(ip, port, analysis, is_match)

        if is_match:
            matches.append(ip)

        # Rate limit between requests
        if idx < len(ips):
            time.sleep(REQUEST_DELAY)

    # ── Summary ──────────────────────────────────────────────────────────
    print_summary(matches, port)


if __name__ == "__main__":
    main()
