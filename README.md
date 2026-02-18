# Access Checker

TCP / ICMP connectivity scanner using the [check-host.net](https://check-host.net/about/api) API. Finds IPs that are **reachable from Iran** but **blocked or unreachable from most other countries** (fewer than 3 non-Iran countries connected).

## Features

- **Two check modes:** TCP (port check) or ICMP (ping)
- Accepts comma-separated IPs and CIDR ranges (e.g. `10.0.0.0/28`)
- Custom TCP port selection
- Uses up to 40 global check-host.net nodes
- Colored terminal output with per-country breakdown
- Cross-platform: Windows, Linux, macOS
- **Zero dependencies** — pure Python 3 stdlib

## Usage

```bash
# Interactive mode — prompts for IPs, method, and port
python access_checker.py

# CLI: TCP check on port 443
python access_checker.py "1.2.3.4,5.6.7.8,10.0.0.0/30" 443

# CLI: ICMP ping check
python access_checker.py "1.2.3.4,5.6.7.8" icmp
```

### Windows (PowerShell)
```powershell
# TCP
.\run_checker.bat "1.2.3.4,5.6.7.8" 443

# ICMP
.\run_checker.bat "1.2.3.4,5.6.7.8" icmp
```

### Linux / macOS
```bash
chmod +x run_checker.sh

# TCP
./run_checker.sh "1.2.3.4,5.6.7.8" 443

# ICMP
./run_checker.sh "1.2.3.4,5.6.7.8" icmp
```

## How It Works

1. Parses input IPs (expands CIDR ranges)
2. For each IP, sends a **TCP** or **ICMP** check request to the check-host.net API
3. Polls results until all nodes respond (up to 25s timeout)
4. Groups results by country and checks:
   - ✅ At least 1 Iran node connected
   - ✅ Fewer than 3 non-Iran countries connected
5. Prints a colored summary of matching IPs

## Requirements

- Python 3.10+
- Internet connection

## License

MIT
