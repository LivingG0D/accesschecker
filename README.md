# Access Checker

TCP connectivity scanner using the [check-host.net](https://check-host.net/about/api) API. Finds IPs that are **reachable from Iran** but **blocked or unreachable from most other countries** (fewer than 3 non-Iran countries connected).

## Features

- Accepts comma-separated IPs and CIDR ranges (e.g. `10.0.0.0/28`)
- Custom TCP port selection
- Uses up to 40 global check-host.net nodes
- Colored terminal output with per-country breakdown
- Cross-platform: Windows, Linux, macOS
- **Zero dependencies** — pure Python 3 stdlib

## Usage

```bash
# Interactive mode — prompts for IPs and port
python access_checker.py

# CLI mode
python access_checker.py "1.2.3.4,5.6.7.8,10.0.0.0/30" 443
```

### Windows
```cmd
run_checker.bat "1.2.3.4,5.6.7.8" 80
```

### Linux / macOS
```bash
chmod +x run_checker.sh
./run_checker.sh "1.2.3.4,5.6.7.8" 80
```

## How It Works

1. Parses input IPs (expands CIDR ranges)
2. For each IP, sends a TCP check request to the check-host.net API
3. Polls results until all nodes respond (up to 20s timeout)
4. Groups results by country and checks:
   - ✅ At least 1 Iran node connected
   - ✅ Fewer than 3 non-Iran countries connected
5. Prints a colored summary of matching IPs

## Requirements

- Python 3.10+
- Internet connection

## License

MIT
