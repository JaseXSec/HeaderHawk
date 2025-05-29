# HeaderHawk

A Python CLI tool for analyzing HTTP security headers across multiple URLs.

## Security Disclaimer

HeaderHawk is designed for security professionals, developers, and system administrators to assess HTTP security headers on websites they own or have explicit permission to test. Please use this tool responsibly:

- Only scan websites you own or have explicit permission to test
- Respect rate limits and robots.txt
- Be mindful of the load your scanning may place on target servers
- This tool is for educational and legitimate security assessment purposes only
- Users are responsible for ensuring their use complies with applicable laws and regulations

## Features

- Check security headers for up to 20 URLs simultaneously
- Accept URLs via command line or interactive input
- Display results in a formatted table
- Export results to CSV
- Validate URLs and handle redirects
- Check key security headers like CSP, X-Frame-Options, etc.
- Rate limiting between requests to prevent server overload
- Proper User-Agent identification
- SSL/TLS verification with graceful fallback

## Installation

1. Clone this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Command line mode:
```bash
python headerhawk.py https://example1.com https://example2.com --save
```

Interactive mode:
```bash
python headerhawk.py
```

## Options

- `--save`: Export results to CSV (headerhawk_results.csv)

## Security Headers Checked

- Content-Security-Policy
- X-Frame-Options
- Strict-Transport-Security
- Referrer-Policy
