#!/usr/bin/env python3

import sys
import argparse
import requests
from rich.console import Console
from rich.table import Table
import validators
from urllib.parse import urlparse
import ssl
from datetime import datetime
import csv
import time

# Constants
MAX_URLS = 20
HEADERS_TO_CHECK = [
    'content-security-policy',
    'x-frame-options',
    'strict-transport-security',
    'referrer-policy'
]
MAX_HEADER_LENGTH = 80
DEFAULT_TIMEOUT = 10
RATE_LIMIT_DELAY = 2  # Delay between requests in seconds
USER_AGENT = "HeaderHawk/1.0 (Security Header Analyzer; https://github.com/your-repo/headerhawk)"

# Request headers
REQUEST_HEADERS = {
    'User-Agent': USER_AGENT,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'DNT': '1',  # Do Not Track
}

HEADER_HAWK_ASCII = r"""
[cyan]|\     /|(  ____ \(  ___  )(  __  \ (  ____ \(  ____ )|\     /|(  ___  )|\     /|| \    /\
| )   ( || (    \/| (   ) || (  \  )| (    \/| (    )|| )   ( || (   ) || )   ( ||  \  / /
| (___) || (__    | (___) || |   ) || (__    | (____)|| (___) || (___) || | _ | ||  (_/ / 
|  ___  ||  __)   |  ___  || |   | ||  __)   |     __)|  ___  ||  ___  || |( )| ||   _ (  
| (   ) || (      | (   ) || |   ) || (      | (\ (   | (   ) || (   ) || || || ||  ( \ \ 
| )   ( || (____/\| )   ( || (__/  )| (____/\| ) \ \__| )   ( || )   ( || () () ||  /  \ \
|/     \|(_______/|/     \|(______/ (_______/|/   \__/|/     \||/     \|(_______)|_/    \/[/cyan]
"""

console = Console()

def validate_and_format_url(url: str) -> str:
    """Validate URL and add https:// if protocol is missing."""
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    if not validators.url(url):
        raise ValueError(f"Invalid URL format: {url}")
    
    return url

def get_headers(url: str) -> dict:
    """Fetch HTTP headers from a URL with error handling."""
    try:
        response = requests.get(
            url,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=True,
            verify=True,
            headers=REQUEST_HEADERS
        )
        return {k.lower(): v for k, v in response.headers.items()}
    except requests.exceptions.SSLError:
        console.print(f"[yellow]Warning: SSL verification failed for {url}[/yellow]")
        try:
            response = requests.get(
                url,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True,
                verify=False,
                headers=REQUEST_HEADERS
            )
            return {k.lower(): v for k, v in response.headers.items()}
        except Exception as e:
            return {header: f"Error: {str(e)}" for header in HEADERS_TO_CHECK}
    except Exception as e:
        return {header: f"Error: {str(e)}" for header in HEADERS_TO_CHECK}

def truncate_value(value: str) -> str:
    """Truncate long header values."""
    if len(value) > MAX_HEADER_LENGTH:
        return value[:MAX_HEADER_LENGTH] + "..."
    return value

def process_urls(urls: list) -> list:
    """Process URLs and return results as a list of dictionaries."""
    results = []
    total_urls = len(urls)
    
    for index, url in enumerate(urls, 1):
        try:
            url = validate_and_format_url(url)
            console.print(f"[cyan]Processing {url} ({index}/{total_urls})[/cyan]")
            
            headers = get_headers(url)
            
            result = {'URL': url}
            for header in HEADERS_TO_CHECK:
                value = headers.get(header, "Missing")
                if isinstance(value, str):
                    result[header] = truncate_value(value)
                else:
                    result[header] = "Missing"
            
            results.append(result)
            
            # Apply rate limiting if not the last URL
            if index < total_urls:
                console.print(f"[yellow]Rate limiting: waiting {RATE_LIMIT_DELAY} seconds...[/yellow]")
                time.sleep(RATE_LIMIT_DELAY)
            
        except Exception as e:
            console.print(f"[red]Error processing {url}: {str(e)}[/red]")
    
    return results

def display_results(results: list):
    """Display results in a rich table."""
    table = Table(show_header=True, header_style="bold magenta")
    
    # Add columns
    table.add_column("URL", style="cyan")
    for header in HEADERS_TO_CHECK:
        table.add_column(header.upper(), style="green")
    
    # Add rows
    for result in results:
        values = [result['URL']] + [str(result[header]) for header in HEADERS_TO_CHECK]
        table.add_row(*values)
    
    console.print(table)

def save_to_csv(results: list, filename: str):
    """Save results to a CSV file."""
    fieldnames = ['URL'] + HEADERS_TO_CHECK
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

def main():
    # Display ASCII art and version
    console.print(HEADER_HAWK_ASCII)
    console.print("[yellow]Security Header Analysis Tool[/yellow]")
    console.print(f"[yellow]Version: 1.0[/yellow]")
    console.print(f"[yellow]User-Agent: {USER_AGENT}[/yellow]")
    console.print()

    parser = argparse.ArgumentParser(description="HeaderHawk - HTTP Security Headers Analyzer")
    parser.add_argument('urls', nargs='*', help='URLs to analyze')
    parser.add_argument('--save', action='store_true', help='Save results to CSV')
    args = parser.parse_args()

    urls = args.urls

    if not urls:
        console.print("[yellow]No URLs provided. Enter URLs (one per line, max 20).[/yellow]")
        console.print("[yellow]Press Enter twice when done:[/yellow]")
        
        urls = []
        while True:
            url = input().strip()
            if not url:
                break
            urls.append(url)

    if not urls:
        console.print("[red]No URLs provided. Exiting.[/red]")
        sys.exit(1)

    if len(urls) > MAX_URLS:
        console.print(f"[red]Error: Maximum {MAX_URLS} URLs allowed. You provided {len(urls)}.[/red]")
        sys.exit(1)

    console.print("[cyan]Analyzing security headers...[/cyan]")
    console.print(f"[cyan]Rate limiting: {RATE_LIMIT_DELAY} seconds between requests[/cyan]")
    console.print()
    
    results = process_urls(urls)
    display_results(results)

    if args.save:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"headerhawk_results_{timestamp}.csv"
        save_to_csv(results, filename)
        console.print(f"[green]Results saved to {filename}[/green]")

if __name__ == "__main__":
    main() 