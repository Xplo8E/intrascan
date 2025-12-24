"""CLI interface for intrascan tool"""

import sys
import time
import click
from typing import Optional, Tuple

from .executor import NucleiExecutor
from .frida_client import FridaNetworkClient, RateLimitConfig
from .output import OutputFormatter


EXAMPLES = """
EXAMPLES:

  Scan with single template:

      $ intrascan -t template.yaml -u https://target.com -a com.app.bundle

  Scan with severity filter:

      $ intrascan -t templates/ -u https://target.com -a com.app.bundle -s high

  Scan with JSON output:

      $ intrascan -t templates/ -u https://target.com -a com.app.bundle -o out.json

  Scan with rate limiting:

      $ intrascan -t templates/ -u https://target.com -a com.app.bundle --rate-limit 5

Documentation: https://github.com/Xplo8E/intrascan

"""


@click.command(epilog=EXAMPLES, context_settings={'max_content_width': 120})
@click.option('-t', '--template', required=True, 
              help='Template file or directory path')
@click.option('-u', '--url', required=True, 
              help='Target URL to scan')
@click.option('-a', '--app', required=True, 
              help='iOS app bundle ID (e.g., com.app.bundle)')
@click.option('--script', default=None, 
              help='Custom Frida network script path')
@click.option('-o', '--output', default=None,
              help='JSON output file path')
@click.option('--store-responses', default=None,
              help='Directory to store request/response pairs for findings')
@click.option('-s', '--severity', default=None,
              help='Filter by severity (comma-separated: critical,high,medium,low,info)')
@click.option('--tags', default=None,
              help='Filter by tags (comma-separated)')
@click.option('--exclude-tags', default=None,
              help='Exclude templates with these tags (comma-separated)')
@click.option('--rate-limit', default=10, type=float,
              help='Requests per second (default: 10)')
@click.option('--timeout', default=30, type=float,
              help='Request timeout in seconds (default: 30)')
@click.option('--limit', default=0, type=int,
              help='Limit number of templates to process (0 = no limit)')
@click.option('-v', '--verbose', is_flag=True,
              help='Verbose output')
@click.option('--no-color', is_flag=True,
              help='Disable colored output')
@click.option('--silent', is_flag=True,
              help='Show only findings, no banner or progress')
@click.option('--skip-preflight', is_flag=True,
              help='Skip connectivity preflight check')
@click.option('--log-file', default=None, type=str,
              help='Save detailed log to file (optional)')
@click.option('-H', '--header', multiple=True,
              help='Custom header in header:value format (can be used multiple times)')
def main(template: str, 
         url: str, 
         app: str, 
         script: Optional[str],
         output: Optional[str],
         store_responses: Optional[str],
         severity: Optional[str],
         tags: Optional[str],
         exclude_tags: Optional[str],
         rate_limit: float,
         timeout: float,
         limit: int,
         verbose: bool,
         no_color: bool,
         silent: bool,
         skip_preflight: bool,
         log_file: Optional[str],
         header: Tuple[str, ...]):
    """Intrascan - iOS/Android security scanner using Nuclei templates."""
    formatter = OutputFormatter(verbose=verbose, no_color=no_color)
    
    if not silent:
        formatter.print_banner()
        
    # Parse severity filters
    valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
    severity_list = None
    if severity:
        severity_list = [s.strip().lower() for s in severity.split(',')]
        invalid = [s for s in severity_list if s not in valid_severities]
        if invalid:
            formatter.print_error(f"Invalid severity: {', '.join(invalid)}. Valid: critical,high,medium,low,info")
            sys.exit(1)
    
    # Parse tag filters
    include_tags = [t.strip() for t in tags.split(',')] if tags else None
    exclude_tags_list = [t.strip() for t in exclude_tags.split(',')] if exclude_tags else None
    
    # Parse custom headers
    custom_headers = {}
    for h in header:
        if ':' in h:
            key, value = h.split(':', 1)
            custom_headers[key.strip()] = value.strip()
        else:
            formatter.print_error(f"Invalid header format: {h} (expected header:value)")
            sys.exit(1)
    
    # Configure rate limiting
    rate_config = RateLimitConfig(
        requests_per_second=rate_limit,
        timeout=timeout
    )
    
    # Create Frida client
    client = FridaNetworkClient(
        app_bundle=app,
        script_path=script,
        rate_limit=rate_config
    )
    
    if not silent:
        formatter.print_info(f"Connecting to {app}...")
        
    try:
        client.connect()
    except ConnectionError as e:
        formatter.print_error(str(e))
        sys.exit(1)
        
    if not silent:
        formatter.print_success("Connected")
        formatter.print_info(f"Loading templates from: {template}")
        
    results = []  # Initialize results before try
    
    try:
        # Create executor (log_file is optional)
        executor = NucleiExecutor(client, verbose=verbose, log_file=log_file, custom_headers=custom_headers)
        
        if not silent and log_file:
            formatter.print_info(f"Logging to: {log_file}")
        
        # Preflight check
        if not skip_preflight:
            if not executor.preflight_check(url):
                formatter.print_error("Preflight check failed. Use --skip-preflight to bypass.")
                sys.exit(1)
        
        # Set up callbacks for progress
        def on_result(result):
            if result.matched:
                print(formatter.format_result(result))
                
        executor.on_template_complete = on_result
        
        # Start timing
        start_time = time.time()
        
        # Execute
        results = executor.execute(
            template_path=template,
            target_url=url,
            severities=severity_list,
            tags=include_tags,
            exclude_tags=exclude_tags_list,
            limit=limit if limit > 0 else None,
        )
        
        duration = time.time() - start_time
        
        # Summary
        if not silent:
            formatter.print_summary(results, duration)
            
        # Save outputs
        if output:
            formatter.save_json(results, output)
            formatter.print_info(f"Results saved to: {output}")
            
        if store_responses:
            count = formatter.save_requests_responses(results, store_responses)
            if count > 0:
                formatter.print_info(f"Saved {count} request/response pairs to: {store_responses}/")
                
    except KeyboardInterrupt:
        formatter.print_info("Interrupted by user")
        # Show partial results if any
        if results:
            matched = [r for r in results if r.matched]
            if matched:
                formatter.print_info(f"Partial results: {len(matched)} findings")
    except Exception as e:
        formatter.print_error(f"Error: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        client.disconnect()
        
    # Exit code based on findings
    sys.exit(0)


def cli():
    """Entry point for console script"""
    main()


if __name__ == '__main__':
    cli()
