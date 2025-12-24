"""Main executor - orchestrates template execution"""

import time
import logging
from typing import List, Optional, Dict, Any, Callable, TextIO
from datetime import datetime

from .models import NucleiTemplate, ScanResult, FridaResponse, Severity
from .template_discovery import TemplateDiscovery
from .template_parser import TemplateParser
from .request_builder import RequestBuilder
from .frida_client import FridaNetworkClient
from .matchers import MatcherEngine
from .extractors import ExtractorEngine


class NucleiExecutor:
    """Main execution orchestrator"""
    
    def __init__(self, 
                 frida_client: FridaNetworkClient,
                 verbose: bool = False,
                 log_file: Optional[str] = None,
                 custom_headers: Optional[Dict[str, str]] = None):
        self.frida_client = frida_client
        self.verbose = verbose
        self.log_file = log_file
        self.custom_headers = custom_headers or {}
        self._log_handle: Optional[TextIO] = None
        
        self.template_parser = TemplateParser()
        self.request_builder = RequestBuilder()
        self.matcher_engine = MatcherEngine()
        self.extractor_engine = ExtractorEngine()
        
        # Callbacks for progress reporting
        self.on_template_start: Optional[Callable[[str], None]] = None
        self.on_template_complete: Optional[Callable[[ScanResult], None]] = None
        
        # Open log file if specified
        if self.log_file:
            self._log_handle = open(self.log_file, 'w')
            self._log(f"=== Intrascan Log - {datetime.now().isoformat()} ===\n")
    
    def _log(self, message: str, also_print: bool = False):
        """Write to log file and optionally print"""
        if self._log_handle:
            self._log_handle.write(message + '\n')
            self._log_handle.flush()
        if also_print or self.verbose:
            print(message)
    
    def preflight_check(self, target_url: str) -> bool:
        """
        Perform a connectivity check before running templates
        
        Sends a simple GET request to verify:
        1. Frida connection is working
        2. Target is reachable
        3. Network requests are going through
        
        Returns True if check passes, False otherwise
        """
        self._log(f"Preflight check: {target_url}", also_print=True)
        
        # Build a simple GET request
        request = {
            'method': 'GET',
            'url': target_url,
            'headers': {'User-Agent': 'Test/0.1'},
            'body': ''
        }
        
        try:
            response = self.frida_client.send_request(request, timeout=10)
            
            if response.error:
                self._log(f"[!] Preflight failed: {response.error}", also_print=True)
                return False
                
            self._log(f"[+] Preflight OK: HTTP {response.status_code} ({response.duration:.2f}s)", also_print=True)
            return True
            
        except Exception as e:
            self._log(f"[!] Preflight failed: {e}", also_print=True)
            return False
        
    def execute(self, 
                template_path: str,
                target_url: str,
                severities: Optional[List[str]] = None,
                tags: Optional[List[str]] = None,
                exclude_tags: Optional[List[str]] = None,
                limit: Optional[int] = None) -> List[ScanResult]:
        """
        Execute templates against target
        
        Args:
            template_path: Path to template file or directory
            target_url: Target URL to scan
            severities: Filter by severity levels
            tags: Include only templates with these tags
            exclude_tags: Exclude templates with these tags
            limit: Maximum number of templates to process
            
        Returns:
            List of ScanResult for all executed templates
        """
        # Discover templates
        discovery = TemplateDiscovery(template_path)
        template_paths = discovery.discover()
        
        # Apply filters
        if severities:
            template_paths = discovery.filter_by_severity(template_paths, severities)
            
        if tags or exclude_tags:
            template_paths = discovery.filter_by_tags(
                template_paths, 
                include_tags=tags,
                exclude_tags=exclude_tags
            )
        
        # Apply limit
        if limit and limit > 0:
            template_paths = template_paths[:limit]
            
        # Parse templates
        templates = self.template_parser.parse_multiple(template_paths)
        
        self._log(f"Scanning {len(templates)} templates against {target_url}", also_print=True)
        
        # Execute each template
        results = []
        for template in templates:
            result = self.execute_template(template, target_url)
            results.append(result)
            
            if self.on_template_complete:
                self.on_template_complete(result)
                
        return results
        
    def execute_template(self, 
                         template: NucleiTemplate,
                         target_url: str) -> ScanResult:
        """Execute a single template against target"""
        
        if self.on_template_start:
            self.on_template_start(template.id)
            
        # Build result (default: not matched)
        result = ScanResult(
            template_id=template.id,
            template_name=template.info.name,
            severity=template.info.severity,
            matched=False,
            target_url=target_url,
            matched_at=target_url,
        )
        
        try:
            # Process each HTTP request in template
            for http_req in template.http_requests:
                # Build executable requests
                requests = self.request_builder.build_requests(
                    template, target_url, custom_headers=self.custom_headers
                )
                
                for req in requests:
                    # Store request for potential saving
                    request_str = self._format_request(req)
                    
                    # Log request to file
                    self._log(f"\n--- REQUEST [{template.id}] ---")
                    self._log(f"URL: {req.get('url')}")
                    self._log(f"Method: {req.get('method')}")
                    self._log(request_str)
                    
                    # Send via Frida
                    response = self.frida_client.send_request(req)
                    
                    # Log response to file
                    self._log(f"\n--- RESPONSE [{template.id}] ---")
                    self._log(f"Status: {response.status_code}")
                    self._log(f"Duration: {response.duration:.2f}s")
                    if response.error:
                        self._log(f"Error: {response.error}")
                    self._log(f"Body length: {len(response.body)} bytes")
                    # Log headers
                    for hdr_name, hdr_val in response.headers.items():
                        self._log(f"{hdr_name}: {hdr_val}")
                    # Log body (truncate if very large)
                    body_to_log = response.body[:5000] if len(response.body) > 5000 else response.body
                    self._log(f"\n{body_to_log}")
                    if len(response.body) > 5000:
                        self._log(f"... [truncated {len(response.body) - 5000} more bytes]")
                    
                    if response.error:
                        self._log(f"[!] Error for {template.id}: {response.error}")
                        continue
                        
                    # Store response for potential saving
                    response_str = self._format_response(response)
                    
                    # Run extractors first (they can feed into matchers)
                    extracted_vars = self.extractor_engine.extract_internal(
                        response, http_req.extractors
                    )
                    
                    # Run all extractors for output
                    extracted = self.extractor_engine.extract(
                        response, http_req.extractors
                    )
                    
                    # Run matchers
                    matched, snippets = self.matcher_engine.match(
                        response,
                        http_req.matchers,
                        http_req.matchers_condition,
                        extracted_vars
                    )
                    
                    if matched:
                        # Collect all extracted values for output
                        all_extracted = []
                        for values in extracted.values():
                            all_extracted.extend(values)
                            
                        result.matched = True
                        result.matched_at = req.get('url', target_url)
                        result.extracted = all_extracted
                        result.request = request_str
                        result.response = response_str
                        result.response_time = response.duration
                        
                        # Stop at first match if configured
                        if http_req.stop_at_first_match:
                            return result
                            
        except Exception as e:
            if self.verbose:
                print(f"[!] Exception executing {template.id}: {e}")
                
        return result
        
    def _format_request(self, req: dict) -> str:
        """Format request dict as HTTP request string"""
        lines = [f"{req.get('method', 'GET')} {req.get('url', '/')} HTTP/1.1"]
        
        for key, value in req.get('headers', {}).items():
            lines.append(f"{key}: {value}")
            
        body = req.get('body', '')
        if body:
            lines.append('')
            lines.append(body)
            
        return '\n'.join(lines)
        
    def _format_response(self, response: FridaResponse) -> str:
        """Format response as HTTP response string"""
        lines = [f"HTTP/1.1 {response.status_code} OK"]
        
        for key, value in response.headers.items():
            lines.append(f"{key}: {value}")
            
        lines.append('')
        lines.append(response.body)
        
        return '\n'.join(lines)
