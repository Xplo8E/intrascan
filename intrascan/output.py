"""Output formatting - console output and JSON export"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from dataclasses import asdict

from .models import ScanResult, Severity


class Colors:
    """ANSI color codes"""
    CRITICAL = '\033[91m'  # Bright Red
    HIGH = '\033[93m'      # Yellow  
    MEDIUM = '\033[94m'    # Blue
    LOW = '\033[92m'       # Green
    INFO = '\033[96m'      # Cyan
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


class OutputFormatter:
    """Format scan results for output"""
    
    def __init__(self, verbose: bool = False, no_color: bool = False):
        self.verbose = verbose
        self.no_color = no_color
        
    def format_result(self, result: ScanResult) -> str:
        """
        Format single result in Nuclei style:
        
        [critical] [CVE-2024-0012] [http] https://target.com/path
        """
        severity_str = self._format_severity(result.severity)
        
        # Build line
        parts = [
            severity_str,
            f"[{result.template_id}]",
            "[http]",
            result.matched_at,
        ]
        
        # Add extracted values if any
        if result.extracted:
            extracted_str = ', '.join(result.extracted[:3])  # Limit to 3
            if len(result.extracted) > 3:
                extracted_str += f" (+{len(result.extracted) - 3} more)"
            parts.append(f"[{extracted_str}]")
            
        return ' '.join(parts)
        
    def _format_severity(self, severity: Severity) -> str:
        """Format severity with color"""
        if self.no_color:
            return f"[{severity.value}]"
            
        color = {
            Severity.CRITICAL: Colors.CRITICAL,
            Severity.HIGH: Colors.HIGH,
            Severity.MEDIUM: Colors.MEDIUM,
            Severity.LOW: Colors.LOW,
            Severity.INFO: Colors.INFO,
        }.get(severity, '')
        
        return f"[{color}{severity.value}{Colors.RESET}]"
        
    def print_banner(self):
        """Print startup banner"""
        banner = f"""
{Colors.BOLD}  _       _                                  
 (_)_ __ | |_ _ __ __ _ ___  ___ __ _ _ __  
 | | '_ \\| __| '__/ _` / __|/ __/ _` | '_ \\ 
 | | | | | |_| | | (_| \\__ \\ (_| (_| | | | |
 |_|_| |_|\\__|_|  \\__,_|___/\\___\\__,_|_| |_|
{Colors.RESET}{Colors.DIM}Mobile app security scanner powered by Nuclei + Frida{Colors.RESET}
"""
        if self.no_color:
            banner = banner.replace(Colors.BOLD, '').replace(Colors.RESET, '').replace(Colors.DIM, '')
        print(banner)
        
    def print_info(self, message: str):
        """Print info message"""
        print(f"[*] {message}")
        
    def print_success(self, message: str):
        """Print success message"""
        if self.no_color:
            print(f"[+] {message}")
        else:
            print(f"{Colors.LOW}[+]{Colors.RESET} {message}")
            
    def print_error(self, message: str):
        """Print error message"""
        if self.no_color:
            print(f"[!] {message}")
        else:
            print(f"{Colors.CRITICAL}[!]{Colors.RESET} {message}")
            
    def print_summary(self, results: List[ScanResult], duration: float):
        """Print scan summary"""
        total = len(results)
        matched = [r for r in results if r.matched]
        
        by_severity = {}
        for r in matched:
            sev = r.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
        print(f"\n{'='*60}")
        print(f"Scan completed in {duration:.2f}s")
        print(f"Templates tested: {total}")
        print(f"Findings: {len(matched)}")
        
        if by_severity:
            sev_parts = []
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                if sev in by_severity:
                    sev_parts.append(f"{sev}: {by_severity[sev]}")
            print(f"By severity: {', '.join(sev_parts)}")
        print(f"{'='*60}")
        
    def save_json(self, results: List[ScanResult], output_path: str):
        """Save results to JSON file"""
        # Filter to matched only
        matched = [r for r in results if r.matched]
        
        data = {
            'scan_time': datetime.now().isoformat(),
            'total_tested': len(results),
            'total_findings': len(matched),
            'results': []
        }
        
        for r in matched:
            result_dict = {
                'template_id': r.template_id,
                'template_name': r.template_name,
                'severity': r.severity.value,
                'target_url': r.target_url,
                'matched_at': r.matched_at,
                'extracted': r.extracted,
            }
            if r.matcher_name:
                result_dict['matcher_name'] = r.matcher_name
            data['results'].append(result_dict)
            
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
            
    def save_requests_responses(self, results: List[ScanResult], output_dir: str):
        """Save request/response pairs for findings"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        matched = [r for r in results if r.matched and r.request]
        
        for i, result in enumerate(matched):
            base_name = f"{result.template_id}_{i+1}"
            
            # Save request
            if result.request:
                with open(output_path / f"{base_name}_request.txt", 'w') as f:
                    f.write(result.request)
                    
            # Save response
            if result.response:
                with open(output_path / f"{base_name}_response.txt", 'w') as f:
                    f.write(result.response)
                    
        return len(matched)
