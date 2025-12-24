"""Variable substitution engine"""

import re
from urllib.parse import urlparse, urlunparse
from typing import Dict


class VariableEngine:
    """Handle Nuclei variable substitution ({{BaseURL}}, etc.)"""
    
    VARIABLE_PATTERN = re.compile(r'\{\{([^}]+)\}\}')
    
    def generate_base_variables(self, target_url: str) -> Dict[str, str]:
        """
        Generate standard variables from target URL
        
        Input: https://example.com:8080/api/v1
        Output:
            {{BaseURL}}    → https://example.com:8080/api/v1
            {{RootURL}}    → https://example.com:8080
            {{Hostname}}   → example.com
            {{Host}}       → example.com:8080
            {{Port}}       → 8080
            {{Path}}       → /api/v1
            {{Schema}}     → https
            {{Scheme}}     → https
        """
        parsed = urlparse(target_url)
        
        # Determine port
        if parsed.port:
            port = str(parsed.port)
        elif parsed.scheme == "https":
            port = "443"
        else:
            port = "80"
        
        # Host with port vs hostname
        hostname = parsed.hostname or ""
        if parsed.port:
            host = f"{hostname}:{parsed.port}"
        else:
            host = hostname
        
        # Root URL (without path)
        root_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            "",
            "",
            "",
            ""
        ))
        
        # Base URL (full URL as provided)
        base_url = target_url.rstrip("/")
        
        # Path
        path = parsed.path or "/"
        
        return {
            "BaseURL": base_url,
            "RootURL": root_url,
            "Hostname": hostname,
            "Host": host,
            "Port": port,
            "Path": path,
            "Schema": parsed.scheme,
            "Scheme": parsed.scheme,
            # Additional useful variables
            "FullURL": target_url,
        }
    
    def substitute(self, template_str: str, variables: Dict[str, str]) -> str:
        """Replace {{variable}} placeholders with values"""
        
        def replacer(match):
            var_name = match.group(1)
            # Try exact match first
            if var_name in variables:
                return str(variables[var_name])
            # Try case-insensitive match
            var_lower = var_name.lower()
            for key, value in variables.items():
                if key.lower() == var_lower:
                    return str(value)
            # Return original if not found
            return match.group(0)
        
        return self.VARIABLE_PATTERN.sub(replacer, template_str)
    
    def substitute_in_dict(self, data: Dict[str, str], 
                           variables: Dict[str, str]) -> Dict[str, str]:
        """Substitute variables in all values of a dict"""
        return {
            key: self.substitute(value, variables)
            for key, value in data.items()
        }
    
    def parse_raw_request(self, raw: str, variables: Dict[str, str]) -> dict:
        """
        Parse raw HTTP request format to dict
        
        Input:
            GET /api/v1 HTTP/1.1
            Host: {{Hostname}}
            X-Custom: value
            
            {"body": "data"}
            
        Output:
            {
                'method': 'GET',
                'url': 'https://example.com/api/v1',
                'headers': {'Host': 'example.com', 'X-Custom': 'value'},
                'body': '{"body": "data"}'
            }
        """
        # Substitute variables first
        raw = self.substitute(raw, variables)
        
        lines = raw.strip().split('\n')
        if not lines:
            return {}
        
        # Parse request line
        request_line = lines[0].strip()
        parts = request_line.split()
        
        if len(parts) < 2:
            return {}
        
        method = parts[0].upper()
        path = parts[1]
        
        # Parse headers and body
        headers = {}
        body = ""
        body_started = False
        
        for line in lines[1:]:
            if body_started:
                body += line + "\n"
            elif line.strip() == "":
                body_started = True
            else:
                # Parse header
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
        
        # Build full URL
        scheme = variables.get("Scheme", "https")
        host = headers.get("Host", variables.get("Host", ""))
        
        if path.startswith("http"):
            url = path  # Already a full URL
        else:
            url = f"{scheme}://{host}{path}"
        
        return {
            'method': method,
            'url': url,
            'headers': headers,
            'body': body.strip(),
        }
