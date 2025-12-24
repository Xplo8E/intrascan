"""Request builder - build HTTP requests from templates"""

from typing import List, Dict, Optional
from urllib.parse import urljoin

from .models import HttpRequest, NucleiTemplate
from .variables import VariableEngine


class RequestBuilder:
    """Build executable HTTP requests from template definitions"""
    
    def __init__(self):
        self.variable_engine = VariableEngine()
    
    def build_requests(self, 
                       template: NucleiTemplate,
                       target_url: str) -> List[dict]:
        """
        Build all requests from a template for the given target
        
        Returns list of request dicts ready for Frida:
        [
            {
                'method': 'GET',
                'url': 'https://target.com/api',
                'headers': {...},
                'body': ''
            },
            ...
        ]
        """
        # Generate base variables from target URL
        variables = self.variable_engine.generate_base_variables(target_url)
        
        # Add template variables
        variables.update(template.variables)
        
        requests = []
        
        for http_req in template.http_requests:
            reqs = self._build_http_request(http_req, variables, target_url)
            requests.extend(reqs)
            
        return requests
    
    def _build_http_request(self, 
                            http_req: HttpRequest,
                            variables: Dict[str, str],
                            target_url: str) -> List[dict]:
        """Build request(s) from a single HTTP request definition"""
        
        # If raw requests are defined, use those
        if http_req.raw:
            return self._build_from_raw(http_req.raw, variables)
        
        # Otherwise, use path-based requests
        if http_req.path:
            return self._build_from_path(http_req, variables, target_url)
        
        return []
    
    def _build_from_raw(self, 
                        raw_requests: List[str],
                        variables: Dict[str, str]) -> List[dict]:
        """Build requests from raw HTTP format"""
        requests = []
        
        for raw in raw_requests:
            req = self.variable_engine.parse_raw_request(raw, variables)
            if req and req.get('url'):
                requests.append(req)
                
        return requests
    
    def _build_from_path(self,
                         http_req: HttpRequest,
                         variables: Dict[str, str],
                         target_url: str) -> List[dict]:
        """Build requests from path definitions"""
        requests = []
        
        for path in http_req.path:
            # Substitute variables in path
            path = self.variable_engine.substitute(path, variables)
            
            # Build full URL
            if path.startswith("http"):
                url = path
            else:
                # Handle path joining
                base = variables.get("BaseURL", target_url)
                if path.startswith("/"):
                    # Absolute path - use root URL
                    url = urljoin(variables.get("RootURL", base), path)
                else:
                    # Relative path
                    url = urljoin(base + "/", path)
            
            # Build headers
            headers = self.variable_engine.substitute_in_dict(
                http_req.headers, variables
            )
            
            # Ensure Host header exists
            if "Host" not in headers and "host" not in headers:
                headers["Host"] = variables.get("Host", "")
            
            # Build body
            body = self.variable_engine.substitute(http_req.body, variables)
            
            req = {
                'method': http_req.method.upper(),
                'url': url,
                'headers': headers,
                'body': body,
            }
            
            requests.append(req)
            
        return requests
    
    def build_single_request(self,
                             http_req: HttpRequest,
                             target_url: str,
                             custom_vars: Optional[Dict] = None) -> Optional[dict]:
        """Build a single request for testing"""
        variables = self.variable_engine.generate_base_variables(target_url)
        if custom_vars:
            variables.update(custom_vars)
            
        requests = self._build_http_request(http_req, variables, target_url)
        return requests[0] if requests else None
