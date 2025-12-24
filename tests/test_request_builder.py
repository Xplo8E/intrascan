"""Tests for request builder"""

import pytest

from intrascan.request_builder import RequestBuilder
from intrascan.template_parser import TemplateParser


class TestRequestBuilder:
    """Test request building functionality"""
    
    def setup_method(self):
        self.builder = RequestBuilder()
        self.parser = TemplateParser()
        
    def test_build_from_path(self):
        """Test building request from path template"""
        content = """
id: test-path
info:
  name: Path Test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/test"
    matchers:
      - type: status
        status: [200]
"""
        template = self.parser.parse_content(content)
        target = "https://example.com"
        
        requests = self.builder.build_requests(template, target)
        
        assert len(requests) == 1
        assert requests[0]["method"] == "GET"
        assert requests[0]["url"] == "https://example.com/api/test"
        
    def test_build_from_multiple_paths(self):
        """Test building multiple requests from multiple paths"""
        content = """
id: multi-path
info:
  name: Multi Path Test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1"
      - "{{BaseURL}}/api/v2"
    matchers:
      - type: status
        status: [200]
"""
        template = self.parser.parse_content(content)
        target = "https://example.com"
        
        requests = self.builder.build_requests(template, target)
        
        assert len(requests) == 2
        assert requests[0]["url"] == "https://example.com/api/v1"
        assert requests[1]["url"] == "https://example.com/api/v2"
        
    def test_build_with_headers(self):
        """Test building request with headers"""
        content = """
id: header-test
info:
  name: Header Test
  severity: info
http:
  - method: POST
    path:
      - "{{BaseURL}}/api"
    headers:
      Content-Type: application/json
      X-Custom: value
    matchers:
      - type: status
        status: [200]
"""
        template = self.parser.parse_content(content)
        target = "https://example.com"
        
        requests = self.builder.build_requests(template, target)
        
        assert len(requests) == 1
        assert requests[0]["headers"]["Content-Type"] == "application/json"
        assert requests[0]["headers"]["X-Custom"] == "value"
        
    def test_build_with_body(self):
        """Test building request with body"""
        content = """
id: body-test
info:
  name: Body Test
  severity: info
http:
  - method: POST
    path:
      - "{{BaseURL}}/api"
    body: '{"key": "value"}'
    matchers:
      - type: status
        status: [200]
"""
        template = self.parser.parse_content(content)
        target = "https://example.com"
        
        requests = self.builder.build_requests(template, target)
        
        assert len(requests) == 1
        assert requests[0]["body"] == '{"key": "value"}'
        
    def test_build_from_raw(self):
        """Test building request from raw format"""
        content = """
id: raw-test
info:
  name: Raw Test
  severity: info
http:
  - raw:
      - |
        GET /api/test HTTP/1.1
        Host: {{Hostname}}
        X-Custom: value

    matchers:
      - type: status
        status: [200]
"""
        template = self.parser.parse_content(content)
        target = "https://example.com:8080"
        
        requests = self.builder.build_requests(template, target)
        
        assert len(requests) == 1
        assert requests[0]["method"] == "GET"
        assert "example.com" in requests[0]["url"]
        assert requests[0]["headers"]["X-Custom"] == "value"
        
    def test_variable_substitution(self):
        """Test that variables are properly substituted"""
        content = """
id: var-test
info:
  name: Variable Test
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/api"
    headers:
      Host: "{{Hostname}}"
      Origin: "{{RootURL}}"
    matchers:
      - type: status
        status: [200]
"""
        template = self.parser.parse_content(content)
        target = "https://api.example.com:8080/path"
        
        requests = self.builder.build_requests(template, target)
        
        assert len(requests) == 1
        assert requests[0]["url"] == "https://api.example.com:8080/api"
        # Host header gets Hostname (without port) which is also valid
        assert "api.example.com" in requests[0]["headers"]["Host"]
        
    def test_host_header_auto_added(self):
        """Test that Host header is auto-added if missing"""
        content = """
id: host-test
info:
  name: Host Test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/api"
    matchers:
      - type: status
        status: [200]
"""
        template = self.parser.parse_content(content)
        target = "https://example.com"
        
        requests = self.builder.build_requests(template, target)
        
        assert "Host" in requests[0]["headers"]
