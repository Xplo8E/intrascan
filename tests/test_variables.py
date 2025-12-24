"""Tests for variable substitution engine"""

import pytest

from nuclei_frida.variables import VariableEngine


class TestVariableEngine:
    """Test variable substitution functionality"""
    
    def setup_method(self):
        self.engine = VariableEngine()
        
    def test_generate_base_variables_full_url(self):
        """Test variable generation from full URL with port and path"""
        url = "https://example.com:8080/api/v1"
        vars = self.engine.generate_base_variables(url)
        
        assert vars["BaseURL"] == "https://example.com:8080/api/v1"
        assert vars["RootURL"] == "https://example.com:8080"
        assert vars["Hostname"] == "example.com"
        assert vars["Host"] == "example.com:8080"
        assert vars["Port"] == "8080"
        assert vars["Path"] == "/api/v1"
        assert vars["Scheme"] == "https"
        assert vars["Schema"] == "https"
        
    def test_generate_base_variables_simple_url(self):
        """Test variable generation from simple URL"""
        url = "https://example.com"
        vars = self.engine.generate_base_variables(url)
        
        assert vars["BaseURL"] == "https://example.com"
        assert vars["Hostname"] == "example.com"
        assert vars["Host"] == "example.com"
        assert vars["Port"] == "443"  # Default HTTPS port
        assert vars["Scheme"] == "https"
        
    def test_generate_base_variables_http(self):
        """Test variable generation for HTTP URL (port 80)"""
        url = "http://example.com/path"
        vars = self.engine.generate_base_variables(url)
        
        assert vars["Port"] == "80"  # Default HTTP port
        assert vars["Scheme"] == "http"
        
    def test_substitute_single_variable(self):
        """Test substitution of single variable"""
        template = "GET {{BaseURL}}/api"
        vars = {"BaseURL": "https://example.com"}
        
        result = self.engine.substitute(template, vars)
        assert result == "GET https://example.com/api"
        
    def test_substitute_multiple_variables(self):
        """Test substitution of multiple variables"""
        template = "{{Scheme}}://{{Hostname}}:{{Port}}{{Path}}"
        vars = {
            "Scheme": "https",
            "Hostname": "example.com",
            "Port": "8080",
            "Path": "/api"
        }
        
        result = self.engine.substitute(template, vars)
        assert result == "https://example.com:8080/api"
        
    def test_substitute_missing_variable(self):
        """Test that missing variables are preserved"""
        template = "{{BaseURL}}/{{MissingVar}}"
        vars = {"BaseURL": "https://example.com"}
        
        result = self.engine.substitute(template, vars)
        assert result == "https://example.com/{{MissingVar}}"
        
    def test_substitute_case_insensitive(self):
        """Test case-insensitive variable matching"""
        template = "{{baseurl}}/api"
        vars = {"BaseURL": "https://example.com"}
        
        result = self.engine.substitute(template, vars)
        assert result == "https://example.com/api"
        
    def test_substitute_in_dict(self):
        """Test substitution in dictionary values"""
        headers = {
            "Host": "{{Hostname}}",
            "Origin": "{{RootURL}}",
            "X-Custom": "static-value"
        }
        vars = {
            "Hostname": "example.com",
            "RootURL": "https://example.com"
        }
        
        result = self.engine.substitute_in_dict(headers, vars)
        
        assert result["Host"] == "example.com"
        assert result["Origin"] == "https://example.com"
        assert result["X-Custom"] == "static-value"
        
    def test_parse_raw_request_simple(self):
        """Test parsing simple raw request"""
        raw = """GET /api/test HTTP/1.1
Host: example.com
X-Custom: value

"""
        vars = {
            "Scheme": "https",
            "Host": "example.com"
        }
        
        result = self.engine.parse_raw_request(raw, vars)
        
        assert result["method"] == "GET"
        assert result["url"] == "https://example.com/api/test"
        assert result["headers"]["Host"] == "example.com"
        assert result["headers"]["X-Custom"] == "value"
        
    def test_parse_raw_request_with_body(self):
        """Test parsing raw request with body"""
        raw = """POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username": "test", "password": "test123"}"""

        vars = {
            "Scheme": "https",
            "Host": "example.com"
        }
        
        result = self.engine.parse_raw_request(raw, vars)
        
        assert result["method"] == "POST"
        assert result["body"] == '{"username": "test", "password": "test123"}'
        
    def test_parse_raw_request_with_variables(self):
        """Test parsing raw request with variable substitution"""
        raw = """GET /api/{{Version}} HTTP/1.1
Host: {{Hostname}}
Authorization: Bearer {{Token}}

"""
        vars = {
            "Scheme": "https",
            "Host": "api.example.com",
            "Hostname": "api.example.com",
            "Version": "v2",
            "Token": "abc123"
        }
        
        result = self.engine.parse_raw_request(raw, vars)
        
        assert result["url"] == "https://api.example.com/api/v2"
        assert result["headers"]["Host"] == "api.example.com"
        assert result["headers"]["Authorization"] == "Bearer abc123"
        
    def test_trailing_slash_handling(self):
        """Test URLs with trailing slashes"""
        url = "https://example.com/api/"
        vars = self.engine.generate_base_variables(url)
        
        # BaseURL should not have trailing slash
        assert vars["BaseURL"] == "https://example.com/api"
