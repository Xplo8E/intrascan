"""Tests for extractor engine"""

import pytest
import json

from intrascan.extractors import ExtractorEngine
from intrascan.models import Extractor, ExtractorType, FridaResponse


class TestExtractorEngine:
    """Test extractor functionality"""
    
    def setup_method(self):
        self.engine = ExtractorEngine()
        
    def create_response(self, status_code=200, headers=None, body=""):
        """Helper to create test response"""
        return FridaResponse(
            status_code=status_code,
            headers=headers or {},
            body=body
        )
        
    # Regex Extractor Tests
    def test_extract_regex_simple(self):
        """Test simple regex extraction"""
        extractor = Extractor(
            type=ExtractorType.REGEX,
            name="version",
            regex=[r"version: ([0-9.]+)"]
        )
        response = self.create_response(body="Server version: 2.5.1")
        
        results = self.engine.extract(response, [extractor])
        
        assert "version" in results
        assert "2.5.1" in results["version"]
        
    def test_extract_regex_with_group(self):
        """Test regex extraction with specific group"""
        extractor = Extractor(
            type=ExtractorType.REGEX,
            name="major",
            regex=[r"v([0-9]+)\.([0-9]+)\.([0-9]+)"],
            group=0  # First capture group (major version)
        )
        response = self.create_response(body="Version v2.5.1")
        
        results = self.engine.extract(response, [extractor])
        
        assert "major" in results
        assert "2" in results["major"]
        
    def test_extract_regex_multiple_matches(self):
        """Test regex extracting multiple matches"""
        extractor = Extractor(
            type=ExtractorType.REGEX,
            name="emails",
            regex=[r"[\w.]+@[\w.]+\.\w+"]
        )
        response = self.create_response(
            body="Contact: admin@example.com, support@example.com"
        )
        
        results = self.engine.extract(response, [extractor])
        
        assert "emails" in results
        assert len(results["emails"]) == 2
        assert "admin@example.com" in results["emails"]
        
    def test_extract_regex_no_match(self):
        """Test regex with no match returns empty"""
        extractor = Extractor(
            type=ExtractorType.REGEX,
            name="phone",
            regex=[r"\d{3}-\d{3}-\d{4}"]
        )
        response = self.create_response(body="No phone numbers here")
        
        results = self.engine.extract(response, [extractor])
        
        assert results == {}  # No matches, no key
        
    # KVal Extractor Tests
    def test_extract_kval_header(self):
        """Test extracting values from headers"""
        extractor = Extractor(
            type=ExtractorType.KVAL,
            name="server_info",
            kval=["server", "x-powered-by"]
        )
        response = self.create_response(
            headers={
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/7.4",
                "Content-Type": "text/html"
            }
        )
        
        results = self.engine.extract(response, [extractor])
        
        assert "server_info" in results
        assert "nginx/1.18.0" in results["server_info"]
        assert "PHP/7.4" in results["server_info"]
        
    def test_extract_kval_missing_header(self):
        """Test kval with missing header"""
        extractor = Extractor(
            type=ExtractorType.KVAL,
            name="missing",
            kval=["x-custom-header"]
        )
        response = self.create_response(headers={"Server": "nginx"})
        
        results = self.engine.extract(response, [extractor])
        
        assert results == {}
        
    def test_extract_kval_case_insensitive(self):
        """Test kval is case-insensitive for header names"""
        extractor = Extractor(
            type=ExtractorType.KVAL,
            name="server",
            kval=["SERVER"]  # Uppercase
        )
        response = self.create_response(headers={"server": "nginx"})  # Lowercase
        
        results = self.engine.extract(response, [extractor])
        
        assert "server" in results
        assert "nginx" in results["server"]
        
    # JSON Extractor Tests
    def test_extract_json_simple(self):
        """Test simple JSON extraction"""
        extractor = Extractor(
            type=ExtractorType.JSON,
            name="user_id",
            json=[".data.user.id"]
        )
        response = self.create_response(
            body='{"data": {"user": {"id": "12345", "name": "test"}}}'
        )
        
        results = self.engine.extract(response, [extractor])
        
        assert "user_id" in results
        assert "12345" in results["user_id"]
        
    def test_extract_json_nested(self):
        """Test nested JSON extraction"""
        extractor = Extractor(
            type=ExtractorType.JSON,
            name="version",
            json=[".config.version"]
        )
        body = json.dumps({
            "config": {
                "version": "1.2.3",
                "enabled": True
            }
        })
        response = self.create_response(body=body)
        
        results = self.engine.extract(response, [extractor])
        
        assert "version" in results
        assert "1.2.3" in results["version"]
        
    def test_extract_json_array_index(self):
        """Test JSON array index extraction"""
        extractor = Extractor(
            type=ExtractorType.JSON,
            name="first_item",
            json=[".items[0].name"]
        )
        body = json.dumps({
            "items": [
                {"name": "first"},
                {"name": "second"}
            ]
        })
        response = self.create_response(body=body)
        
        results = self.engine.extract(response, [extractor])
        
        assert "first_item" in results
        assert "first" in results["first_item"]
        
    def test_extract_json_invalid(self):
        """Test JSON extraction from invalid JSON"""
        extractor = Extractor(
            type=ExtractorType.JSON,
            name="data",
            json=[".key"]
        )
        response = self.create_response(body="not valid json")
        
        results = self.engine.extract(response, [extractor])
        
        assert results == {}
        
    # Multiple Extractors Tests
    def test_extract_multiple(self):
        """Test running multiple extractors"""
        extractors = [
            Extractor(
                type=ExtractorType.REGEX,
                name="version",
                regex=[r"v([0-9.]+)"]
            ),
            Extractor(
                type=ExtractorType.KVAL,
                name="server",
                kval=["server"]
            )
        ]
        response = self.create_response(
            headers={"Server": "nginx"},
            body="Version v1.2.3"
        )
        
        results = self.engine.extract(response, extractors)
        
        assert "version" in results
        assert "server" in results
        assert "1.2.3" in results["version"]
        assert "nginx" in results["server"]
        
    # Internal Extractor Tests
    def test_extract_internal(self):
        """Test internal extractor for matcher use"""
        extractors = [
            Extractor(
                type=ExtractorType.REGEX,
                name="token",
                regex=[r"token=([a-f0-9]+)"],
                internal=True
            ),
            Extractor(
                type=ExtractorType.REGEX,
                name="public",
                regex=[r"id=(\d+)"],
                internal=False
            )
        ]
        response = self.create_response(body="token=abc123 id=456")
        
        internal = self.engine.extract_internal(response, extractors)
        
        assert "token" in internal
        assert internal["token"] == "abc123"
        assert "public" not in internal  # Not internal
        
    # Part Selection Tests
    def test_extract_from_header(self):
        """Test extracting from header part"""
        extractor = Extractor(
            type=ExtractorType.REGEX,
            name="version",
            regex=[r"nginx/([0-9.]+)"],
            part="header"
        )
        response = self.create_response(
            headers={"Server": "nginx/1.18.0"},
            body="Some body"
        )
        
        results = self.engine.extract(response, [extractor])
        
        assert "version" in results
        assert "1.18.0" in results["version"]
