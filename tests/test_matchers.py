"""Tests for matcher engine"""

import pytest

from intrascan.matchers import MatcherEngine
from intrascan.models import Matcher, MatcherType, FridaResponse


class TestMatcherEngine:
    """Test matcher functionality"""
    
    def setup_method(self):
        self.engine = MatcherEngine()
        
    def create_response(self, status_code=200, headers=None, body=""):
        """Helper to create test response"""
        return FridaResponse(
            status_code=status_code,
            headers=headers or {},
            body=body
        )
        
    # Status Matcher Tests
    def test_match_status_single(self):
        """Test matching single status code"""
        matcher = Matcher(
            type=MatcherType.STATUS,
            status=[200]
        )
        response = self.create_response(status_code=200)
        
        matched, snippets = self.engine.match(response, [matcher])
        
        assert matched == True
        assert "200" in snippets
        
    def test_match_status_multiple(self):
        """Test matching one of multiple status codes"""
        matcher = Matcher(
            type=MatcherType.STATUS,
            status=[200, 201, 302]
        )
        response = self.create_response(status_code=302)
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == True
        
    def test_match_status_fail(self):
        """Test status matcher failure"""
        matcher = Matcher(
            type=MatcherType.STATUS,
            status=[200]
        )
        response = self.create_response(status_code=404)
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == False
        
    # Word Matcher Tests
    def test_match_word_simple(self):
        """Test simple word matching"""
        matcher = Matcher(
            type=MatcherType.WORD,
            words=["success"]
        )
        response = self.create_response(body="Operation success!")
        
        matched, snippets = self.engine.match(response, [matcher])
        
        assert matched == True
        assert "success" in snippets
        
    def test_match_word_or_condition(self):
        """Test word matching with OR condition (default)"""
        matcher = Matcher(
            type=MatcherType.WORD,
            words=["success", "admin", "root"],
            condition="or"
        )
        response = self.create_response(body="Welcome admin user")
        
        matched, snippets = self.engine.match(response, [matcher])
        
        assert matched == True
        assert "admin" in snippets
        
    def test_match_word_and_condition(self):
        """Test word matching with AND condition"""
        matcher = Matcher(
            type=MatcherType.WORD,
            words=["success", "admin"],
            condition="and"
        )
        
        # Both words present
        response1 = self.create_response(body="success admin panel")
        matched1, _ = self.engine.match(response1, [matcher])
        assert matched1 == True
        
        # Only one word present
        response2 = self.create_response(body="success only")
        matched2, _ = self.engine.match(response2, [matcher])
        assert matched2 == False
        
    def test_match_word_case_insensitive(self):
        """Test case-insensitive word matching"""
        matcher = Matcher(
            type=MatcherType.WORD,
            words=["SUCCESS"],
            case_insensitive=True
        )
        response = self.create_response(body="Operation success!")
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == True
        
    def test_match_word_in_header(self):
        """Test word matching in headers"""
        matcher = Matcher(
            type=MatcherType.WORD,
            words=["nginx"],
            part="header"
        )
        response = self.create_response(
            headers={"Server": "nginx/1.18.0"}
        )
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == True
        
    # Regex Matcher Tests
    def test_match_regex_simple(self):
        """Test simple regex matching"""
        matcher = Matcher(
            type=MatcherType.REGEX,
            regex=[r"version: ([0-9.]+)"]
        )
        response = self.create_response(body="Server version: 2.5.1")
        
        matched, snippets = self.engine.match(response, [matcher])
        
        assert matched == True
        assert "2.5.1" in snippets
        
    def test_match_regex_multiple_patterns(self):
        """Test multiple regex patterns"""
        matcher = Matcher(
            type=MatcherType.REGEX,
            regex=[r"v([0-9]+)", r"build-([0-9]+)"]
        )
        response = self.create_response(body="Version v23 build-456")
        
        matched, snippets = self.engine.match(response, [matcher])
        
        assert matched == True
        assert "23" in snippets
        assert "456" in snippets
        
    def test_match_regex_no_match(self):
        """Test regex with no match"""
        matcher = Matcher(
            type=MatcherType.REGEX,
            regex=[r"[0-9]{10}"]  # 10-digit number
        )
        response = self.create_response(body="No numbers here")
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == False
        
    # DSL Matcher Tests
    def test_match_dsl_status_code(self):
        """Test DSL matching on status code"""
        matcher = Matcher(
            type=MatcherType.DSL,
            dsl=["status_code == 200"]
        )
        response = self.create_response(status_code=200)
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == True
        
    def test_match_dsl_contains(self):
        """Test DSL contains function"""
        matcher = Matcher(
            type=MatcherType.DSL,
            dsl=['contains(body, "admin")']
        )
        response = self.create_response(body="Welcome admin")
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == True
        
    def test_match_dsl_contains_any(self):
        """Test DSL contains_any function"""
        matcher = Matcher(
            type=MatcherType.DSL,
            dsl=['contains_any(body, "admin", "root", "superuser")']
        )
        response = self.create_response(body="Login as root")
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == True
        
    def test_match_dsl_combined(self):
        """Test DSL with combined conditions"""
        matcher = Matcher(
            type=MatcherType.DSL,
            dsl=[
                'status_code == 200',
                'contains(body, "success")'
            ]
        )
        
        # Both conditions met
        response1 = self.create_response(status_code=200, body="Operation success")
        matched1, _ = self.engine.match(response1, [matcher])
        assert matched1 == True
        
        # Only one condition met
        response2 = self.create_response(status_code=200, body="Operation failed")
        matched2, _ = self.engine.match(response2, [matcher])
        assert matched2 == False
        
    # Negative Matcher Tests
    def test_match_negative(self):
        """Test negative matching"""
        matcher = Matcher(
            type=MatcherType.WORD,
            words=["error"],
            negative=True
        )
        
        # No error = match
        response1 = self.create_response(body="Operation success")
        matched1, _ = self.engine.match(response1, [matcher])
        assert matched1 == True
        
        # Has error = no match
        response2 = self.create_response(body="An error occurred")
        matched2, _ = self.engine.match(response2, [matcher])
        assert matched2 == False
        
    # Multiple Matchers Tests
    def test_match_multiple_or_condition(self):
        """Test multiple matchers with OR condition"""
        matchers = [
            Matcher(type=MatcherType.STATUS, status=[200]),
            Matcher(type=MatcherType.WORD, words=["admin"]),
        ]
        
        # First matcher passes
        response = self.create_response(status_code=200, body="Normal page")
        matched, _ = self.engine.match(response, matchers, "or")
        assert matched == True
        
    def test_match_multiple_and_condition(self):
        """Test multiple matchers with AND condition"""
        matchers = [
            Matcher(type=MatcherType.STATUS, status=[200]),
            Matcher(type=MatcherType.WORD, words=["admin"]),
        ]
        
        # Both pass (lowercase 'admin' in body)
        response1 = self.create_response(status_code=200, body="Welcome admin user")
        matched1, _ = self.engine.match(response1, matchers, "and")
        assert matched1 == True
        
        # Only one passes
        response2 = self.create_response(status_code=200, body="Normal page")
        matched2, _ = self.engine.match(response2, matchers, "and")
        assert matched2 == False
        
    # Binary Matcher Tests
    def test_match_binary(self):
        """Test binary/hex pattern matching"""
        matcher = Matcher(
            type=MatcherType.BINARY,
            binary=["504b0304"]  # ZIP file signature
        )
        # Create response with ZIP magic bytes
        response = self.create_response(body="PK\x03\x04some zip content")
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == True
        
    # Size Matcher Tests
    def test_match_size(self):
        """Test size matching"""
        matcher = Matcher(
            type=MatcherType.SIZE,
            size=[5]
        )
        response = self.create_response(body="12345")
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == True
        
    # Part Selection Tests
    def test_match_part_all(self):
        """Test matching on 'all' (headers + body)"""
        matcher = Matcher(
            type=MatcherType.WORD,
            words=["nginx"],
            part="all"
        )
        response = self.create_response(
            headers={"Server": "nginx"},
            body="Welcome"
        )
        
        matched, _ = self.engine.match(response, [matcher])
        assert matched == True
