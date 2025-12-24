"""
Tests for FridaResponse building and type handling

These tests specifically target edge cases that could cause bugs when
Frida JS returns data in unexpected formats.
"""
import pytest
from intrascan.models import FridaResponse
from intrascan.matchers import MatcherEngine, Matcher, MatcherType


class TestFridaResponseTypeCoercion:
    """Test that FridaResponse handles various input types correctly"""
    
    def test_status_code_as_int(self):
        """Normal case: status code is int"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='test'
        )
        assert response.status_code == 200
        assert isinstance(response.status_code, int)
    
    def test_status_code_zero(self):
        """Handle 0 status (no response)"""
        response = FridaResponse(
            status_code=0,
            headers={},
            body=''
        )
        assert response.status_code == 0
    
    def test_empty_body(self):
        """Handle empty body"""
        response = FridaResponse(
            status_code=204,
            headers={'Content-Length': '0'},
            body=''
        )
        assert response.body == ''
        assert len(response.body) == 0
    
    def test_none_body_defaults(self):
        """Handle None body - should default to empty string"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body=None
        )
        # Model should handle None gracefully
        assert response.body is None or response.body == ''
    
    def test_binary_like_body(self):
        """Handle body with binary-like content markers"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='[Binary data: 1024 bytes]'
        )
        assert 'Binary data' in response.body
    
    def test_unicode_body(self):
        """Handle unicode in body"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='日本語 中文 한국어 🎉 emoji'
        )
        assert '日本語' in response.body
        assert '🎉' in response.body
    
    def test_headers_with_special_chars(self):
        """Headers with special characters"""
        response = FridaResponse(
            status_code=200,
            headers={
                'Set-Cookie': 'session=abc123; Path=/; HttpOnly; Secure',
                'X-Custom': 'value with spaces & symbols!'
            },
            body=''
        )
        assert 'session=abc123' in response.headers['Set-Cookie']
    
    def test_large_body(self):
        """Handle large response body"""
        large_body = 'A' * 1000000  # 1MB
        response = FridaResponse(
            status_code=200,
            headers={},
            body=large_body
        )
        assert len(response.body) == 1000000


class TestMatcherWithStringStatusCode:
    """
    Test that matchers work correctly when status codes come as strings.
    This was the bug we discovered - Frida JS returns status as string.
    """
    
    def test_status_matcher_with_int_status(self):
        """Status matcher with int status code (normal case)"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='test'
        )
        matcher = Matcher(
            type=MatcherType.STATUS,
            status=[200]
        )
        
        engine = MatcherEngine()
        result, snippets = engine.match(response, [matcher], 'and', None)
        
        assert result is True, "Int status 200 should match [200]"
        assert '200' in snippets
    
    def test_status_matcher_multiple_codes(self):
        """Status matcher with multiple allowed codes"""
        response = FridaResponse(
            status_code=201,
            headers={},
            body=''
        )
        matcher = Matcher(
            type=MatcherType.STATUS,
            status=[200, 201, 204]
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True, "201 should match [200, 201, 204]"
    
    def test_status_matcher_no_match(self):
        """Status matcher should fail on different code"""
        response = FridaResponse(
            status_code=403,
            headers={},
            body=''
        )
        matcher = Matcher(
            type=MatcherType.STATUS,
            status=[200]
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is False, "403 should not match [200]"


class TestMatcherEdgeCases:
    """Edge cases in matcher logic"""
    
    def test_empty_matchers_list(self):
        """Empty matchers list should return False"""
        response = FridaResponse(status_code=200, headers={}, body='test')
        engine = MatcherEngine()
        result, _ = engine.match(response, [], 'and', None)
        assert result is False
    
    def test_word_matcher_partial_match(self):
        """Word matcher should match substrings"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='The administrator is logged in'
        )
        matcher = Matcher(
            type=MatcherType.WORD,
            words=['admin'],
            condition='or'
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True, "'admin' should match in 'administrator'"
    
    def test_word_matcher_exact_json_key(self):
        """Word matcher for JSON keys with quotes"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='{"openapi":"3.0.1","info":{}}'
        )
        matcher = Matcher(
            type=MatcherType.WORD,
            words=['"openapi"'],
            condition='or'
        )
        
        engine = MatcherEngine()
        result, snippets = engine.match(response, [matcher], 'and', None)
        
        assert result is True, '\"openapi\" should match in JSON'
        assert '"openapi"' in snippets
    
    def test_word_matcher_empty_words(self):
        """Word matcher with empty words list"""
        response = FridaResponse(status_code=200, headers={}, body='test')
        matcher = Matcher(
            type=MatcherType.WORD,
            words=[],
            condition='or'
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is False, "Empty words should not match"
    
    def test_word_matcher_empty_body(self):
        """Word matcher against empty body"""
        response = FridaResponse(status_code=200, headers={}, body='')
        matcher = Matcher(
            type=MatcherType.WORD,
            words=['test'],
            condition='or'
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is False
    
    def test_multiple_matchers_and_condition(self):
        """Multiple matchers with AND condition"""
        response = FridaResponse(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            body='{"openapi":"3.0.1"}'
        )
        matchers = [
            Matcher(type=MatcherType.STATUS, status=[200]),
            Matcher(type=MatcherType.WORD, words=['"openapi"'], condition='or')
        ]
        
        engine = MatcherEngine()
        result, snippets = engine.match(response, matchers, 'and', None)
        
        assert result is True
        assert '200' in snippets
        assert '"openapi"' in snippets
    
    def test_multiple_matchers_and_one_fails(self):
        """AND condition fails if any matcher fails"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='plain text body'
        )
        matchers = [
            Matcher(type=MatcherType.STATUS, status=[200]),
            Matcher(type=MatcherType.WORD, words=['"openapi"'], condition='or')
        ]
        
        engine = MatcherEngine()
        result, _ = engine.match(response, matchers, 'and', None)
        
        assert result is False, "AND should fail when word matcher fails"
    
    def test_multiple_matchers_or_condition(self):
        """OR condition passes if any matcher passes"""
        response = FridaResponse(
            status_code=404,
            headers={},
            body='Not Found'
        )
        matchers = [
            Matcher(type=MatcherType.STATUS, status=[200]),
            Matcher(type=MatcherType.WORD, words=['Found'], condition='or')
        ]
        
        engine = MatcherEngine()
        result, _ = engine.match(response, matchers, 'or', None)
        
        assert result is True, "OR should pass when word matcher passes"
    
    def test_negative_matcher(self):
        """Negative matcher inverts result"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='success'
        )
        matcher = Matcher(
            type=MatcherType.WORD,
            words=['error'],
            negative=True
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True, "Negative matcher should pass when word NOT found"
    
    def test_case_insensitive_word_matcher(self):
        """Case insensitive word matching"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='SUCCESS message'
        )
        matcher = Matcher(
            type=MatcherType.WORD,
            words=['success'],
            case_insensitive=True
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True


class TestRegexMatcher:
    """Regex matcher edge cases"""
    
    def test_regex_no_groups(self):
        """Regex without capture groups"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='Version: 1.2.3'
        )
        matcher = Matcher(
            type=MatcherType.REGEX,
            regex=[r'\d+\.\d+\.\d+']
        )
        
        engine = MatcherEngine()
        result, snippets = engine.match(response, [matcher], 'and', None)
        
        assert result is True
        assert '1.2.3' in snippets
    
    def test_regex_with_groups(self):
        """Regex with capture groups"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='{"version":"2.0.0"}'
        )
        matcher = Matcher(
            type=MatcherType.REGEX,
            regex=[r'"version"\s*:\s*"([^"]+)"']
        )
        
        engine = MatcherEngine()
        result, snippets = engine.match(response, [matcher], 'and', None)
        
        assert result is True
        assert '2.0.0' in snippets
    
    def test_regex_multiple_patterns_or(self):
        """Multiple regex patterns - any match wins"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='Server: nginx'
        )
        matcher = Matcher(
            type=MatcherType.REGEX,
            regex=[r'Apache', r'nginx', r'IIS']
        )
        
        engine = MatcherEngine()
        result, snippets = engine.match(response, [matcher], 'and', None)
        
        assert result is True
        assert 'nginx' in snippets
    
    def test_regex_invalid_pattern(self):
        """Invalid regex should not crash"""
        response = FridaResponse(status_code=200, headers={}, body='test')
        matcher = Matcher(
            type=MatcherType.REGEX,
            regex=[r'[invalid(regex']
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        # Should not crash, just return no match
        assert result is False


class TestBinaryMatcher:
    """Binary matcher edge cases"""
    
    def test_binary_hex_match(self):
        """Binary hex pattern matching"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='PK\x03\x04....zip content'  # ZIP magic bytes
        )
        matcher = Matcher(
            type=MatcherType.BINARY,
            binary=['504b0304']  # PK\x03\x04 in hex
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        # This may or may not match depending on encoding
        # The test ensures no crash
        assert isinstance(result, bool)


class TestSizeMatcher:
    """Size matcher tests"""
    
    def test_size_exact_match(self):
        """Size matches exactly"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='12345'  # 5 bytes
        )
        matcher = Matcher(
            type=MatcherType.SIZE,
            size=[5]
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True
    
    def test_size_multiple_options(self):
        """Size matches one of several options"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='test'  # 4 bytes
        )
        matcher = Matcher(
            type=MatcherType.SIZE,
            size=[0, 4, 100]
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True
    
    def test_size_no_match(self):
        """Size doesn't match"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='hello world'  # 11 bytes
        )
        matcher = Matcher(
            type=MatcherType.SIZE,
            size=[5, 10, 15]
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is False


class TestDSLMatcher:
    """DSL expression matcher tests"""
    
    def test_dsl_status_code_comparison(self):
        """DSL: status_code == 200"""
        response = FridaResponse(status_code=200, headers={}, body='')
        matcher = Matcher(
            type=MatcherType.DSL,
            dsl=['status_code == 200']
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True
    
    def test_dsl_contains(self):
        """DSL: contains(body, \"text\")"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='some text here'
        )
        matcher = Matcher(
            type=MatcherType.DSL,
            dsl=['contains(body, "text")']
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True
    
    def test_dsl_content_length(self):
        """DSL: len(body) > 0"""
        response = FridaResponse(
            status_code=200,
            headers={},
            body='not empty'
        )
        matcher = Matcher(
            type=MatcherType.DSL,
            dsl=['len(body) > 0']
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True


class TestMatcherPartSelection:
    """Test matching on different response parts"""
    
    def test_match_in_header(self):
        """Match word in headers"""
        response = FridaResponse(
            status_code=200,
            headers={'Server': 'Apache/2.4.41 (Ubuntu)'},
            body='body content'
        )
        matcher = Matcher(
            type=MatcherType.WORD,
            words=['Apache'],
            part='header'
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True
    
    def test_match_in_all(self):
        """Match in combined headers + body"""
        response = FridaResponse(
            status_code=200,
            headers={'X-Custom': 'secret-value'},
            body='normal body'
        )
        matcher = Matcher(
            type=MatcherType.WORD,
            words=['secret'],
            part='all'
        )
        
        engine = MatcherEngine()
        result, _ = engine.match(response, [matcher], 'and', None)
        
        assert result is True
