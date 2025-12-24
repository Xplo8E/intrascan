"""
Shared test fixtures for intrascan tests
"""
import pytest
from nuclei_frida.models import (
    FridaResponse, NucleiTemplate, HttpRequest, Matcher, 
    Extractor, TemplateInfo, Severity, MatcherType, ExtractorType
)


# ============================================================================
# FridaResponse Fixtures - Various response types
# ============================================================================

@pytest.fixture
def simple_response():
    """Basic 200 OK response"""
    return FridaResponse(
        status_code=200,
        headers={'Content-Type': 'application/json'},
        body='{"status": "ok"}',
        duration=0.1
    )

@pytest.fixture
def html_response():
    """HTML response"""
    return FridaResponse(
        status_code=200,
        headers={
            'Content-Type': 'text/html',
            'Server': 'nginx/1.18.0',
            'X-Powered-By': 'PHP/7.4.3'
        },
        body='<html><head><title>Test Page</title></head><body><h1>Welcome</h1></body></html>',
        duration=0.2
    )

@pytest.fixture
def error_response():
    """500 error response"""
    return FridaResponse(
        status_code=500,
        headers={'Content-Type': 'application/json'},
        body='{"error": "Internal Server Error"}',
        duration=0.5
    )

@pytest.fixture
def empty_response():
    """Empty body response"""
    return FridaResponse(
        status_code=204,
        headers={},
        body='',
        duration=0.05
    )

@pytest.fixture
def unicode_response():
    """Response with unicode content"""
    return FridaResponse(
        status_code=200,
        headers={'Content-Type': 'text/html; charset=utf-8'},
        body='<html><body>日本語 中文 한국어 🎉</body></html>',
        duration=0.1
    )

@pytest.fixture
def large_response():
    """Large response body"""
    return FridaResponse(
        status_code=200,
        headers={'Content-Type': 'text/plain'},
        body='A' * 100000,  # 100KB of A's
        duration=1.0
    )

@pytest.fixture
def api_response():
    """Realistic API response with OpenAPI content"""
    return FridaResponse(
        status_code=200,
        headers={
            'Content-Type': 'application/json',
            'X-API-Version': '2.0',
            'Cache-Control': 'no-cache'
        },
        body='{"openapi":"3.0.1","info":{"title":"Test API","version":"v1"},"paths":{}}',
        duration=0.3
    )


# ============================================================================
# String status code fixtures (simulating Frida JS output)
# ============================================================================

@pytest.fixture
def string_status_response():
    """Response where status came as string from Frida JS - testing type coercion"""
    # Note: This simulates what we'd get if we didn't convert
    # The actual code should convert, so this tests the model directly
    return {
        'status_code': '200',  # String!
        'headers': {'Content-Type': 'text/plain'},
        'body': 'test',
        'duration': '0.1'  # Also string!
    }


# ============================================================================
# Matcher Fixtures
# ============================================================================

@pytest.fixture
def status_200_matcher():
    """Matcher for status 200"""
    return Matcher(
        type=MatcherType.STATUS,
        status=[200]
    )

@pytest.fixture
def word_matcher():
    """Word matcher for common terms"""
    return Matcher(
        type=MatcherType.WORD,
        words=['admin', 'password', 'login'],
        condition='or'
    )

@pytest.fixture
def regex_version_matcher():
    """Regex matcher for version extraction"""
    return Matcher(
        type=MatcherType.REGEX,
        regex=[r'version["\s:]+([0-9]+\.[0-9]+\.[0-9]+)']
    )


# ============================================================================
# Extractor Fixtures
# ============================================================================

@pytest.fixture
def json_extractor():
    """JSON path extractor"""
    return Extractor(
        type=ExtractorType.JSON,
        name='api_version',
        json=['.info.version']
    )

@pytest.fixture
def regex_extractor():
    """Regex extractor"""
    return Extractor(
        type=ExtractorType.REGEX,
        name='title',
        regex=[r'<title>([^<]+)</title>']
    )


# ============================================================================
# Template Fixtures
# ============================================================================

@pytest.fixture
def simple_template():
    """Minimal template for testing"""
    return NucleiTemplate(
        id='test-template',
        info=TemplateInfo(
            name='Test Template',
            author='test',
            severity=Severity.INFO
        ),
        http_requests=[
            HttpRequest(
                method='GET',
                path=['{{BaseURL}}/test'],
                matchers=[
                    Matcher(type=MatcherType.STATUS, status=[200])
                ]
            )
        ]
    )

@pytest.fixture
def multi_matcher_template():
    """Template with multiple matchers (AND condition)"""
    return NucleiTemplate(
        id='multi-matcher-test',
        info=TemplateInfo(
            name='Multi Matcher Test',
            author='test',
            severity=Severity.MEDIUM
        ),
        http_requests=[
            HttpRequest(
                method='GET',
                path=['{{BaseURL}}/api'],
                matchers_condition='and',
                matchers=[
                    Matcher(type=MatcherType.STATUS, status=[200]),
                    Matcher(type=MatcherType.WORD, words=['openapi'], condition='or')
                ]
            )
        ]
    )
