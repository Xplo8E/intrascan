"""Tests for template parser"""

import pytest
import tempfile
import os

from intrascan.template_parser import TemplateParser
from intrascan.models import Severity, MatcherType, ExtractorType


class TestTemplateParser:
    """Test template parsing functionality"""
    
    def setup_method(self):
        self.parser = TemplateParser()
        
    def test_parse_simple_template(self):
        """Test parsing a simple template"""
        content = """
id: test-template

info:
  name: Test Template
  author: tester
  severity: high
  description: A test template
  tags: test,example

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/test"
    
    matchers:
      - type: status
        status:
          - 200
"""
        template = self.parser.parse_content(content)
        
        assert template is not None
        assert template.id == "test-template"
        assert template.info.name == "Test Template"
        assert template.info.author == "tester"
        assert template.info.severity == Severity.HIGH
        assert "test" in template.info.tags
        assert len(template.http_requests) == 1
        assert template.http_requests[0].method == "GET"
        
    def test_parse_template_with_matchers(self):
        """Test parsing template with various matcher types"""
        content = """
id: matcher-test

info:
  name: Matcher Test
  severity: critical

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 201
      
      - type: word
        part: body
        words:
          - "success"
          - "admin"
        condition: or
      
      - type: regex
        regex:
          - "version: ([0-9.]+)"
      
      - type: dsl
        dsl:
          - 'status_code == 200'
          - 'contains(body, "test")'
"""
        template = self.parser.parse_content(content)
        
        assert template is not None
        assert len(template.http_requests[0].matchers) == 4
        
        req = template.http_requests[0]
        assert req.matchers_condition == "and"
        
        # Check status matcher
        status_matcher = req.matchers[0]
        assert status_matcher.type == MatcherType.STATUS
        assert 200 in status_matcher.status
        assert 201 in status_matcher.status
        
        # Check word matcher
        word_matcher = req.matchers[1]
        assert word_matcher.type == MatcherType.WORD
        assert word_matcher.part == "body"
        assert "success" in word_matcher.words
        assert word_matcher.condition == "or"
        
        # Check regex matcher
        regex_matcher = req.matchers[2]
        assert regex_matcher.type == MatcherType.REGEX
        assert len(regex_matcher.regex) == 1
        
        # Check DSL matcher
        dsl_matcher = req.matchers[3]
        assert dsl_matcher.type == MatcherType.DSL
        assert len(dsl_matcher.dsl) == 2
        
    def test_parse_template_with_extractors(self):
        """Test parsing template with extractors"""
        content = """
id: extractor-test

info:
  name: Extractor Test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    extractors:
      - type: regex
        name: version
        regex:
          - 'version[":]+([0-9.]+)'
        group: 1
        internal: true
        
      - type: kval
        name: server
        kval:
          - server
          - x-powered-by
          
      - type: json
        name: data
        json:
          - '.data.id'
"""
        template = self.parser.parse_content(content)
        
        assert template is not None
        assert len(template.http_requests[0].extractors) == 3
        
        extractors = template.http_requests[0].extractors
        
        # Check regex extractor
        regex_ext = extractors[0]
        assert regex_ext.type == ExtractorType.REGEX
        assert regex_ext.name == "version"
        assert regex_ext.group == 1
        assert regex_ext.internal == True
        
        # Check kval extractor
        kval_ext = extractors[1]
        assert kval_ext.type == ExtractorType.KVAL
        assert "server" in kval_ext.kval
        
        # Check json extractor
        json_ext = extractors[2]
        assert json_ext.type == ExtractorType.JSON
        assert ".data.id" in json_ext.json
        
    def test_parse_raw_request(self):
        """Test parsing template with raw request format"""
        content = """
id: raw-request-test

info:
  name: Raw Request Test
  severity: medium

http:
  - raw:
      - |
        GET /api/test HTTP/1.1
        Host: {{Hostname}}
        X-Custom: value
        
    matchers:
      - type: word
        words:
          - "success"
"""
        template = self.parser.parse_content(content)
        
        assert template is not None
        assert len(template.http_requests[0].raw) == 1
        assert "GET /api/test" in template.http_requests[0].raw[0]
        
    def test_parse_severity_levels(self):
        """Test parsing all severity levels"""
        severities = ["critical", "high", "medium", "low", "info"]
        
        for sev in severities:
            content = f"""
id: severity-{sev}
info:
  name: Test
  severity: {sev}
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}"
    matchers:
      - type: status
        status: [200]
"""
            template = self.parser.parse_content(content)
            assert template is not None
            assert template.info.severity.value == sev
            
    def test_parse_invalid_template(self):
        """Test parsing invalid template returns None"""
        # Missing id
        content1 = """
info:
  name: No ID
  severity: high
"""
        assert self.parser.parse_content(content1) is None
        
        # Missing http section
        content2 = """
id: no-http
info:
  name: No HTTP
  severity: high
"""
        assert self.parser.parse_content(content2) is None
        
        # Invalid YAML
        content3 = "not: valid: yaml: [[[["
        assert self.parser.parse_content(content3) is None
        
    def test_parse_file(self):
        """Test parsing from file"""
        content = """
id: file-test
info:
  name: File Test
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status: [200]
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(content)
            path = f.name
            
        try:
            template = self.parser.parse_file(path)
            assert template is not None
            assert template.id == "file-test"
            assert template.path == path
        finally:
            os.unlink(path)
            
    def test_parse_negative_matcher(self):
        """Test parsing negative matcher"""
        content = """
id: negative-test
info:
  name: Negative Test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "error"
        negative: true
"""
        template = self.parser.parse_content(content)
        
        assert template is not None
        assert template.http_requests[0].matchers[0].negative == True
