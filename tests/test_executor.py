"""
Tests for NucleiExecutor using mocked FridaNetworkClient.

These tests verify the orchestration logic without requiring
a real Frida connection.
"""
import pytest
import os
from unittest.mock import Mock, MagicMock, patch
from nuclei_frida.executor import NucleiExecutor
from nuclei_frida.frida_client import FridaNetworkClient
from nuclei_frida.models import (
    NucleiTemplate, HttpRequest, Matcher, Extractor,
    TemplateInfo, Severity, MatcherType, ExtractorType,
    FridaResponse, ScanResult
)


class TestExecutorInit:
    """Test executor initialization"""
    
    def test_init_basic(self):
        """Basic initialization"""
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(frida_client=mock_client)
        
        assert executor.frida_client == mock_client
        assert executor.verbose is False
        assert executor.log_file is None
        assert executor._log_handle is None
    
    def test_init_with_verbose(self):
        """Verbose mode initialization"""
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(frida_client=mock_client, verbose=True)
        
        assert executor.verbose is True
    
    def test_init_with_log_file(self, tmp_path):
        """Log file initialization"""
        log_file = tmp_path / "test.log"
        mock_client = Mock(spec=FridaNetworkClient)
        
        executor = NucleiExecutor(
            frida_client=mock_client,
            log_file=str(log_file)
        )
        
        assert executor.log_file == str(log_file)
        assert executor._log_handle is not None
        
        # Write something
        executor._log("test message")
        executor._log_handle.close()
        
        # Verify log file content
        content = log_file.read_text()
        assert "Intrascan Log" in content
        assert "test message" in content
    
    def test_init_creates_components(self):
        """Executor creates required components"""
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(frida_client=mock_client)
        
        assert executor.template_parser is not None
        assert executor.request_builder is not None
        assert executor.matcher_engine is not None
        assert executor.extractor_engine is not None
    
    def test_callbacks_default_none(self):
        """Callbacks default to None"""
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(frida_client=mock_client)
        
        assert executor.on_template_start is None
        assert executor.on_template_complete is None


class TestExecutorLogging:
    """Test logging functionality"""
    
    def test_log_to_file(self, tmp_path):
        """Log writes to file"""
        log_file = tmp_path / "test.log"
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(
            frida_client=mock_client,
            log_file=str(log_file)
        )
        
        executor._log("First message")
        executor._log("Second message")
        executor._log_handle.close()
        
        content = log_file.read_text()
        assert "First message" in content
        assert "Second message" in content
    
    def test_log_also_print(self, tmp_path, capsys):
        """Log with also_print=True prints to stdout"""
        log_file = tmp_path / "test.log"
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(
            frida_client=mock_client,
            log_file=str(log_file)
        )
        
        executor._log("Visible message", also_print=True)
        
        captured = capsys.readouterr()
        assert "Visible message" in captured.out
    
    def test_log_verbose_mode(self, tmp_path, capsys):
        """Verbose mode prints all logs"""
        log_file = tmp_path / "test.log"
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(
            frida_client=mock_client,
            log_file=str(log_file),
            verbose=True
        )
        
        executor._log("Verbose message")
        
        captured = capsys.readouterr()
        assert "Verbose message" in captured.out
    
    def test_log_without_file(self, capsys):
        """Log without file handle (verbose mode)"""
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(
            frida_client=mock_client,
            verbose=True
        )
        
        # Should not crash
        executor._log("No file message")
        
        captured = capsys.readouterr()
        assert "No file message" in captured.out


class TestPreflightCheck:
    """Test preflight connectivity check"""
    
    def test_preflight_success(self):
        """Preflight passes with 200 response"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={},
            body='OK',
            duration=0.1
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        result = executor.preflight_check("https://example.com")
        
        assert result is True
        mock_client.send_request.assert_called_once()
    
    def test_preflight_success_with_log(self, tmp_path, capsys):
        """Preflight logs success message"""
        log_file = tmp_path / "test.log"
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={},
            body='OK',
            duration=0.5
        )
        
        executor = NucleiExecutor(
            frida_client=mock_client,
            log_file=str(log_file)
        )
        result = executor.preflight_check("https://example.com")
        
        assert result is True
        captured = capsys.readouterr()
        assert "Preflight OK" in captured.out
        assert "HTTP 200" in captured.out
    
    def test_preflight_error_response(self, capsys):
        """Preflight fails with error in response"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=0,
            headers={},
            body='',
            error='Connection refused'
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        result = executor.preflight_check("https://example.com")
        
        assert result is False
        captured = capsys.readouterr()
        assert "Preflight failed" in captured.out
    
    def test_preflight_exception(self, capsys):
        """Preflight handles exception"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.side_effect = Exception("Network error")
        
        executor = NucleiExecutor(frida_client=mock_client)
        result = executor.preflight_check("https://example.com")
        
        assert result is False
        captured = capsys.readouterr()
        assert "Preflight failed" in captured.out


class TestExecuteTemplate:
    """Test single template execution"""
    
    def test_execute_template_match(self):
        """Execute template that matches"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            body='{"success": true}',
            duration=0.3
        )
        
        template = NucleiTemplate(
            id='test-match',
            info=TemplateInfo(name='Test Match', author='test', severity=Severity.INFO),
            http_requests=[
                HttpRequest(
                    method='GET',
                    path=['{{BaseURL}}/api/test'],
                    matchers=[
                        Matcher(type=MatcherType.STATUS, status=[200])
                    ]
                )
            ]
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        result = executor.execute_template(template, 'https://example.com')
        
        assert result.matched is True
        assert result.template_id == 'test-match'
        assert result.severity == Severity.INFO
    
    def test_execute_template_no_match(self):
        """Execute template that doesn't match"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=404,
            headers={},
            body='Not Found',
            duration=0.2
        )
        
        template = NucleiTemplate(
            id='test-no-match',
            info=TemplateInfo(name='Test No Match', author='test', severity=Severity.HIGH),
            http_requests=[
                HttpRequest(
                    method='GET',
                    path=['{{BaseURL}}/admin'],
                    matchers=[
                        Matcher(type=MatcherType.STATUS, status=[200])
                    ]
                )
            ]
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        result = executor.execute_template(template, 'https://example.com')
        
        assert result.matched is False
        assert result.template_id == 'test-no-match'
    
    def test_execute_template_with_extractor(self):
        """Execute template with extractors"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={'Server': 'nginx/1.18.0'},
            body='<html><title>Test Page</title></html>',
            duration=0.2
        )
        
        template = NucleiTemplate(
            id='test-extract',
            info=TemplateInfo(name='Test Extract', author='test', severity=Severity.INFO),
            http_requests=[
                HttpRequest(
                    method='GET',
                    path=['{{BaseURL}}/'],
                    matchers=[
                        Matcher(type=MatcherType.STATUS, status=[200])
                    ],
                    extractors=[
                        Extractor(
                            type=ExtractorType.REGEX,
                            name='title',
                            regex=[r'<title>([^<]+)</title>']
                        )
                    ]
                )
            ]
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        result = executor.execute_template(template, 'https://example.com')
        
        assert result.matched is True
        assert 'Test Page' in result.extracted
    
    def test_execute_template_multiple_paths(self):
        """Execute template with multiple paths"""
        mock_client = Mock(spec=FridaNetworkClient)
        # First request 404, second request 200
        mock_client.send_request.side_effect = [
            FridaResponse(status_code=404, headers={}, body='Not Found', duration=0.1),
            FridaResponse(status_code=200, headers={}, body='Found', duration=0.1),
        ]
        
        template = NucleiTemplate(
            id='test-multi-path',
            info=TemplateInfo(name='Multi Path', author='test', severity=Severity.INFO),
            http_requests=[
                HttpRequest(
                    method='GET',
                    path=[
                        '{{BaseURL}}/path1',
                        '{{BaseURL}}/path2'
                    ],
                    matchers=[
                        Matcher(type=MatcherType.STATUS, status=[200])
                    ]
                )
            ]
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        result = executor.execute_template(template, 'https://example.com')
        
        # Should match on second path
        assert result.matched is True
        assert mock_client.send_request.call_count == 2
    
    def test_execute_template_with_callback(self):
        """Execute template triggers callbacks"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={},
            body='OK',
            duration=0.1
        )
        
        template = NucleiTemplate(
            id='test-callback',
            info=TemplateInfo(name='Callback Test', author='test', severity=Severity.INFO),
            http_requests=[
                HttpRequest(
                    method='GET',
                    path=['{{BaseURL}}/'],
                    matchers=[Matcher(type=MatcherType.STATUS, status=[200])]
                )
            ]
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        
        # Set up callback
        callback_called = []
        executor.on_template_start = lambda tid: callback_called.append(('start', tid))
        
        result = executor.execute_template(template, 'https://example.com')
        
        assert ('start', 'test-callback') in callback_called
    
    def test_execute_template_handles_error(self):
        """Execute template handles request error"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=0,
            headers={},
            body='',
            error='Timeout',
            duration=0.0
        )
        
        template = NucleiTemplate(
            id='test-error',
            info=TemplateInfo(name='Error Test', author='test', severity=Severity.INFO),
            http_requests=[
                HttpRequest(
                    method='GET',
                    path=['{{BaseURL}}/'],
                    matchers=[Matcher(type=MatcherType.STATUS, status=[200])]
                )
            ]
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        result = executor.execute_template(template, 'https://example.com')
        
        # Should not match due to error
        assert result.matched is False
    
    def test_execute_template_exception_handling(self):
        """Execute template handles exceptions gracefully"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.side_effect = Exception("Unexpected error")
        
        template = NucleiTemplate(
            id='test-exception',
            info=TemplateInfo(name='Exception Test', author='test', severity=Severity.INFO),
            http_requests=[
                HttpRequest(
                    method='GET',
                    path=['{{BaseURL}}/'],
                    matchers=[]
                )
            ]
        )
        
        executor = NucleiExecutor(frida_client=mock_client, verbose=True)
        result = executor.execute_template(template, 'https://example.com')
        
        # Should return non-matched result without crashing
        assert result.matched is False


class TestExecute:
    """Test full execution with template discovery"""
    
    def test_execute_from_file(self, tmp_path):
        """Execute from single template file"""
        # Create template file
        template_content = """
id: test-template

info:
  name: Test Template
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: status
        status:
          - 200
"""
        template_file = tmp_path / "test.yaml"
        template_file.write_text(template_content)
        
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={},
            body='OK',
            duration=0.1
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        results = executor.execute(str(template_file), 'https://example.com')
        
        assert len(results) == 1
        assert results[0].matched is True
        assert results[0].template_id == 'test-template'
    
    def test_execute_with_limit(self, tmp_path):
        """Execute with template limit"""
        # Create multiple template files
        for i in range(5):
            content = f"""
id: test-{i}

info:
  name: Test {i}
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/test{i}"
    matchers:
      - type: status
        status:
          - 200
"""
            (tmp_path / f"test{i}.yaml").write_text(content)
        
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={},
            body='OK',
            duration=0.1
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        results = executor.execute(str(tmp_path), 'https://example.com', limit=2)
        
        assert len(results) == 2
    
    def test_execute_with_severity_filter(self, tmp_path):
        """Execute with severity filter"""
        # Create templates with different severities
        high_template = """
id: high-severity

info:
  name: High Severity
  author: test
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/high"
    matchers:
      - type: status
        status:
          - 200
"""
        low_template = """
id: low-severity

info:
  name: Low Severity
  author: test
  severity: low

http:
  - method: GET
    path:
      - "{{BaseURL}}/low"
    matchers:
      - type: status
        status:
          - 200
"""
        (tmp_path / "high.yaml").write_text(high_template)
        (tmp_path / "low.yaml").write_text(low_template)
        
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={},
            body='OK',
            duration=0.1
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        results = executor.execute(
            str(tmp_path), 
            'https://example.com',
            severities=['high']
        )
        
        assert len(results) == 1
        assert results[0].template_id == 'high-severity'
    
    def test_execute_on_complete_callback(self, tmp_path):
        """Execute calls on_complete callback for each template"""
        template_content = """
id: callback-test

info:
  name: Callback Test
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: status
        status:
          - 200
"""
        (tmp_path / "test.yaml").write_text(template_content)
        
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={},
            body='OK',
            duration=0.1
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        
        completed_results = []
        executor.on_template_complete = lambda r: completed_results.append(r)
        
        results = executor.execute(str(tmp_path), 'https://example.com')
        
        assert len(completed_results) == 1
        assert completed_results[0].template_id == 'callback-test'


class TestFormatMethods:
    """Test request/response formatting"""
    
    def test_format_request_get(self):
        """Format GET request"""
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(frida_client=mock_client)
        
        request = {
            'method': 'GET',
            'url': 'https://example.com/api',
            'headers': {'Host': 'example.com', 'User-Agent': 'Test'},
            'body': ''
        }
        
        formatted = executor._format_request(request)
        
        assert 'GET https://example.com/api HTTP/1.1' in formatted
        assert 'Host: example.com' in formatted
        assert 'User-Agent: Test' in formatted
    
    def test_format_request_post_with_body(self):
        """Format POST request with body"""
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(frida_client=mock_client)
        
        request = {
            'method': 'POST',
            'url': 'https://example.com/api',
            'headers': {'Content-Type': 'application/json'},
            'body': '{"key": "value"}'
        }
        
        formatted = executor._format_request(request)
        
        assert 'POST https://example.com/api HTTP/1.1' in formatted
        assert '{"key": "value"}' in formatted
    
    def test_format_response(self):
        """Format response"""
        mock_client = Mock(spec=FridaNetworkClient)
        executor = NucleiExecutor(frida_client=mock_client)
        
        response = FridaResponse(
            status_code=200,
            headers={'Content-Type': 'application/json', 'Server': 'nginx'},
            body='{"status": "ok"}',
            duration=0.5
        )
        
        formatted = executor._format_response(response)
        
        assert 'HTTP/1.1 200 OK' in formatted
        assert 'Content-Type: application/json' in formatted
        assert '{"status": "ok"}' in formatted


class TestComplexScenarios:
    """Test complex execution scenarios"""
    
    def test_and_condition_matchers(self):
        """Template with AND condition matchers"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            body='{"openapi": "3.0.1"}',
            duration=0.2
        )
        
        template = NucleiTemplate(
            id='and-test',
            info=TemplateInfo(name='AND Test', author='test', severity=Severity.INFO),
            http_requests=[
                HttpRequest(
                    method='GET',
                    path=['{{BaseURL}}/api-docs'],
                    matchers_condition='and',
                    matchers=[
                        Matcher(type=MatcherType.STATUS, status=[200]),
                        Matcher(type=MatcherType.WORD, words=['"openapi"'], condition='or')
                    ]
                )
            ]
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        result = executor.execute_template(template, 'https://example.com')
        
        assert result.matched is True
    
    def test_stop_at_first_match(self):
        """Template with stop_at_first_match"""
        mock_client = Mock(spec=FridaNetworkClient)
        mock_client.send_request.return_value = FridaResponse(
            status_code=200,
            headers={},
            body='Found',
            duration=0.1
        )
        
        template = NucleiTemplate(
            id='stop-test',
            info=TemplateInfo(name='Stop Test', author='test', severity=Severity.INFO),
            http_requests=[
                HttpRequest(
                    method='GET',
                    path=[
                        '{{BaseURL}}/path1',
                        '{{BaseURL}}/path2',
                        '{{BaseURL}}/path3'
                    ],
                    stop_at_first_match=True,
                    matchers=[Matcher(type=MatcherType.STATUS, status=[200])]
                )
            ]
        )
        
        executor = NucleiExecutor(frida_client=mock_client)
        result = executor.execute_template(template, 'https://example.com')
        
        assert result.matched is True
        # Should stop after first match
        assert mock_client.send_request.call_count == 1
