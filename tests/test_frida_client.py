"""
Tests for FridaNetworkClient using mocks.

These tests mock the frida library to test client logic without
requiring a real Frida connection.
"""
import pytest
import queue
import time
from unittest.mock import Mock, patch, MagicMock
from intrascan.frida_client import FridaNetworkClient, RateLimitConfig
from intrascan.models import FridaResponse


class TestRateLimitConfig:
    """Test RateLimitConfig dataclass"""
    
    def test_default_values(self):
        """Default rate limit config"""
        config = RateLimitConfig()
        assert config.requests_per_second == 10.0
        assert config.delay_between_requests == 0.0
        assert config.timeout == 30.0
    
    def test_custom_values(self):
        """Custom rate limit config"""
        config = RateLimitConfig(
            requests_per_second=5.0,
            delay_between_requests=0.5,
            timeout=60.0
        )
        assert config.requests_per_second == 5.0
        assert config.delay_between_requests == 0.5
        assert config.timeout == 60.0
    
    def test_min_interval_from_rate(self):
        """Min interval calculated from requests per second"""
        config = RateLimitConfig(requests_per_second=2.0, delay_between_requests=0.0)
        assert config.min_interval == 0.5  # 1/2 = 0.5
    
    def test_min_interval_from_delay(self):
        """Min interval from explicit delay when larger"""
        config = RateLimitConfig(requests_per_second=10.0, delay_between_requests=1.0)
        assert config.min_interval == 1.0  # delay is larger than 0.1
    
    def test_min_interval_uses_max(self):
        """Min interval is max of rate-based and delay"""
        config = RateLimitConfig(requests_per_second=1.0, delay_between_requests=0.5)
        assert config.min_interval == 1.0  # 1/1 = 1.0 > 0.5


class TestFridaNetworkClientInit:
    """Test FridaNetworkClient initialization"""
    
    def test_init_basic(self):
        """Basic initialization"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        assert client.app_bundle == "com.test.app"
        assert client.script_path is None
        assert client.platform == "ios"
        assert isinstance(client.rate_limit, RateLimitConfig)
        assert client.is_connected is False
    
    def test_init_with_custom_script(self):
        """Initialization with custom script path"""
        client = FridaNetworkClient(
            app_bundle="com.test.app",
            script_path="/path/to/script.js"
        )
        assert client.script_path == "/path/to/script.js"
    
    def test_init_with_rate_limit(self):
        """Initialization with custom rate limit"""
        config = RateLimitConfig(requests_per_second=5.0)
        client = FridaNetworkClient(
            app_bundle="com.test.app",
            rate_limit=config
        )
        assert client.rate_limit.requests_per_second == 5.0
    
    def test_init_android_platform(self):
        """Initialization for Android platform"""
        client = FridaNetworkClient(
            app_bundle="com.test.android.app",
            platform="android"
        )
        assert client.platform == "android"


class TestFridaNetworkClientConnect:
    """Test connection logic"""
    
    @patch('intrascan.frida_client.frida')
    def test_connect_success(self, mock_frida):
        """Successful connection"""
        # Setup mocks
        mock_device = MagicMock()
        mock_device.spawn.return_value = 1234
        mock_session = MagicMock()
        mock_script = MagicMock()
        
        mock_frida.get_usb_device.return_value = mock_device
        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        
        client = FridaNetworkClient(app_bundle="com.test.app")
        
        with patch.object(client, '_get_script_code', return_value="test script"):
            with patch('time.sleep'):  # Skip sleep
                result = client.connect()
        
        assert result is True
        assert client.is_connected is True
        mock_device.spawn.assert_called_once_with(["com.test.app"])
        mock_device.attach.assert_called_once_with(1234)
        mock_script.load.assert_called_once()
        mock_device.resume.assert_called_once_with(1234)
    
    @patch('intrascan.frida_client.frida')
    def test_connect_generic_exception(self, mock_frida):
        """Handle generic connection exception"""
        mock_frida.get_usb_device.side_effect = Exception("Generic error")
        
        # Also mock the exception types so they don't cause issues
        mock_frida.ServerNotRunningError = type('ServerNotRunningError', (Exception,), {})
        mock_frida.ProcessNotFoundError = type('ProcessNotFoundError', (Exception,), {})
        
        client = FridaNetworkClient(app_bundle="com.test.app")
        
        with pytest.raises(ConnectionError) as exc_info:
            client.connect()
        
        assert "Failed to connect" in str(exc_info.value)


class TestFridaNetworkClientSendRequest:
    """Test request sending logic"""
    
    def test_send_request_not_connected(self):
        """Send request when not connected"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        
        response = client.send_request({'method': 'GET', 'url': 'http://test.com'})
        
        assert response.status_code == 0
        assert response.error == 'Not connected'
    
    def test_send_request_with_response(self):
        """Send request and receive response"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        
        # Mock script.post to add response to queue
        def mock_post(msg):
            client.response_queue.put({
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': '{"success": true}',
                'duration': 0.5
            })
        
        client.script = MagicMock()
        client.script.post = mock_post
        
        response = client.send_request({'method': 'GET', 'url': 'http://test.com'}, timeout=5)
        
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        assert response.body == '{"success": true}'
        assert response.duration == 0.5
    
    def test_send_request_status_as_string(self):
        """Status code as string is converted to int"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        
        def mock_post(msg):
            client.response_queue.put({
                'status_code': '404',  # String!
                'headers': {},
                'body': 'Not Found',
                'duration': 0.1
            })
        
        client.script = MagicMock()
        client.script.post = mock_post
        
        response = client.send_request({'method': 'GET', 'url': 'http://test.com'}, timeout=5)
        
        assert response.status_code == 404
        assert isinstance(response.status_code, int)
    
    def test_send_request_timeout(self):
        """Request timeout"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        client.script = MagicMock()  # Don't add anything to queue
        
        response = client.send_request(
            {'method': 'GET', 'url': 'http://test.com'},
            timeout=0.1  # Very short timeout
        )
        
        assert response.status_code == 0
        assert response.error == 'Request timeout'
    
    def test_send_request_with_null_status(self):
        """Handle null status code"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        
        def mock_post(msg):
            client.response_queue.put({
                'status_code': None,
                'headers': {},
                'body': ''
            })
        
        client.script = MagicMock()
        client.script.post = mock_post
        
        response = client.send_request({'method': 'GET', 'url': 'http://test.com'}, timeout=5)
        
        assert response.status_code == 0
    
    def test_send_request_missing_fields(self):
        """Handle response with missing fields"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        
        def mock_post(msg):
            client.response_queue.put({'status_code': 200})
        
        client.script = MagicMock()
        client.script.post = mock_post
        
        response = client.send_request({'method': 'GET', 'url': 'http://test.com'}, timeout=5)
        
        assert response.status_code == 200
        assert response.headers == {}
        assert response.body == ''
        assert response.error is None


class TestFridaNetworkClientMessageHandler:
    """Test message handler"""
    
    def test_on_message_send_type(self):
        """Handle 'send' message type"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        
        message = {
            'type': 'send',
            'payload': {'status_code': 200, 'body': 'test'}
        }
        
        client._on_message(message, None)
        
        # Check response was queued
        assert not client.response_queue.empty()
        resp = client.response_queue.get_nowait()
        assert resp['status_code'] == 200
    
    def test_on_message_send_json_string(self):
        """Handle 'send' with JSON string payload"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        
        message = {
            'type': 'send',
            'payload': '{"status_code": 201, "body": "created"}'
        }
        
        client._on_message(message, None)
        
        resp = client.response_queue.get_nowait()
        assert resp['status_code'] == 201
    
    def test_on_message_error_type(self, capsys):
        """Handle 'error' message type"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        
        message = {
            'type': 'error',
            'stack': 'Error: Something went wrong\n  at line 1'
        }
        
        client._on_message(message, None)
        
        captured = capsys.readouterr()
        assert 'Frida Error' in captured.out
    
    def test_on_message_invalid_json(self):
        """Handle invalid JSON in payload"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        
        message = {
            'type': 'send',
            'payload': 'not valid json {'
        }
        
        # Should not crash
        client._on_message(message, None)
        
        # Queue should be empty (payload wasn't valid)
        assert client.response_queue.empty()


class TestFridaNetworkClientRateLimiting:
    """Test rate limiting behavior"""
    
    def test_rate_limit_config_applied(self):
        """Rate limit config is properly applied"""
        config = RateLimitConfig(requests_per_second=2.0)
        client = FridaNetworkClient(app_bundle="com.test.app", rate_limit=config)
        
        assert client.rate_limit.min_interval == 0.5
    
    def test_first_request_no_wait(self):
        """First request does not wait (last_request_time is 0)"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        assert client._last_request_time == 0
        
        # _wait_for_rate_limit should not sleep on first call
        start = time.time()
        client._wait_for_rate_limit()
        duration = time.time() - start
        
        assert duration < 0.1  # Should be nearly instant


class TestFridaNetworkClientDisconnect:
    """Test disconnect behavior"""
    
    def test_disconnect(self):
        """Disconnect cleans up resources"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        client.session = MagicMock()
        client.script = MagicMock()
        client.device = MagicMock()
        
        client.disconnect()
        
        assert client.is_connected is False
        assert client.session is None
        assert client.script is None
        assert client.device is None
    
    def test_disconnect_handles_session_error(self):
        """Disconnect handles session detach error"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        client.session = MagicMock()
        client.session.detach.side_effect = Exception("Detach failed")
        
        # Should not raise
        client.disconnect()
        
        assert client.is_connected is False


class TestFridaNetworkClientContextManager:
    """Test context manager protocol"""
    
    @patch('intrascan.frida_client.frida')
    def test_context_manager(self, mock_frida):
        """Use client as context manager"""
        mock_device = MagicMock()
        mock_device.spawn.return_value = 1234
        mock_session = MagicMock()
        mock_script = MagicMock()
        
        mock_frida.get_usb_device.return_value = mock_device
        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        
        with patch('time.sleep'):
            with FridaNetworkClient(app_bundle="com.test.app") as client:
                assert client.is_connected is True
        
        # After exit, should be disconnected
        assert client.is_connected is False


class TestFridaNetworkClientScriptCode:
    """Test script code loading"""
    
    def test_default_script(self):
        """Use default script when no path provided"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        code = client._get_script_code()
        
        assert 'httpRequest' in code
        assert 'NSURLSession' in code
    
    def test_custom_script(self, tmp_path):
        """Load custom script from file"""
        script_file = tmp_path / "custom.js"
        script_file.write_text("// Custom script\nfunction test() {}")
        
        client = FridaNetworkClient(
            app_bundle="com.test.app",
            script_path=str(script_file)
        )
        code = client._get_script_code()
        
        assert 'Custom script' in code
        assert 'function test' in code


class TestFridaResponseEdgeCases:
    """Additional edge case tests for response handling"""
    
    def test_response_with_error(self):
        """Response with error field"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        
        def mock_post(msg):
            client.response_queue.put({
                'status_code': 0,
                'headers': {},
                'body': '',
                'error': 'Connection refused'
            })
        
        client.script = MagicMock()
        client.script.post = mock_post
        
        response = client.send_request({'method': 'GET', 'url': 'http://test.com'}, timeout=5)
        
        assert response.error == 'Connection refused'
    
    def test_response_with_binary_marker(self):
        """Response with binary data marker"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        
        def mock_post(msg):
            client.response_queue.put({
                'status_code': 200,
                'headers': {'Content-Type': 'application/octet-stream'},
                'body': '[Binary data: 4096 bytes]',
                'duration': 0.2
            })
        
        client.script = MagicMock()
        client.script.post = mock_post
        
        response = client.send_request({'method': 'GET', 'url': 'http://test.com'}, timeout=5)
        
        assert 'Binary data' in response.body
        assert response.status_code == 200
    
    def test_response_with_unicode(self):
        """Response with unicode content"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        
        def mock_post(msg):
            client.response_queue.put({
                'status_code': 200,
                'headers': {'Content-Type': 'text/html; charset=utf-8'},
                'body': '<html><body>日本語コンテンツ 🎉</body></html>',
                'duration': 0.1
            })
        
        client.script = MagicMock()
        client.script.post = mock_post
        
        response = client.send_request({'method': 'GET', 'url': 'http://test.com'}, timeout=5)
        
        assert '日本語' in response.body
        assert '🎉' in response.body
    
    def test_large_response_body(self):
        """Handle large response body"""
        client = FridaNetworkClient(app_bundle="com.test.app")
        client._connected = True
        
        large_body = 'A' * 100000  # 100KB
        def mock_post(msg):
            client.response_queue.put({
                'status_code': 200,
                'headers': {},
                'body': large_body
            })
        
        client.script = MagicMock()
        client.script.post = mock_post
        
        response = client.send_request({'method': 'GET', 'url': 'http://test.com'}, timeout=5)
        
        assert len(response.body) == 100000
