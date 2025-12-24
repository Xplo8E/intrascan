"""Frida network client - wrapper for Frida communication"""

import frida
import json
import queue
import time
import threading
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass

from .models import FridaResponse


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    requests_per_second: float = 10.0   # Max requests per second
    delay_between_requests: float = 0.0  # Additional delay in seconds
    timeout: float = 30.0               # Request timeout in seconds
    
    @property
    def min_interval(self) -> float:
        """Minimum interval between requests"""
        return max(1.0 / self.requests_per_second, self.delay_between_requests)


class FridaNetworkClient:
    """Wrapper for Frida network communication with rate limiting"""
    
    # Default iOS network script (quiet mode - no console output)
    DEFAULT_IOS_SCRIPT = """
/**
 * Frida Network Request Script for iOS (Intrascan)
 */
function httpRequest(input) {
    const { method, url, headers, body } = input;

    const NSString = ObjC.classes.NSString;
    const NSURL = ObjC.classes.NSURL;
    const NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    const NSURLSession = ObjC.classes.NSURLSession;

    const nsStr = NSString.stringWithUTF8String_(Memory.allocUtf8String(url));
    const nsURL = NSURL.URLWithString_(nsStr);
    const request = NSMutableURLRequest.requestWithURL_(nsURL);

    request.setHTTPMethod_(NSString.stringWithUTF8String_(Memory.allocUtf8String(method)));

    if (headers && typeof headers === 'object') {
        const headerObj = ObjC.classes.NSMutableDictionary.alloc().init();
        for (const key in headers) {
            const nsKey = NSString.stringWithUTF8String_(Memory.allocUtf8String(key));
            const nsVal = NSString.stringWithUTF8String_(Memory.allocUtf8String(headers[key]));
            headerObj.setObject_forKey_(nsVal, nsKey);
        }
        request.setAllHTTPHeaderFields_(headerObj);
    }

    if (body && ["POST", "PUT", "PATCH"].includes(method.toUpperCase())) {
        const bodyData = NSString.stringWithUTF8String_(Memory.allocUtf8String(body)).dataUsingEncoding_(4);
        request.setHTTPBody_(bodyData);
    }

    const session = NSURLSession.sharedSession();
    const startTime = Date.now();

    const task = session.dataTaskWithRequest_completionHandler_(
        request,
        new ObjC.Block({
            retType: 'void',
            argTypes: ['object', 'object', 'object'],
            implementation: function (data, response, error) {
                const duration = (Date.now() - startTime) / 1000;
                const result = {
                    type: 'response',
                    url: url,
                    method: method,
                    status_code: null,
                    headers: {},
                    body: '',
                    error: null,
                    duration: duration
                };

                if (error && !error.isNull()) {
                    result.error = new ObjC.Object(error).localizedDescription().toString();
                }

                if (response && !response.isNull()) {
                    const res = new ObjC.Object(response);
                    result.status_code = res.statusCode();
                    const hdrs = res.allHeaderFields();
                    const keys = hdrs.allKeys();
                    for (let i = 0; i < keys.count(); i++) {
                        const k = keys.objectAtIndex_(i).toString();
                        const v = hdrs.objectForKey_(keys.objectAtIndex_(i)).toString();
                        result.headers[k] = v;
                    }
                }

                if (data && !data.isNull()) {
                    const nsData = new ObjC.Object(data);
                    const length = nsData.length();
                    try {
                        result.body = nsData.bytes().readUtf8String(length);
                    } catch (e) {
                        result.body = "[Binary data: " + length + " bytes]";
                    }
                }

                send(JSON.stringify(result));
            }
        })
    );
    task.resume();
}

function waitForRequest() {
    recv('request', function onMessage(message) {
        httpRequest(message.payload);
        waitForRequest();
    });
}
waitForRequest();
"""

    def __init__(self, 
                 app_bundle: str,
                 script_path: Optional[str] = None,
                 rate_limit: Optional[RateLimitConfig] = None,
                 platform: str = "ios"):
        """
        Initialize Frida network client
        
        Args:
            app_bundle: iOS app bundle ID (e.g., "com.app.bundle")
            script_path: Path to custom Frida script, or None for default
            rate_limit: Rate limiting configuration
            platform: Target platform ("ios" or "android")
        """
        self.app_bundle = app_bundle
        self.script_path = script_path
        self.platform = platform
        self.rate_limit = rate_limit or RateLimitConfig()
        
        self.device: Optional[frida.core.Device] = None
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.response_queue: queue.Queue = queue.Queue()
        
        self._last_request_time: float = 0
        self._connected: bool = False
        
    def connect(self) -> bool:
        """Connect to device and spawn app"""
        try:
            # Get USB device
            self.device = frida.get_usb_device()
            
            # Spawn the app
            pid = self.device.spawn([self.app_bundle])
            self.session = self.device.attach(pid)
            
            # Load script
            script_code = self._get_script_code()
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)
            self.script.load()
            
            # Resume app
            self.device.resume(pid)
            
            # Wait for app to initialize
            time.sleep(2)
            
            self._connected = True
            return True
            
        except frida.ServerNotRunningError:
            raise ConnectionError("Frida server not running on device. Run: frida-server &")
        except frida.ProcessNotFoundError:
            raise ConnectionError(f"App not found: {self.app_bundle}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect: {e}")
    
    def _get_script_code(self) -> str:
        """Get Frida script code"""
        if self.script_path:
            with open(self.script_path) as f:
                return f.read()
        return self.DEFAULT_IOS_SCRIPT
    
    def _on_message(self, message: dict, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            try:
                payload = message['payload']
                if isinstance(payload, str):
                    resp = json.loads(payload)
                else:
                    resp = payload
                self.response_queue.put(resp)
            except (json.JSONDecodeError, KeyError):
                pass
        elif message['type'] == 'error':
            print(f"[Frida Error] {message.get('stack', message)}")
    
    def _wait_for_rate_limit(self):
        """Wait to respect rate limits"""
        if self._last_request_time > 0:
            elapsed = time.time() - self._last_request_time
            min_interval = self.rate_limit.min_interval
            
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
    
    def send_request(self, request: dict, 
                     timeout: Optional[float] = None) -> FridaResponse:
        """
        Send request and wait for response
        
        Args:
            request: Request dict with method, url, headers, body
            timeout: Request timeout in seconds (uses default if None)
            
        Returns:
            FridaResponse with status_code, headers, body, error
        """
        if not self._connected:
            return FridaResponse(0, {}, '', 'Not connected')
        
        timeout = timeout or self.rate_limit.timeout
        
        # Apply rate limiting
        self._wait_for_rate_limit()
        self._last_request_time = time.time()
        
        # Clear any old responses
        while not self.response_queue.empty():
            try:
                self.response_queue.get_nowait()
            except queue.Empty:
                break
        
        # Send request
        self.script.post({'type': 'request', 'payload': request})
        
        try:
            resp = self.response_queue.get(timeout=timeout)
            # Ensure status_code is int (Frida JS may return it as string)
            status = resp.get('status_code', 0)
            return FridaResponse(
                status_code=int(status) if status else 0,
                headers=resp.get('headers', {}),
                body=resp.get('body', ''),
                error=resp.get('error'),
                duration=resp.get('duration', 0.0),
            )
        except queue.Empty:
            return FridaResponse(0, {}, '', 'Request timeout')
    
    def disconnect(self):
        """Clean up Frida session"""
        self._connected = False
        
        if self.session:
            try:
                self.session.detach()
            except:
                pass
            self.session = None
            
        self.script = None
        self.device = None
    
    @property
    def is_connected(self) -> bool:
        """Check if client is connected"""
        return self._connected
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
