# How Intrascan Works

Intrascan bridges the gap between [Nuclei](https://github.com/projectdiscovery/nuclei) templates and mobile app security testing by using [Frida](https://frida.re/) to inject network requests directly from within the target application.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Your Machine                             │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────┐ │
│  │   Nuclei    │    │  Intrascan   │    │   Frida Python      │ │
│  │  Templates  │───▶│   Engine     │───▶│    Client           │ │
│  │   (.yaml)   │    │              │    │                     │ │
│  └─────────────┘    └──────────────┘    └──────────┬──────────┘ │
└──────────────────────────────────────────────────────┬──────────┘
                                                       │ USB
┌──────────────────────────────────────────────────────┼──────────┐
│                    iOS/Android Device                │          │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                     frida-server                             ││
│  └────────────────────────────┬────────────────────────────────┘│
│                               │                                  │
│  ┌────────────────────────────▼────────────────────────────────┐│
│  │                      Target App                              ││
│  │  ┌──────────────────────────────────────────────────────┐   ││
│  │  │              Injected Frida Script                    │   ││
│  │  │  ┌─────────────────┐    ┌─────────────────────────┐  │   ││
│  │  │  │  Receive HTTP   │    │   Make HTTP Request     │  │   ││
│  │  │  │  Request Spec   │───▶│   via NSURLSession      │  │   ││
│  │  │  │  from Python    │    │   (uses app's certs)    │  │   ││
│  │  │  └─────────────────┘    └───────────┬─────────────┘  │   ││
│  │  └─────────────────────────────────────┼────────────────┘   ││
│  │                                        │                     ││
│  │                                        ▼                     ││
│  │  ┌─────────────────────────────────────────────────────┐    ││
│  │  │              App's Network Stack                     │    ││
│  │  │   • SSL Pinning (bypassed - using app's certs)      │    ││
│  │  │   • VPN Tunnel (requests go through)                │    ││
│  │  │   • Proxy Settings (honored)                        │    ││
│  │  └────────────────────────┬────────────────────────────┘    ││
│  └───────────────────────────┼─────────────────────────────────┘│
└──────────────────────────────┼──────────────────────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Target Server    │
                    │   (internal/public) │
                    └─────────────────────┘
```

## Execution Flow

### 1. Template Discovery & Parsing

```
templates/
├── swagger-detect.yaml
├── tech-detect/
│   ├── nginx-detect.yaml
│   └── apache-detect.yaml
└── cves/
    └── CVE-2023-xxxx.yaml
```

Intrascan discovers all `.yaml` files and parses them into structured template objects:

```python
# Template structure
NucleiTemplate:
    id: "swagger-detect"
    info:
        name: "Swagger API Detection"
        severity: info
        tags: ["swagger", "api"]
    http_requests:
        - method: GET
          path: ["{{BaseURL}}/swagger.json"]
          matchers: [...]
          extractors: [...]
```

### 2. Variable Substitution

Templates use Nuclei-style variables that get substituted:

| Variable | Example Value |
|----------|---------------|
| `{{BaseURL}}` | `https://api.example.com` |
| `{{Hostname}}` | `api.example.com` |
| `{{Host}}` | `api.example.com` |
| `{{Port}}` | `443` |
| `{{Scheme}}` | `https` |
| `{{Path}}` | `/api/v1` |

### 3. Frida Connection

```python
# Connect to device and spawn app
device = frida.get_usb_device()
pid = device.spawn(["com.target.app"])
session = device.attach(pid)

# Inject network script
script = session.create_script(NETWORK_SCRIPT)
script.load()
device.resume(pid)
```

### 4. Request Injection

The injected JavaScript uses the app's native networking APIs:

```javascript
// iOS - Using NSURLSession (app's certificates apply)
function httpRequest(input) {
    const { method, url, headers, body } = input;
    
    const request = NSMutableURLRequest.requestWithURL_(
        NSURL.URLWithString_(url)
    );
    request.setHTTPMethod_(method);
    
    // Uses app's SSL certificates and VPN tunnel
    const session = NSURLSession.sharedSession();
    const task = session.dataTaskWithRequest_completionHandler_(...);
    task.resume();
}
```

### 5. Response Matching

Responses are matched against template matchers:

```yaml
matchers-condition: and
matchers:
  - type: status
    status:
      - 200
      
  - type: word
    words:
      - '"openapi"'
      - '"swagger"'
    condition: or
```

Matcher Types:
- **status** - HTTP status code
- **word** - Substring match
- **regex** - Regular expression
- **dsl** - Expression language (e.g., `len(body) > 100`)
- **binary** - Hex pattern match
- **size** - Response size

### 6. Value Extraction

Extractors pull data from matched responses:

```yaml
extractors:
  - type: regex
    name: version
    regex:
      - '"version"\s*:\s*"([^"]+)"'
```

Extractor Types:
- **regex** - Regular expression with groups
- **kval** - Key-value from headers
- **json** - JSON path query
- **xpath** - XPath query (basic)

## Why Frida?

Traditional security scanners send requests from your machine. This fails when:

1. **SSL Pinning** - App rejects certificates not in its trust store
2. **VPN Tunnel** - Internal APIs only accessible via app's VPN
3. **Client Certificates** - mTLS authentication
4. **IP Restrictions** - Server allows only app's IP ranges

By injecting requests from within the app:
- ✅ SSL pinning is satisfied (using app's certs)
- ✅ VPN tunnel is used automatically
- ✅ Client certs are applied
- ✅ Requests appear to come from the app

## Component Responsibilities

| Component | Purpose |
|-----------|---------|
| `TemplateDiscovery` | Find and filter template files |
| `TemplateParser` | Parse YAML into structured objects |
| `VariableEngine` | Substitute `{{variables}}` |
| `RequestBuilder` | Build HTTP request dicts |
| `FridaNetworkClient` | Manage Frida connection and scripts |
| `MatcherEngine` | Evaluate response matchers |
| `ExtractorEngine` | Extract values from responses |
| `NucleiExecutor` | Orchestrate the full pipeline |
| `OutputFormatter` | Format and display results |

## Rate Limiting

Intrascan includes rate limiting to prevent overwhelming targets:

```python
RateLimitConfig:
    requests_per_second: 10.0  # Max RPS
    delay_between_requests: 0.0  # Additional delay
    timeout: 30.0  # Request timeout
```

## Logging

All requests and responses are logged to a timestamped file:

```
intrascan_20241224_120000.log
```

Contains:
- Full request (method, URL, headers, body)
- Full response (status, headers, body)
- Timing information
- Match results
