# Writing Templates for Intrascan

Intrascan uses the same template format as [Nuclei](https://github.com/projectdiscovery/nuclei) by [ProjectDiscovery](https://github.com/projectdiscovery). You can use templates from the official [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) repository.

## Template Structure

```yaml
id: template-unique-id

info:
  name: Human Readable Name
  author: your-name
  severity: info|low|medium|high|critical
  description: What this template detects
  tags: tag1,tag2,tag3

http:
  - method: GET
    path:
      - "{{BaseURL}}/path/to/check"
    
    matchers:
      - type: status
        status:
          - 200
```

## Basic Example

Detect exposed Swagger documentation:

```yaml
id: swagger-api-detect

info:
  name: Swagger API Documentation
  author: intrascan
  severity: info
  description: Detects exposed Swagger/OpenAPI documentation
  tags: swagger,api,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/swagger.json"
      - "{{BaseURL}}/openapi.json"
      - "{{BaseURL}}/v3/api-docs"
    
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
    
    extractors:
      - type: regex
        name: version
        regex:
          - '"(?:openapi|swagger)"\s*:\s*"([^"]+)"'
```

## Variables

Nuclei-style variables are supported:

| Variable | Description | Example |
|----------|-------------|---------|
| `{{BaseURL}}` | Full base URL | `https://api.example.com:8443/v1` |
| `{{RootURL}}` | Root URL without path | `https://api.example.com:8443` |
| `{{Hostname}}` | Hostname only | `api.example.com` |
| `{{Host}}` | Host with port | `api.example.com:8443` |
| `{{Port}}` | Port number | `8443` |
| `{{Scheme}}` | Protocol | `https` |
| `{{Path}}` | URL path | `/v1` |

## Matchers

### Status Matcher

```yaml
matchers:
  - type: status
    status:
      - 200
      - 201
      - 204
```

### Word Matcher

```yaml
matchers:
  - type: word
    words:
      - "admin"
      - "password"
    condition: or        # or / and (default: or)
    case-insensitive: true
    part: body          # body / header / all
```

### Regex Matcher

```yaml
matchers:
  - type: regex
    regex:
      - "version[\"\\s:]+([0-9]+\\.[0-9]+)"
    part: body
```

### DSL Matcher

```yaml
matchers:
  - type: dsl
    dsl:
      - "status_code == 200"
      - "len(body) > 100"
      - 'contains(body, "error")'
```

### Negative Matcher

```yaml
matchers:
  - type: word
    words:
      - "error"
    negative: true  # Match if word NOT found
```

### Matcher Conditions

Combine multiple matchers:

```yaml
matchers-condition: and  # All matchers must pass
matchers:
  - type: status
    status: [200]
  - type: word
    words: ["success"]
```

```yaml
matchers-condition: or  # Any matcher can pass
matchers:
  - type: status
    status: [200]
  - type: status
    status: [201]
```

## Extractors

### Regex Extractor

```yaml
extractors:
  - type: regex
    name: api-version
    regex:
      - '"version"\s*:\s*"([^"]+)"'
    group: 1  # Which capture group (default: 1)
```

### Key-Value Extractor

```yaml
extractors:
  - type: kval
    name: server
    kval:
      - Server
      - X-Powered-By
```

### JSON Extractor

```yaml
extractors:
  - type: json
    name: user-id
    json:
      - '.data.user.id'
      - '.results[0].id'
```

## Multiple Paths

Test multiple endpoints with one template:

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/admin/"
      - "{{BaseURL}}/administrator"
      - "{{BaseURL}}/wp-admin"
    
    stop-at-first-match: true  # Stop after first match
    
    matchers:
      - type: status
        status:
          - 200
```

## Raw Requests

For complex requests, use raw format:

```yaml
http:
  - raw:
      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json
        
        {"username":"admin","password":"admin"}
    
    matchers:
      - type: word
        words:
          - "token"
          - "session"
```

## POST Requests

```yaml
http:
  - method: POST
    path:
      - "{{BaseURL}}/api/auth"
    
    headers:
      Content-Type: application/json
      X-Custom-Header: value
    
    body: '{"username":"test","password":"test"}'
    
    matchers:
      - type: status
        status:
          - 200
```

## Template Tips

### 1. Use Specific Matchers

```yaml
# Bad - too generic
matchers:
  - type: status
    status: [200]

# Good - specific indicators
matchers-condition: and
matchers:
  - type: status
    status: [200]
  - type: word
    words:
      - "specific-indicator"
```

### 2. Extract Useful Data

```yaml
extractors:
  - type: regex
    name: version
    regex:
      - 'Server:\s*([^\r\n]+)'
    part: header
```

### 3. Use Tags for Organization

```yaml
info:
  tags: cve,rce,critical,apache
```

### 4. Handle False Positives

```yaml
matchers-condition: and
matchers:
  - type: status
    status: [200]
  - type: word
    words:
      - "login failed"
    negative: true  # Must NOT contain this
```

## Using Community Templates

The official Nuclei templates work with Intrascan:

```bash
# Clone templates
git clone https://github.com/projectdiscovery/nuclei-templates

# Use with Intrascan
intrascan -t nuclei-templates/http/technologies/ \
    -u https://target.com -a com.app.bundle
```

## Credits

Template format and concepts are from [ProjectDiscovery's Nuclei](https://github.com/projectdiscovery/nuclei).

For comprehensive template documentation, see:
- [Nuclei Template Guide](https://docs.projectdiscovery.io/templates/introduction)
- [nuclei-templates Repository](https://github.com/projectdiscovery/nuclei-templates)
