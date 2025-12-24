# Configuration Reference

Complete reference for Intrascan CLI options and configuration.

## Command Line Options

### Required Options

| Option | Short | Description |
|--------|-------|-------------|
| `--template PATH` | `-t` | Path to template file or directory |
| `--url URL` | `-u` | Target base URL |
| `--app BUNDLE_ID` | `-a` | iOS/Android app bundle identifier |

### Request Options

| Option | Short | Description |
|--------|-------|-------------|
| `--header HEADER:VALUE` | `-H` | Custom header to include in all requests (can be used multiple times) |

### Filtering Options

| Option | Description |
|--------|-------------|
| `--severity LEVEL` | Filter by severity. Repeatable. Values: `info`, `low`, `medium`, `high`, `critical` |
| `--tags TAGS` | Include only templates with these tags (comma-separated) |
| `--exclude-tags TAGS` | Exclude templates with these tags (comma-separated) |
| `--limit N` | Maximum number of templates to process |

### Output Options

| Option | Short | Description |
|--------|-------|-------------|
| `--output FILE` | `-o` | Save results to JSON file |
| `--store-responses DIR` | | Directory to save request/response pairs for matches |
| `--log-file FILE` | | Save detailed request/response log to file |
| `--verbose` | `-v` | Print detailed output to console |
| `--silent` | | Suppress banner and progress messages |
| `--no-color` | | Disable colored output |

### Network Options

| Option | Description | Default |
|--------|-------------|---------|
| `--rate-limit N` | Maximum requests per second | 10 |
| `--timeout SECONDS` | Request timeout | 30 |
| `--delay SECONDS` | Additional delay between requests | 0 |
| `--skip-preflight` | Skip initial connectivity check | false |

### Advanced Options

| Option | Description |
|--------|-------------|
| `--script PATH` | Custom Frida JavaScript file |

## Usage Examples

### Basic Scan

```bash
intrascan -t template.yaml -u https://api.example.com -a com.example.app
```

### Severity Filtering

```bash
# Only critical and high severity
intrascan -t templates/ -u https://api.example.com -a com.example.app \
    -s critical -s high
```

### Tag Filtering

```bash
# Include specific tags
intrascan -t nuclei-templates/http/ -u https://api.example.com -a com.example.app \
    --tags "swagger,api,exposure"

# Exclude certain tags
intrascan -t nuclei-templates/http/ -u https://api.example.com -a com.example.app \
    --exclude-tags "intrusive,dos"
```

### Output Configuration

```bash
# JSON output
intrascan -t templates/ -u https://api.example.com -a com.example.app \
    -o results.json

# Store request/response for matches
intrascan -t templates/ -u https://api.example.com -a com.example.app \
    --store-responses ./findings/
```

### Rate Limiting

```bash
# Slow scan (2 requests per second)
intrascan -t templates/ -u https://api.example.com -a com.example.app \
    --rate-limit 2 --delay 0.5
```

### Verbose/Debug Mode

```bash
intrascan -t template.yaml -u https://api.example.com -a com.example.app -v
```

### Silent Mode

```bash
# No banner, minimal output
intrascan -t templates/ -u https://api.example.com -a com.example.app \
    --silent -o results.json
```

## Output Formats

### Console Output

```
  _       _                                  
 (_)_ __ | |_ _ __ __ _ ___  ___ __ _ _ __  
 | | '_ \| __| '__/ _` / __|/ __/ _` | '_ \ 
 | | | | | |_| | | (_| \__ \ (_| (_| | | | |
 |_|_| |_|\__|_|  \__,_|___/\___\__,_|_| |_|
Mobile app security scanner powered by Nuclei + Frida

[*] Connecting to com.example.app...
[+] Connected
[*] Loading templates from: templates/
[*] Logging to: intrascan_20241224_120000.log
Preflight check: https://api.example.com
[+] Preflight OK: HTTP 200 (0.15s)

[info] [swagger-detect] [http] https://api.example.com/swagger.json [3.0.1]
[high] [admin-panel] [http] https://api.example.com/admin

============================================================
Scan completed in 5.23s
Templates tested: 50
Findings: 2
By severity: info: 1, high: 1
============================================================
```

### JSON Output

```json
[
  {
    "template_id": "swagger-detect",
    "template_name": "Swagger API Detection",
    "severity": "info",
    "matched": true,
    "target_url": "https://api.example.com",
    "matched_at": "https://api.example.com/swagger.json",
    "extracted": ["3.0.1"],
    "response_time": 0.234
  }
]
```

### Log File

Each scan creates a timestamped log file:

```
intrascan_20241224_120000.log
```

Contents:
```
=== Intrascan Log - 2024-12-24T12:00:00 ===

Preflight check: https://api.example.com
[+] Preflight OK: HTTP 200 (0.15s)

--- REQUEST [swagger-detect] ---
URL: https://api.example.com/swagger.json
Method: GET
GET https://api.example.com/swagger.json HTTP/1.1
Host: api.example.com

--- RESPONSE [swagger-detect] ---
Status: 200
Duration: 0.23s
Body length: 15234 bytes
Content-Type: application/json
...
```

## Environment Variables

Currently, Intrascan does not use environment variables. All configuration is via CLI.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (may have findings) |
| 1 | Error (connection failed, invalid args, etc.) |

## Tips

### Optimize Large Scans

```bash
# Limit templates and increase timeout
intrascan -t nuclei-templates/http/ -u https://target.com -a com.app \
    --limit 100 --timeout 60 --rate-limit 5
```

### Debug Connection Issues

```bash
# Verbose mode shows all details
intrascan -t test.yaml -u https://target.com -a com.app -v
```

### CI/CD Integration

```bash
# Silent mode with JSON output
intrascan -t templates/ -u $TARGET_URL -a $APP_BUNDLE \
    --silent -o results.json

# Check for findings
if [ -s results.json ]; then
    echo "Vulnerabilities found!"
    exit 1
fi
```
