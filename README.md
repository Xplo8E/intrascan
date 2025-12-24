# Intrascan

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Mobile app security scanner that runs Nuclei templates via Frida network injection.**

Intrascan enables security scanning of iOS/Android applications by injecting HTTP requests directly from within the app's context, bypassing SSL pinning and VPN tunnels.

## 🌟 Key Features

- 🔒 **Bypass SSL Pinning** - Requests originate from within the app's network stack
- 🌐 **VPN Passthrough** - Access internal networks the app is connected to
- 📋 **Nuclei Compatible** - Uses standard [Nuclei](https://github.com/projectdiscovery/nuclei) YAML templates

## 📦 Installation

```bash
# Prerequisites: Frida server running on target device

# Activate your frida environment
source /path/to/frida-env/bin/activate

# Install in development mode
pip install -e .
```

### Requirements

- Python 3.10+
- [Frida](https://frida.re/) and frida-tools
- iOS/Android device with frida-server running
- USB connection to device

## 🚀 Quick Start

```bash
# Basic scan with single template
intrascan -t template.yaml -u https://target.com -a com.app.bundle

# Scan with Nuclei templates directory
intrascan -t ~/nuclei-templates/http/technologies/ \
    -u https://target.com -a com.app.bundle \
    -s info -s low --limit 50

# Full scan with output
intrascan -t ~/nuclei-templates/http/ \
    -u https://internal-api.company.com -a com.company.app \
    -o results.json --store-responses ./findings/ -v
```

## 📖 Documentation

- [How It Works](docs/how-it-works.md) - Architecture and flow
- [Writing Templates](docs/templates.md) - Template format guide
- [Configuration](docs/configuration.md) - CLI options reference

## 🎯 Use Cases

1. **Internal API Testing** - Test APIs only accessible via mobile app VPN
2. **SSL Pinned Apps** - Scan apps with certificate pinning

## ⚙️ CLI Options

| Option | Description |
|--------|-------------|
| `-t, --template` | Template file or directory (required) |
| `-u, --url` | Target base URL (required) |
| `-a, --app` | iOS/Android app bundle ID (required) |
| `-H, --header` | Custom header (header:value format, can use multiple times) |
| `-s, --severity` | Filter by severity (comma-separated: critical,high,medium,low,info) |
| `--tags` | Include templates with these tags (comma-separated) |
| `--exclude-tags` | Exclude templates with these tags (comma-separated) |
| `--limit` | Maximum templates to process |
| `-o, --output` | Save results to JSON file |
| `--store-responses` | Directory to save request/response pairs for findings |
| `--rate-limit` | Requests per second (default: 10) |
| `--timeout` | Request timeout in seconds (default: 30) |
| `--log-file` | Save detailed log to file |
| `--script` | Custom Frida network script path |
| `--skip-preflight` | Skip connectivity preflight check |
| `-v, --verbose` | Verbose console output |
| `--no-color` | Disable colored output |
| `--silent` | Suppress banner and progress |

## 🧪 Running Tests

```bash
# Run all tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=nuclei_frida --cov-report=html
```

## 🙏 Credits & Acknowledgments

Intrascan is built on the shoulders of giants:

### [ProjectDiscovery](https://github.com/projectdiscovery)

- **[Nuclei](https://github.com/projectdiscovery/nuclei)** - The powerful vulnerability scanner that inspired this tool's template format
- **[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)** - Community-powered vulnerability templates

### [Frida](https://frida.re/)

- Dynamic instrumentation toolkit that makes this tool possible

### Template Format

Intrascan uses the same YAML template format as Nuclei. You can use templates from the [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) repository directly.

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

**Disclaimer**: This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any systems.
