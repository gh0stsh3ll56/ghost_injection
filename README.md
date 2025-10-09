# Ghost_Injections v2.0

```
╔══════════════════════════════════════════════════════════════╗
║   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗              ║
║  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝              ║
║  ██║  ███╗███████║██║   ██║███████╗   ██║                 ║
║  ██║   ██║██╔══██║██║   ██║╚════██║   ██║                 ║
║  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║                 ║
║                                                              ║
║     ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗        ║
║     ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝        ║
║     ██║██╔██╗ ██║     ██║█████╗  ██║        ██║           ║
║     ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║           ║
║     ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║           ║
║                                                              ║
║        Advanced Command Injection Testing Framework         ║
║                    Ghost Ops Security                        ║
╚══════════════════════════════════════════════════════════════╝
```

**Ghost Ops Security - Professional Penetration Testing Tool**

An extensive, enterprise-grade command injection vulnerability detection framework with 300+ payloads across 30+ categories, multiple detection methods, and intelligent confidence scoring.

## 🎯 Key Features

- **300+ Injection Payloads** across 30+ specialized categories
- **Multi-Method Detection**: Output-based, time-based, error-based, length-based
- **Confidence Scoring**: CRITICAL, HIGH, MEDIUM, LOW classifications
- **Baseline Analysis**: Intelligent time/length deviation detection
- **Session Markers**: Unique per-scan markers for precise detection
- **Evidence Extraction**: Context capture for all findings
- **Multi-threaded Scanning**: Concurrent parameter testing
- **Proxy Integration**: Burp Suite / OWASP ZAP compatibility
- **Comprehensive Reporting**: JSON export with full statistics

## 📦 Installation

```bash
pip install -r requirements.txt
chmod +x ghost_injections.py
```

##  Quick Start

```bash
# Basic GET parameter test
python3 ghost_injections.py -u "http://target.com/ping?host=127.0.0.1" -p host

# POST with multiple parameters
python3 ghost_injections.py -u "http://target.com/api/exec" -m POST -p cmd,input -d "cmd=test&input=value"

# With Burp Suite proxy
python3 ghost_injections.py -u "http://target.com/api" -p param --proxy http://127.0.0.1:8080 -o report.json

# List all payload categories
python3 ghost_injections.py --list-categories
```

## 📋 Usage

### Command Line Options

```
Required:
  -u, --url URL              Target URL
  -p, --params PARAMS        Parameters to test (comma-separated)

Request Config:
  -m, --method METHOD        HTTP method: GET or POST (default: GET)
  -d, --data DATA           POST data (key=value&key2=value2)
  -H, --headers HEADERS     Custom headers ('Header1:Value1,Header2:Value2')
  -c, --cookies COOKIES     Cookies ('name1=value1,name2=value2')
  --user-agent UA           Custom User-Agent

Scan Config:
  --timeout SECONDS         Request timeout (default: 15)
  --delay SECONDS           Delay between requests (default: 0)
  --proxy URL               Proxy URL (http://127.0.0.1:8080)
  -t, --threads N           Concurrent threads (default: 1)

Output:
  -o, --output FILE         JSON report output file
  -v, --verbose             Show all tested payloads

Payloads:
  --categories CATS         Specific categories (comma-separated)
  --list-categories         List all available categories
```

### Advanced Examples

```bash
# Authenticated testing
python3 ghost_injections.py \
  -u "http://target.com/admin/cmd" \
  -p command \
  -H "Authorization:Bearer TOKEN,X-API-Key:secret" \
  -c "session=abc123,auth=valid" \
  --proxy http://127.0.0.1:8080 \
  -v -o scan.json

# Multi-threaded comprehensive scan
python3 ghost_injections.py \
  -u "http://target.com/search" \
  -p q,category,filter,sort \
  -t 5 --delay 0.5 --timeout 20 \
  -o full_scan.json

# Specific payload categories only
python3 ghost_injections.py \
  -u "http://target.com/ping" \
  -p host \
  --categories "time_based_unix_sleep,output_marker_basic,obfuscated_commands"
```

## 🗂️ Payload Categories (30+ Categories, 300+ Payloads)

### Basic Injection
- `basic_unix_semicolon` - Semicolon separators (15)
- `basic_unix_pipe` - Pipe operators (10)
- `basic_unix_or` - OR operators (10)
- `basic_unix_and` - AND operators (12)
- `basic_unix_backticks` - Backtick substitution (10)
- `basic_unix_substitution` - $() substitution (10)
- `basic_windows` - Windows separators (15)

### Time-Based Blind
- `time_based_unix_sleep` - Sleep delays (15)
- `time_based_windows` - Timeout/ping delays (10)

### Output Detection
- `output_marker_basic` - Session markers (10)
- `output_marker_wrapped` - Wrapped markers (8)

### Encoding/Obfuscation
- `url_encoded` - URL encoding (12)
- `double_encoded` - Double encoding (8)
- `unicode_encoded` - Unicode encoding (5)
- `obfuscated_spaces` - Space bypass (12)
- `obfuscated_commands` - Command obfuscation (15)
- `obfuscated_variables` - Variable tricks (8)
- `base64_obfuscation` - Base64 decode execution (5)
- `wildcard_injection` - Wildcard execution (8)
- `concatenation_bypass` - String concat (10)

### Advanced Techniques
- `newline_injection` - Newline-based (15)
- `null_byte` - Null byte injection (8)
- `path_traversal_combo` - Path traversal combo (5)
- `semicolon_variants` - Comment bypass (10)
- `inline_execution` - Inline commands (8)
- `chained_commands` - Multiple chained (8)
- `alternative_execution` - Language interpreters (8)
- `redirection_based` - Output redirection (8)
- `environment_variables` - Env extraction (10)
- `file_read_attempts` - File reads (10)
- `network_based` - Network commands (8)

##  Detection Methods

### 1. Output-Based (Highest Confidence)
- Session-unique markers (CRITICAL confidence)
- UID/GID patterns (CRITICAL confidence)
- File content detection (/etc/passwd)
- Username detection (root, www-data, SYSTEM)
- System paths (multiple occurrences)
- Command output patterns

### 2. Time-Based Blind
- Baseline response time establishment (3 samples)
- Expected delay matching (sleep/timeout/ping)
- Statistical deviation analysis
- Network latency compensation

### 3. Error-Based
- Shell error messages (sh:, bash:)
- Command not found errors
- Permission denied errors
- Syntax error detection
- Multiple language interpreters

### 4. Length-Based Analysis
- Response size baseline comparison
- Significant deviation detection (>20%)
- Combined with other indicators

## 📊 Confidence Levels

- **CRITICAL**: Session marker detected, UID/GID found, file content detected
- **HIGH**: Usernames detected, multiple paths, time delays matched, strong errors
- **MEDIUM**: System info, command patterns, baseline deviations, shell errors
- **LOW**: Length changes, weak indicators (requires manual verification)

## 📈 Report Format

### JSON Output
```json
{
  "scan_info": {
    "tool": "Ghost_Injections v2.0",
    "target": "http://target.com/api",
    "method": "POST",
    "timestamp": "2025-10-07T10:30:00",
    "session_marker": "ABCD1234EFGH",
    "total_payloads_tested": 287
  },
  "results": {
    "total_vulnerabilities": 5,
    "vulnerabilities": [...]
  },
  "statistics": {
    "by_detection_type": {...},
    "by_category": {...},
    "by_confidence": {...},
    "scan_duration": "45.23 seconds"
  }
}
```

### Terminal Output
- Color-coded by confidence (RED=Critical/High, YELLOW=Medium, GREEN=Low)
- Real-time progress tracking
- Evidence excerpts for each finding
- Comprehensive statistics summary

## 🔧 Integration

### Burp Suite
```bash
python3 ghost_injections.py \
  -u "http://target.com/api" \
  -p cmd \
  --proxy http://127.0.0.1:8080 \
  --delay 1 \
  -v
```

Benefits: Intercept/modify requests, verify findings, save to Repeater

### OWASP ZAP
```bash
python3 ghost_injections.py \
  -u "http://target.com/search" \
  -p q \
  --proxy http://127.0.0.1:8080
```

##  Remediation Recommendations

### Input Validation
```python
import re
def validate_input(user_input):
    if not re.match(r'^[a-zA-Z0-9\.\-]+$', user_input):
        raise ValueError("Invalid input")
    return user_input
```

### Avoid Command Execution
```python
# BAD
os.system(f"ping {user_input}")

# GOOD
import subprocess
subprocess.run(['ping', '-c', '4', user_input], 
               capture_output=True, timeout=10)
```

### Additional Controls
- Use parameterized APIs
- Principle of least privilege
- Input length restrictions
- WAF implementation
- Rate limiting
- Command execution monitoring

## ⚠️ Best Practices

### Authorization
- ✅ Always obtain written authorization
- ✅ Verify target is in scope
- ✅ Maintain proper documentation
- ❌ Never test unauthorized systems

### Responsible Testing
- Use `--delay` to avoid DoS
- Test during maintenance windows
- Monitor application behavior
- Generate reports for all scans
- Manually verify all findings

### Documentation
- Use `-o` flag for JSON reports
- Save Burp Suite project files
- Screenshot critical findings
- Note timestamps and system changes

## 📖 Example Workflows

### Quick Assessment
```bash
python3 ghost_injections.py \
  -u "http://target.com/api/ping" \
  -p host,timeout \
  -o initial.json
```

### Deep Dive
```bash
python3 ghost_injections.py \
  -u "http://target.com/admin/diagnostics" \
  -p command,host,options \
  -H "Auth:Bearer TOKEN" \
  --proxy http://127.0.0.1:8080 \
  -t 3 --delay 0.5 \
  -o deep_scan.json -v
```

### Focused Testing
```bash
python3 ghost_injections.py \
  -u "http://target.com/exec" \
  -p cmd \
  --categories "basic_unix_semicolon,time_based_unix_sleep" \
  --proxy http://127.0.0.1:8080
```

##  Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection timeouts | Increase `--timeout` value |
| Rate limiting | Add `--delay` between requests |
| No vulnerabilities | Verify params, check WAF, use `-v`, try proxy |
| SSL errors | Modify code to disable verification (testing only) |

## 📝 Changelog

### Version 2.0
- 300+ payloads (6x increase)
- 30+ categories (10x increase)
- Advanced detection methods
- Confidence scoring
- Baseline establishment
- Evidence extraction
- Session-unique markers
- Enhanced reporting

## 📄 License

**Proprietary - Ghost Ops Security**

Licensed exclusively for Ghost Ops Security professional penetration testing engagements.

## 👥 Credits

**Ghost Ops Security Penetration Testing Team**

---

**Ghost Ops Security - Where Shadows Reveal Vulnerabilities**

*Professional. Thorough. Ethical.*
