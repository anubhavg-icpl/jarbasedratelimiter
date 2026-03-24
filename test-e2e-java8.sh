#!/bin/bash
# =============================================================================
# E2E Test Script - Java 8 Rate Limiting POC
# =============================================================================
# Usage: ./test-e2e-java8.sh [PORT] [PERMIT] [WINDOW]
#   PORT   - Tomcat port (default: 8081)
#   PERMIT - rate.limit.permit value configured (default: 5)
#   WINDOW - rate.limit.windowSeconds value configured (default: 30)
# =============================================================================

set -euo pipefail

PORT="${1:-8081}"
PERMIT="${2:-5}"
WINDOW="${3:-30}"
BASE="http://localhost:${PORT}"
IMAGE="rate-limit-java8-e2e"
CONTAINER="java8-e2e"
PASSED=0
FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

assert_eq() {
    local test_name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo -e "  ${GREEN}PASS${NC} $test_name (expected=$expected, got=$actual)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $test_name (expected=$expected, got=$actual)"
        FAILED=$((FAILED + 1))
    fi
}

assert_contains() {
    local test_name="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        echo -e "  ${GREEN}PASS${NC} $test_name (contains '$expected')"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $test_name (expected to contain '$expected', got '$actual')"
        FAILED=$((FAILED + 1))
    fi
}

assert_not_empty() {
    local test_name="$1" actual="$2"
    if [ -n "$actual" ]; then
        echo -e "  ${GREEN}PASS${NC} $test_name (value=$actual)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $test_name (empty)"
        FAILED=$((FAILED + 1))
    fi
}

echo "==========================================================="
echo "  E2E Test Suite - Java 8 Rate Limiting POC"
echo "  Port: $PORT | Permit: $PERMIT | Window: ${WINDOW}s"
echo "==========================================================="
echo ""

# --- Build and Start ---
echo -e "${YELLOW}[Setup] Building Docker image...${NC}"
docker rm -f "$CONTAINER" 2>/dev/null || true
cd "$(dirname "$0")/rate-limit-java8"

# Temporarily set low limits for testing
cat > src/main/resources/rate-limit.properties <<EOF
rate.limit.mode=IP
rate.limit.permit=${PERMIT}
rate.limit.windowSeconds=${WINDOW}
EOF

docker build -t "$IMAGE" . > /dev/null 2>&1
echo -e "${YELLOW}[Setup] Starting container on port $PORT...${NC}"
docker run -d --name "$CONTAINER" -p "${PORT}:8080" "$IMAGE" > /dev/null
sleep 12

# Verify container is running
if ! docker ps --format '{{.Names}}' | grep -q "$CONTAINER"; then
    echo -e "${RED}FATAL: Container failed to start${NC}"
    docker logs "$CONTAINER" 2>&1 | tail -20
    exit 1
fi
echo ""

# --- Test 1: Basic Response ---
echo "[Test 1] Basic GET response"
BODY=$(curl -X GET -s "$BASE/api/test")
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" "$BASE/api/test")
assert_eq "HTTP status is 200" "200" "$CODE"
assert_contains "Response contains status:ok" "status" "$BODY"
echo ""

# --- Test 2: Requests Within Limit ---
echo "[Test 2] Requests within limit (${PERMIT} total allowed, 2 used above)"
REMAINING=$((PERMIT - 2))
for i in $(seq 1 "$REMAINING"); do
    CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" "$BASE/api/test")
done
assert_eq "Last allowed request is 200" "200" "$CODE"
echo ""

# --- Test 3: Request Over Limit = 429 ---
echo "[Test 3] Request over limit (should be blocked)"
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" "$BASE/api/test")
BODY=$(curl -X GET -s "$BASE/api/test")
assert_eq "Blocked request returns 429" "429" "$CODE"
assert_contains "Response body has error message" "Too many requests" "$BODY"
echo ""

# --- Test 4: Retry-After Header ---
echo "[Test 4] Retry-After header on blocked request"
RETRY_AFTER=$(curl -X GET -s -D - -o /dev/null "$BASE/api/test" 2>/dev/null | grep -i "Retry-After" | tr -d '\r' | awk '{print $2}')
assert_not_empty "Retry-After header present" "$RETRY_AFTER"
echo ""

# --- Test 5: X-Forwarded-For = Separate Counter ---
echo "[Test 5] X-Forwarded-For creates separate rate limit counter"
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 203.0.113.50" "$BASE/api/test")
assert_eq "New IP via X-Forwarded-For gets 200" "200" "$CODE"
echo ""

# --- Test 6: X-Forwarded-For IP Also Gets Rate Limited ---
echo "[Test 6] X-Forwarded-For IP exhaustion"
for i in $(seq 2 "$PERMIT"); do
    curl -X GET -s -o /dev/null -H "X-Forwarded-For: 203.0.113.50" "$BASE/api/test"
done
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 203.0.113.50" "$BASE/api/test")
assert_eq "X-FF IP blocked after limit" "429" "$CODE"
echo ""

# --- Test 7: Different IPs Have Separate Limits ---
echo "[Test 7] Different IPs have independent counters"
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 198.51.100.1" "$BASE/api/test")
assert_eq "Different IP still gets 200" "200" "$CODE"
echo ""

# --- Test 8: Window Reset ---
echo "[Test 8] Window reset after ${WINDOW} seconds"
echo -e "  ${YELLOW}Waiting $((WINDOW + 1)) seconds for window to expire...${NC}"
sleep $((WINDOW + 1))
CODE=$(curl -X GET -s -o /dev/null -w "%{http_code}" "$BASE/api/test")
assert_eq "After window reset, request returns 200" "200" "$CODE"
echo ""

# --- Cleanup ---
echo -e "${YELLOW}[Cleanup] Stopping container...${NC}"
docker rm -f "$CONTAINER" > /dev/null 2>&1

# Restore production config
cat > src/main/resources/rate-limit.properties <<EOF
rate.limit.mode=IP
rate.limit.permit=100
rate.limit.windowSeconds=60
EOF

echo ""
echo "==========================================================="
echo -e "  Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}"
echo "==========================================================="

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
