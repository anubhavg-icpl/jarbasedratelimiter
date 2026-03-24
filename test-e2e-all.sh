#!/bin/bash
# =============================================================================
# Run All E2E Tests - Both Java 8 and Java 21
# =============================================================================
# Usage: ./test-e2e-all.sh
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXIT_CODE=0

echo "============================================================"
echo "  Running All E2E Tests"
echo "============================================================"
echo ""

echo ">>> Java 8 E2E Tests"
echo "------------------------------------------------------------"
if bash "$SCRIPT_DIR/test-e2e-java8.sh" 8081 5 30; then
    echo ""
    echo ">>> Java 8: ALL PASSED"
else
    echo ""
    echo ">>> Java 8: SOME TESTS FAILED"
    EXIT_CODE=1
fi

echo ""
echo ""

echo ">>> Java 21 E2E Tests"
echo "------------------------------------------------------------"
if bash "$SCRIPT_DIR/test-e2e-java21.sh" 8082 5 30; then
    echo ""
    echo ">>> Java 21: ALL PASSED"
else
    echo ""
    echo ">>> Java 21: SOME TESTS FAILED"
    EXIT_CODE=1
fi

echo ""
echo "============================================================"
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "  ALL E2E TESTS PASSED"
else
    echo "  SOME E2E TESTS FAILED"
fi
echo "============================================================"

exit $EXIT_CODE
