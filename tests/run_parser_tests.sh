#!/usr/bin/env bash
# Test runner for Parser Registry tests
# Run all parser-related tests with coverage

set -e

echo "Running Parser Registry Tests..."
echo "================================"
echo ""

# Activate virtual environment if using uv
if command -v uv &> /dev/null; then
    echo "Using uv for test execution..."
    TEST_CMD="uv run pytest"
else
    TEST_CMD="pytest"
fi

# Unit tests for parser registry
echo "1. Running Parser Registry unit tests..."
$TEST_CMD tests/unit/plugins/parsers/test_registry.py -v

echo ""
echo "2. Running Parser Discovery unit tests..."
$TEST_CMD tests/unit/plugins/parsers/test_discovery.py -v

echo ""
echo "3. Running Parser Integration tests..."
$TEST_CMD tests/integration/plugins/test_parser_integration.py -v

echo ""
echo "================================"
echo "All Parser Registry tests completed!"
echo ""

# Run with coverage report
echo "Generating coverage report..."
$TEST_CMD tests/unit/plugins/parsers/ tests/integration/plugins/test_parser_integration.py \
    --cov=src/gscripts/plugins/parsers \
    --cov-report=html \
    --cov-report=term-missing \
    -v

echo ""
echo "Coverage report generated in htmlcov/index.html"
