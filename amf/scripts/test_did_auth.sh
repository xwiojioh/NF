#!/bin/bash
# Test script for DID Mutual Authentication API
# Usage: ./test_did_auth.sh <amf_host> <amf_port>

AMF_HOST=${1:-"localhost"}
AMF_PORT=${2:-"8080"}
BASE_URL="http://${AMF_HOST}:${AMF_PORT}/nf_auth/v1"

echo "Testing DID Mutual Authentication API"
echo "========================================"
echo "Target: $BASE_URL"
echo ""

# Test 1: Auth Init Request
echo "Test 1: POST /mutual_auth/init"
echo "-------------------------------"

INIT_REQUEST='{
  "initiator_did": "did:oai5gc:test1234567890abcdef",
  "nonce": "0102030405060708091011121314151617181920212223242526272829303132",
  "timestamp": '$(date +%s)',
  "nf_type": "SMF"
}'

echo "Request: $INIT_REQUEST"
echo ""

INIT_RESPONSE=$(curl -s -X POST "${BASE_URL}/mutual_auth/init" \
  -H "Content-Type: application/json" \
  -d "$INIT_REQUEST")

echo "Response: $INIT_RESPONSE"
echo ""

# Extract session_id from response
SESSION_ID=$(echo "$INIT_RESPONSE" | jq -r '.session_id // empty')

if [ -z "$SESSION_ID" ]; then
  echo "Error: Failed to get session_id from init response"
  echo "This is expected if DID Auth is not enabled or BCF is not configured"
  exit 1
fi

echo "Session ID: $SESSION_ID"
echo ""

# Test 2: Auth Status Check
echo "Test 2: GET /status/${SESSION_ID}"
echo "-------------------------------"

STATUS_RESPONSE=$(curl -s -X GET "${BASE_URL}/status/${SESSION_ID}")
echo "Response: $STATUS_RESPONSE"
echo ""

# Test 3: Auth Complete Request (would normally need valid signature)
echo "Test 3: POST /mutual_auth/complete"
echo "-------------------------------"

COMPLETE_REQUEST='{
  "session_id": "'${SESSION_ID}'",
  "initiator_signature": "deadbeef1234567890abcdef"
}'

echo "Request: $COMPLETE_REQUEST"
echo ""

COMPLETE_RESPONSE=$(curl -s -X POST "${BASE_URL}/mutual_auth/complete" \
  -H "Content-Type: application/json" \
  -d "$COMPLETE_REQUEST")

echo "Response: $COMPLETE_RESPONSE"
echo ""

echo "========================================"
echo "Tests completed"
