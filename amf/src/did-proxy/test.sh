#!/bin/bash
################################################################################
# Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The OpenAirInterface Software Alliance licenses this file to You under
# the OAI Public License, Version 1.1  (the "License"); you may not use this file
# except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.openairinterface.org/?page_id=698
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------
# For more information about the OpenAirInterface (OAI) Software Alliance:
#      contact@openairinterface.org
################################################################################

# Test script for DID Proxy Service

set -e

DID_PROXY_HOST="${DID_PROXY_HOST:-localhost}"
DID_PROXY_PORT="${DID_PROXY_PORT:-8090}"
BASE_URL="http://${DID_PROXY_HOST}:${DID_PROXY_PORT}"

echo "============================================"
echo "DID Proxy Service Integration Tests"
echo "============================================"
echo "Target: ${BASE_URL}"
echo ""

# Function to make HTTP requests
http_get() {
    local path=$1
    curl -s -X GET "${BASE_URL}${path}" -H "Accept: application/json"
}

http_post() {
    local path=$1
    curl -s -X POST "${BASE_URL}${path}" -H "Accept: application/json" -H "Content-Type: application/json"
}

# Test 1: Health Check
echo "Test 1: Health Check"
echo "--------------------"
response=$(http_get "/health")
echo "Response: ${response}"
if echo "${response}" | grep -q '"status":"healthy"'; then
    echo "✓ Health check passed"
else
    echo "✗ Health check failed"
    exit 1
fi
echo ""

# Test 2: Get DID
echo "Test 2: Get DID"
echo "---------------"
response=$(http_get "/did-proxy/v1/did")
echo "Response: ${response}"
if echo "${response}" | grep -q '"did":"did:oai5gc:'; then
    echo "✓ DID retrieval passed"
else
    echo "✗ DID retrieval failed"
    exit 1
fi
echo ""

# Test 3: Get DID Document
echo "Test 3: Get DID Document"
echo "------------------------"
response=$(http_get "/did_proxy/v1/did_document")
echo "Response: ${response}"
if echo "${response}" | grep -q '"@context"'; then
    echo "✓ DID Document retrieval passed"
else
    echo "✗ DID Document retrieval failed"
    exit 1
fi
echo ""

# Test 4: Get Extended NF Profile
echo "Test 4: Get Extended NF Profile"
echo "--------------------------------"
response=$(http_get "/did-proxy/v1/profile")
echo "Response: ${response}" | head -c 500
echo "..."
if echo "${response}" | grep -q '"nfType":"AMF"'; then
    echo ""
    echo "✓ Extended NF Profile retrieval passed"
else
    echo ""
    echo "✗ Extended NF Profile retrieval failed"
    exit 1
fi
echo ""

# Test 5: Get Status
echo "Test 5: Get Status"
echo "------------------"
response=$(http_get "/did-proxy/v1/status")
echo "Response: ${response}"
if echo "${response}" | grep -q '"nfInstanceId"'; then
    echo "✓ Status retrieval passed"
else
    echo "✗ Status retrieval failed"
    exit 1
fi
echo ""

# Test 6: BCF Registration (may fail if BCF is not running)
echo "Test 6: BCF Registration (optional)"
echo "------------------------------------"
response=$(http_post "/did-proxy/v1/register" 2>/dev/null || echo '{"error":"BCF not available"}')
echo "Response: ${response}"
if echo "${response}" | grep -q '"status":"registered"'; then
    echo "✓ BCF registration passed"
elif echo "${response}" | grep -q 'error'; then
    echo "⚠ BCF registration skipped (BCF not available)"
else
    echo "⚠ BCF registration status unknown"
fi
echo ""

echo "============================================"
echo "All tests completed!"
echo "============================================"
