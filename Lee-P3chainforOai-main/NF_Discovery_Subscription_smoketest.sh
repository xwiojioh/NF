#!/bin/bash

set -u

BASE_URL="${BASE_URL:-http://127.0.0.1:8004}"
SUBSCRIBER_DID="${SUBSCRIBER_DID:-did:oai:gc:amf001}"
FAKE_SUBSCRIBER_DID="${FAKE_SUBSCRIBER_DID:-did:oai:gc:fake001}"
TARGET_NF_TYPE="${TARGET_NF_TYPE:-AUSF}"
TARGET_DID="${TARGET_DID:-did:oai:gc:ausf001}"
CALLBACK_URL="${CALLBACK_URL:-http://127.0.0.1:9000/notifications}"
POLL_INTERVAL_SEC="${POLL_INTERVAL_SEC:-2}"
POLL_MAX_ATTEMPTS="${POLL_MAX_ATTEMPTS:-10}"

PASS_COUNT=0
FAIL_COUNT=0
LAST_SUB_ID=""
CASE_BODY=""

print_title() {
    echo
    echo "=================================================="
    echo "$1"
    echo "=================================================="
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "[PASS] $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "[FAIL] $1"
}

run_case() {
    local name="$1"
    local expected_code="$2"
    shift 2

    local tmp_body
    tmp_body=$(mktemp)

    local status
    status=$(curl -sS -o "$tmp_body" -w "%{http_code}" "$@")

    echo
    echo "--- $name ---"
    echo "HTTP $status"
    cat "$tmp_body"
    echo

    if [ "$status" = "$expected_code" ]; then
        pass "$name"
    else
        fail "$name (expected $expected_code, got $status)"
    fi

    CASE_BODY=$(cat "$tmp_body")
    rm -f "$tmp_body"
}

run_case_multi_code() {
    local name="$1"
    local expected_codes="$2"
    shift 2

    local tmp_body
    tmp_body=$(mktemp)

    local status
    status=$(curl -sS -o "$tmp_body" -w "%{http_code}" "$@")

    echo
    echo "--- $name ---"
    echo "HTTP $status"
    cat "$tmp_body"
    echo

    local matched=1
    local code
    for code in $expected_codes; do
        if [ "$status" = "$code" ]; then
            matched=0
            break
        fi
    done

    if [ "$matched" -eq 0 ]; then
        pass "$name"
    else
        fail "$name (expected one of: $expected_codes, got $status)"
    fi

    CASE_BODY=$(cat "$tmp_body")
    rm -f "$tmp_body"
}

extract_subscription_id() {
    local payload
    payload=$(printf '%s\n' "$1" | sed -n '/^{/,$p')

    if command -v jq >/dev/null 2>&1; then
        printf '%s\n' "$payload" | jq -r '.subscriptionId // .data.subscriptionId // empty' 2>/dev/null
    else
        printf '%s\n' "$payload" | sed -n 's/.*"subscriptionId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
    fi
}

body_contains() {
    local body="$1"
    local pattern="$2"
    printf '%s' "$body" | grep -q "$pattern"
}

wait_for_subscription_status() {
    local sub_id="$1"
    local expected_status="$2"
    local attempt=1

    while [ "$attempt" -le "$POLL_MAX_ATTEMPTS" ]; do
        local tmp_body
        tmp_body=$(mktemp)

        local status
        status=$(curl -sS -o "$tmp_body" -w "%{http_code}" \
            -i "$BASE_URL/nbcf_subscription/v1/subscriptions/$sub_id")
        local body
        body=$(cat "$tmp_body")
        rm -f "$tmp_body"

        echo "[INFO] 轮询第 ${attempt}/${POLL_MAX_ATTEMPTS} 次: HTTP $status"
        echo "$body"

        if [ "$status" = "200" ]; then
            if printf '%s' "$body" | grep -q '"subscriptionId":"'"$sub_id"'"' \
                && printf '%s' "$body" | grep -q '"status":"'"$expected_status"'"'; then
                return 0
            fi
        fi

        if [ "$attempt" -lt "$POLL_MAX_ATTEMPTS" ]; then
            sleep "$POLL_INTERVAL_SEC"
        fi
        attempt=$((attempt + 1))
    done

    return 1
}

print_title "NF Discovery / Subscription Smoke Test"
echo "BASE_URL=$BASE_URL"
echo "SUBSCRIBER_DID=$SUBSCRIBER_DID"
echo "TARGET_NF_TYPE=$TARGET_NF_TYPE"

run_case \
    "D1 Discovery 缺少 target-nf-type" \
    "400" \
    -i "$BASE_URL/nbcf_discovery/v1/nf-instances"

run_case \
    "D2 Discovery 查询 AUSF" \
    "200" \
    -i "$BASE_URL/nbcf_discovery/v1/nf-instances?target-nf-type=$TARGET_NF_TYPE"

run_case \
    "S1 Subscription 创建缺少 targetNfType" \
    "400" \
    -i -X POST "$BASE_URL/nbcf_subscription/v1/subscriptions" \
    -H "Content-Type: application/json" \
    -d '{"subscriberDid":"'"$SUBSCRIBER_DID"'"}'

run_case_multi_code \
    "S2 Subscription 创建正常" \
    "201 202" \
    -i -X POST "$BASE_URL/nbcf_subscription/v1/subscriptions" \
    -H "Content-Type: application/json" \
    -d '{
      "subscriberDid":"'"$SUBSCRIBER_DID"'",
      "targetNfType":"'"$TARGET_NF_TYPE"'",
      "targetDid":"'"$TARGET_DID"'",
      "callbackUrl":"'"$CALLBACK_URL"'",
      "eventTypes":["NF_REGISTERED","NF_STATUS_CHANGED"]
    }'

LAST_SUB_ID=$(extract_subscription_id "$CASE_BODY")
if [ -n "$LAST_SUB_ID" ]; then
    pass "提取 subscriptionId 成功: $LAST_SUB_ID"
else
    fail "提取 subscriptionId 失败，后续删除用例可能无法执行"
fi

if [ -n "$LAST_SUB_ID" ]; then
    if body_contains "$CASE_BODY" '"status":"PENDING"'; then
        if wait_for_subscription_status "$LAST_SUB_ID" "ACTIVE"; then
            pass "S2 创建后轮询确认订阅变为 ACTIVE"
        else
            fail "S2 创建后轮询未观察到订阅变为 ACTIVE"
        fi
    elif body_contains "$CASE_BODY" '"status":"ACTIVE"'; then
        pass "S2 创建返回即为 ACTIVE"
    else
        fail "S2 创建响应未包含可识别状态"
    fi
fi

if [ -n "$LAST_SUB_ID" ]; then
    run_case \
        "Q3 按 subscriptionId 查询当前订阅" \
        "200" \
        -i "$BASE_URL/nbcf_subscription/v1/subscriptions/$LAST_SUB_ID"
fi

run_case \
    "Q1 Subscription 查询缺少 subscriber-did" \
    "400" \
    -i "$BASE_URL/nbcf_subscription/v1/subscriptions"

run_case \
    "Q2 Subscription 查询当前订阅人" \
    "200" \
    -i "$BASE_URL/nbcf_subscription/v1/subscriptions?subscriber-did=$SUBSCRIBER_DID"

if [ -n "$LAST_SUB_ID" ]; then
    run_case \
        "R1 非订阅拥有者删除" \
        "403" \
        -i -X DELETE "$BASE_URL/nbcf_subscription/v1/subscriptions/$LAST_SUB_ID?subscriber-did=$FAKE_SUBSCRIBER_DID"

    run_case_multi_code \
        "R2 订阅拥有者删除" \
        "200 202" \
        -i -X DELETE "$BASE_URL/nbcf_subscription/v1/subscriptions/$LAST_SUB_ID?subscriber-did=$SUBSCRIBER_DID"

    if body_contains "$CASE_BODY" '"status":"PENDING"'; then
        if wait_for_subscription_status "$LAST_SUB_ID" "INACTIVE"; then
            pass "R2 删除后轮询确认订阅变为 INACTIVE"
        else
            fail "R2 删除后轮询未观察到订阅变为 INACTIVE"
        fi
    elif body_contains "$CASE_BODY" '"status":"INACTIVE"'; then
        pass "R2 删除返回即为 INACTIVE"
    else
        fail "R2 删除响应未包含可识别状态"
    fi

    run_case \
        "R3 删除后再次查询" \
        "200" \
        -i "$BASE_URL/nbcf_subscription/v1/subscriptions?subscriber-did=$SUBSCRIBER_DID"

    if printf '%s' "$CASE_BODY" | grep -q '"subscriptionId":"'"$LAST_SUB_ID"'"' \
        && printf '%s' "$CASE_BODY" | grep -q '"status":"INACTIVE"'; then
        pass "R3 查询确认目标订阅已为 INACTIVE"
    else
        fail "R3 查询未确认目标订阅为 INACTIVE"
    fi

    run_case \
        "R4 按 subscriptionId 查询删除后的订阅" \
        "200" \
        -i "$BASE_URL/nbcf_subscription/v1/subscriptions/$LAST_SUB_ID"

    if printf '%s' "$CASE_BODY" | grep -q '"subscriptionId":"'"$LAST_SUB_ID"'"' \
        && printf '%s' "$CASE_BODY" | grep -q '"status":"INACTIVE"'; then
        pass "R4 单条查询确认目标订阅已为 INACTIVE"
    else
        fail "R4 单条查询未确认目标订阅为 INACTIVE"
    fi
else
    fail "跳过删除相关测试，因为没有拿到 subscriptionId"
fi

print_title "测试完成"
echo "PASS: $PASS_COUNT"
echo "FAIL: $FAIL_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi

exit 0