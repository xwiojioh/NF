#!/bin/bash
###############################################################################
# DID Mutual Authentication Test Script
# 
# 此脚本用于测试 AMF 的 DID 双向认证功能
# 使用 Mock BCF 服务器进行测试
#
# 测试流程：
# 1. 启动 Mock BCF 服务器
# 2. AMF 启动并向 BCF 注册（POST /nbcf_nfm/v1/nf_instances）
# 3. 测试 SMF 向 AMF 发起认证请求
# 4. AMF 向 BCF 查询 SMF 公钥（GET /nbcf_did/v1/public_key/{did}）
# 5. AMF 验证签名并返回挑战
###############################################################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 默认配置
MOCK_BCF_HOST="localhost"
MOCK_BCF_PORT="8080"
AMF_HOST="localhost"
AMF_PORT="8080"

# 测试 DID（与 mock_bcf_server.py 中的测试数据匹配）
SMF_DID="did:oai5gc:smf:test001"
UDM_DID="did:oai5gc:udm:test001"
AUSF_DID="did:oai5gc:ausf:test001"

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# 显示帮助信息
show_help() {
    echo "DID Mutual Authentication Test Script"
    echo ""
    echo "Usage: $0 [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  check-bcf           检查 Mock BCF 服务器状态"
    echo "  start-bcf           启动 Mock BCF 服务器（后台运行）"
    echo "  stop-bcf            停止 Mock BCF 服务器"
    echo "  test-register-nf    测试 NF 注册到 BCF"
    echo "  test-query-pubkey   测试公钥查询（双向认证核心接口）"
    echo "  test-nf-discovery   测试 NF 发现"
    echo "  test-auth-init      测试认证初始化 (向 AMF 发起认证)"
    echo "  test-auth-flow      展示完整认证流程"
    echo "  all                 运行所有测试"
    echo ""
    echo "Options:"
    echo "  --bcf-host HOST   设置 Mock BCF 主机地址 (默认: $MOCK_BCF_HOST)"
    echo "  --bcf-port PORT   设置 Mock BCF 端口 (默认: $MOCK_BCF_PORT)"
    echo "  --amf-host HOST   设置 AMF 主机地址 (默认: $AMF_HOST)"
    echo "  --amf-port PORT   设置 AMF 端口 (默认: $AMF_PORT)"
    echo "  -h, --help        显示帮助信息"
    echo ""
    echo "Examples:"
    echo "  $0 start-bcf                    # 启动 Mock BCF 服务器"
    echo "  $0 check-bcf                    # 检查服务器状态"
    echo "  $0 test-bcf-query               # 测试公钥查询"
    echo "  $0 --amf-host 192.168.70.132 test-auth-init  # 测试认证初始化"
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --bcf-host)
                MOCK_BCF_HOST="$2"
                shift 2
                ;;
            --bcf-port)
                MOCK_BCF_PORT="$2"
                shift 2
                ;;
            --amf-host)
                AMF_HOST="$2"
                shift 2
                ;;
            --amf-port)
                AMF_PORT="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                COMMAND="$1"
                shift
                ;;
        esac
    done
}

# 检查 Mock BCF 服务器状态
check_bcf() {
    log_info "检查 Mock BCF 服务器状态..."
    
    if curl -s "http://${MOCK_BCF_HOST}:${MOCK_BCF_PORT}/health" > /dev/null 2>&1; then
        log_success "Mock BCF 服务器正在运行 (${MOCK_BCF_HOST}:${MOCK_BCF_PORT})"
        
        # 获取统计信息
        stats=$(curl -s "http://${MOCK_BCF_HOST}:${MOCK_BCF_PORT}/stats")
        echo "服务器统计: $stats"
        return 0
    else
        log_error "Mock BCF 服务器未运行或无法连接"
        return 1
    fi
}

# 启动 Mock BCF 服务器
start_bcf() {
    log_info "启动 Mock BCF 服务器..."
    
    # 检查是否已运行
    if check_bcf > /dev/null 2>&1; then
        log_warning "Mock BCF 服务器已在运行"
        return 0
    fi
    
    # 找到脚本目录
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # 检查 Python 脚本是否存在
    if [[ ! -f "${SCRIPT_DIR}/mock_bcf_server.py" ]]; then
        log_error "找不到 mock_bcf_server.py"
        return 1
    fi
    
    # 启动服务器（后台运行）
    cd "${SCRIPT_DIR}"
    nohup python3 mock_bcf_server.py --port "${MOCK_BCF_PORT}" > mock_bcf.log 2>&1 &
    BCF_PID=$!
    echo $BCF_PID > mock_bcf.pid
    
    # 等待服务器启动
    sleep 2
    
    if check_bcf > /dev/null 2>&1; then
        log_success "Mock BCF 服务器已启动 (PID: $BCF_PID)"
    else
        log_error "Mock BCF 服务器启动失败，请查看 mock_bcf.log"
        return 1
    fi
}

# 停止 Mock BCF 服务器
stop_bcf() {
    log_info "停止 Mock BCF 服务器..."
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PID_FILE="${SCRIPT_DIR}/mock_bcf.pid"
    
    if [[ -f "$PID_FILE" ]]; then
        BCF_PID=$(cat "$PID_FILE")
        if kill -0 "$BCF_PID" 2>/dev/null; then
            kill "$BCF_PID"
            rm -f "$PID_FILE"
            log_success "Mock BCF 服务器已停止 (PID: $BCF_PID)"
        else
            log_warning "进程 $BCF_PID 不存在"
            rm -f "$PID_FILE"
        fi
    else
        # 尝试通过进程名杀死
        pkill -f "mock_bcf_server.py" 2>/dev/null && \
            log_success "Mock BCF 服务器已停止" || \
            log_warning "找不到运行中的 Mock BCF 服务器"
    fi
}

# 测试 BCF 公钥查询接口（双向认证核心）
test_query_pubkey() {
    log_info "测试 BCF 公钥查询接口..."
    log_info "这是双向认证的核心接口：NF 收到认证请求时，需要向 BCF 查询对方公钥来验证签名"
    
    echo ""
    log_step "1. 查询 SMF 公钥 ($SMF_DID)..."
    response=$(curl -s "http://${MOCK_BCF_HOST}:${MOCK_BCF_PORT}/nbcf_did/v1/public_key/${SMF_DID}")
    echo "响应:"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    
    if echo "$response" | grep -q "publicKey"; then
        log_success "SMF 公钥查询成功"
    else
        log_error "SMF 公钥查询失败"
        return 1
    fi
    
    echo ""
    log_step "2. 查询 UDM 公钥 ($UDM_DID)..."
    response=$(curl -s "http://${MOCK_BCF_HOST}:${MOCK_BCF_PORT}/nbcf_did/v1/public_key/${UDM_DID}")
    echo "响应:"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    
    if echo "$response" | grep -q "publicKey"; then
        log_success "UDM 公钥查询成功"
    else
        log_error "UDM 公钥查询失败"
        return 1
    fi
    
    echo ""
    log_step "3. 查询不存在的 DID..."
    response=$(curl -s "http://${MOCK_BCF_HOST}:${MOCK_BCF_PORT}/nbcf_did/v1/public_key/did:oai5gc:unknown:999")
    echo "响应:"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    
    if echo "$response" | grep -q "not_found\|NOT FOUND"; then
        log_success "不存在的 DID 正确返回 404"
    else
        log_warning "不存在 DID 查询响应异常"
    fi
    
    echo ""
    log_success "公钥查询接口测试完成"
}

# 测试 NF 注册到 BCF
test_register_nf() {
    log_info "测试 NF 注册到 BCF..."
    log_info "模拟 AMF 启动时向 BCF 注册"
    
    # 生成测试数据
    TEST_NF_ID="test-amf-$(date +%s)"
    TEST_DID="did:oai5gc:amf:test$(date +%s)"
    TEST_PUBLIC_KEY="04abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
    
    # 构建请求体
    REQUEST_BODY=$(cat <<EOF
{
    "nfType": "AMF",
    "nfInstanceId": "${TEST_NF_ID}",
    "did": "${TEST_DID}",
    "publicKey": "${TEST_PUBLIC_KEY}",
    "nfStatus": "REGISTERED",
    "ipv4Addresses": ["192.168.70.132"],
    "sbiPort": 8080
}
EOF
)
    
    echo ""
    log_step "1. 发送 NF 注册请求..."
    echo "请求体:"
    echo "$REQUEST_BODY" | python3 -m json.tool 2>/dev/null || echo "$REQUEST_BODY"
    
    response=$(curl -s -X POST \
        "http://${MOCK_BCF_HOST}:${MOCK_BCF_PORT}/nbcf_nfm/v1/nf_instances" \
        -H "Content-Type: application/json" \
        -d "$REQUEST_BODY")
    
    echo ""
    echo "响应:"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    
    if echo "$response" | grep -q "nfInstanceId"; then
        log_success "NF 注册成功"
    else
        log_error "NF 注册失败"
        return 1
    fi
    
    echo ""
    log_step "2. 验证：查询刚注册的 DID 公钥..."
    response=$(curl -s "http://${MOCK_BCF_HOST}:${MOCK_BCF_PORT}/nbcf_did/v1/public_key/${TEST_DID}")
    echo "响应:"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    
    if echo "$response" | grep -q "${TEST_PUBLIC_KEY:0:20}"; then
        log_success "公钥验证成功 - BCF 正确存储了 NF 的公钥"
    else
        log_error "公钥验证失败"
        return 1
    fi
    
    echo ""
    log_success "NF 注册测试完成"
}

# 测试 NF 发现
test_nf_discovery() {
    log_info "测试 NF 发现接口..."
    
    echo ""
    log_step "1. 查询所有已注册的 NF..."
    response=$(curl -s "http://${MOCK_BCF_HOST}:${MOCK_BCF_PORT}/nbcf_nfm/v1/nf_instances")
    echo "响应:"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    
    echo ""
    log_step "2. 按类型查询 SMF..."
    response=$(curl -s "http://${MOCK_BCF_HOST}:${MOCK_BCF_PORT}/nbcf_nfm/v1/nf_instances?nf_type=SMF")
    echo "响应:"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    
    echo ""
    log_step "3. 查看服务器状态..."
    response=$(curl -s "http://${MOCK_BCF_HOST}:${MOCK_BCF_PORT}/status")
    echo "响应:"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    
    echo ""
    log_success "NF 发现测试完成"
}

# 测试认证初始化（模拟 SMF 向 AMF 发起认证）
test_auth_init() {
    log_info "测试向 AMF 发起认证初始化..."
    log_info "模拟 SMF 向 AMF 发起 DID 双向认证请求"
    
    # 生成测试数据
    NONCE="test_nonce_$(date +%s)"
    TIMESTAMP=$(date +%s)
    SIGNATURE="test_signature_placeholder"  # 实际测试时应该用真正的签名
    
    # 构建请求体
    REQUEST_BODY=$(cat <<EOF
{
    "initiator_did": "${SMF_DID}",
    "nonce": "${NONCE}",
    "timestamp": ${TIMESTAMP},
    "nf_type": "SMF",
    "signature": "${SIGNATURE}"
}
EOF
)
    
    echo ""
    log_step "发送认证初始化请求到 AMF..."
    echo "请求体:"
    echo "$REQUEST_BODY" | python3 -m json.tool 2>/dev/null || echo "$REQUEST_BODY"
    
    echo ""
    log_info "curl -X POST http://${AMF_HOST}:${AMF_PORT}/namf-did-auth/v1/init"
    
    response=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
        "http://${AMF_HOST}:${AMF_PORT}/namf-did-auth/v1/init" \
        -H "Content-Type: application/json" \
        -d "$REQUEST_BODY" 2>/dev/null || echo "CONNECTION_FAILED")
    
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    body=$(echo "$response" | grep -v "HTTP_CODE:")
    
    echo ""
    echo "HTTP 状态码: $http_code"
    echo "响应体:"
    echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
    
    if [[ "$response" == "CONNECTION_FAILED" ]]; then
        log_warning "无法连接到 AMF (${AMF_HOST}:${AMF_PORT})"
        log_info "提示：确保 AMF 正在运行并且 DID 认证模块已启用"
    elif echo "$body" | grep -q "session_id"; then
        log_success "认证初始化成功"
    else
        log_warning "认证初始化响应，请检查 AMF 日志"
    fi
}

# 展示完整认证流程
test_auth_flow() {
    log_info "DID 双向认证完整流程说明"
    
    echo ""
    echo "============================================================"
    echo "                  DID 双向认证流程图"
    echo "============================================================"
    echo ""
    echo "  ┌─────┐                    ┌─────┐                    ┌─────┐"
    echo "  │ SMF │                    │ AMF │                    │ BCF │"
    echo "  └──┬──┘                    └──┬──┘                    └──┬──┘"
    echo "     │                          │                          │"
    echo "     │  1. POST /init           │                          │"
    echo "     │  (did, nonce, sig)       │                          │"
    echo "     │ ────────────────────────>│                          │"
    echo "     │                          │                          │"
    echo "     │                          │  2. GET /public_key/{did}│"
    echo "     │                          │ ─────────────────────────>│"
    echo "     │                          │                          │"
    echo "     │                          │  3. Return public key    │"
    echo "     │                          │ <─────────────────────────│"
    echo "     │                          │                          │"
    echo "     │                          │  4. Verify signature     │"
    echo "     │                          │     using public key     │"
    echo "     │                          │                          │"
    echo "     │  5. Return challenge     │                          │"
    echo "     │  (session_id, nonce)     │                          │"
    echo "     │ <────────────────────────│                          │"
    echo "     │                          │                          │"
    echo "     │  6. GET /public_key/{did}│                          │"
    echo "     │ ─────────────────────────────────────────────────────>│"
    echo "     │                          │                          │"
    echo "     │  7. Return AMF public key│                          │"
    echo "     │ <─────────────────────────────────────────────────────│"
    echo "     │                          │                          │"
    echo "     │  8. POST /complete       │                          │"
    echo "     │  (challenge response)    │                          │"
    echo "     │ ────────────────────────>│                          │"
    echo "     │                          │                          │"
    echo "     │  9. Auth success         │                          │"
    echo "     │  (token)                 │                          │"
    echo "     │ <────────────────────────│                          │"
    echo "     │                          │                          │"
    echo "  ┌──┴──┐                    ┌──┴──┐                    ┌──┴──┐"
    echo "  │ SMF │                    │ AMF │                    │ BCF │"
    echo "  └─────┘                    └─────┘                    └─────┘"
    echo ""
    echo "============================================================"
    echo ""
    echo "关键步骤说明："
    echo "  步骤 2-3: AMF 向 BCF 查询 SMF 的公钥"
    echo "  步骤 4:   AMF 使用公钥验证 SMF 的签名"
    echo "  步骤 6-7: SMF 向 BCF 查询 AMF 的公钥"
    echo "  步骤 8:   SMF 发送挑战响应，AMF 验证后完成双向认证"
    echo ""
    echo "测试命令："
    echo "  # 启动 Mock BCF 服务器"
    echo "  ./test_did_mutual_auth.sh start-bcf"
    echo ""
    echo "  # 测试公钥查询"
    echo "  ./test_did_mutual_auth.sh test-query-pubkey"
    echo ""
    echo "  # 测试 NF 注册"
    echo "  ./test_did_mutual_auth.sh test-register-nf"
    echo ""
}

# 运行所有测试
run_all_tests() {
    log_info "运行所有测试..."
    echo ""
    
    # 确保 BCF 服务器运行
    if ! check_bcf > /dev/null 2>&1; then
        start_bcf
        sleep 1
    fi
    
    echo ""
    echo "=========================================="
    echo "测试 1: 公钥查询（双向认证核心）"
    echo "=========================================="
    test_query_pubkey
    
    echo ""
    echo "=========================================="
    echo "测试 2: NF 注册"
    echo "=========================================="
    test_register_nf
    
    echo ""
    echo "=========================================="
    echo "测试 3: NF 发现"
    echo "=========================================="
    test_nf_discovery
    
    echo ""
    echo "=========================================="
    echo "测试 4: 认证初始化"
    echo "=========================================="
    test_auth_init
    
    echo ""
    log_success "所有测试完成"
}

# 主函数
main() {
    parse_args "$@"
    
    case "${COMMAND:-help}" in
        check-bcf)
            check_bcf
            ;;
        start-bcf)
            start_bcf
            ;;
        stop-bcf)
            stop_bcf
            ;;
        test-query-pubkey|test-bcf-query)
            test_query_pubkey
            ;;
        test-register-nf)
            test_register_nf
            ;;
        test-nf-discovery)
            test_nf_discovery
            ;;
        test-auth-init)
            test_auth_init
            ;;
        test-auth-flow)
            test_auth_flow
            ;;
        all)
            run_all_tests
            ;;
        help|*)
            show_help
            ;;
    esac
}

main "$@"
