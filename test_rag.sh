#!/bin/bash

# RAG服务测试脚本
# 用法: ./test_rag.sh [basic|full|load]

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
BASE_URL="http://localhost:8000"
TEST_SESSION="test-session-$(date +%s)"

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

# 检查服务是否运行
check_service() {
    log_info "检查RAG服务状态..."
    
    if ! curl -f "$BASE_URL/health" &> /dev/null; then
        log_error "RAG服务未运行，请先启动服务: ./deploy_rag.sh start"
        exit 1
    fi
    
    log_success "RAG服务运行正常"
}

# 测试健康检查
test_health() {
    log_info "测试健康检查端点..."
    
    response=$(curl -s "$BASE_URL/health")
    if echo "$response" | grep -q "healthy"; then
        log_success "健康检查通过"
        echo "响应: $response"
    else
        log_error "健康检查失败"
        echo "响应: $response"
        return 1
    fi
}

# 测试API文档
test_docs() {
    log_info "测试API文档端点..."
    
    status_code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/docs")
    if [ "$status_code" = "200" ]; then
        log_success "API文档可访问"
        log_info "文档地址: $BASE_URL/docs"
    else
        log_error "API文档访问失败，状态码: $status_code"
        return 1
    fi
}

# 测试聊天功能
test_chat() {
    log_info "测试聊天功能..."
    
    # 测试数据
    test_message="你好，请简单介绍一下RAG技术"
    
    # 发送请求
    response=$(curl -s -X POST "$BASE_URL/chat" \
        -H "Content-Type: application/json" \
        -d "{
            \"message\": \"$test_message\",
            \"session_id\": \"$TEST_SESSION\"
        }")
    
    # 检查响应
    if echo "$response" | grep -q "response"; then
        log_success "聊天功能正常"
        echo "用户: $test_message"
        echo "AI: $(echo "$response" | jq -r '.response' 2>/dev/null || echo "$response")"
    else
        log_error "聊天功能失败"
        echo "响应: $response"
        return 1
    fi
}

# 测试搜索功能
test_search() {
    log_info "测试搜索功能..."
    
    # 测试查询
    test_query="RAG技术原理"
    
    # 发送搜索请求
    response=$(curl -s -X POST "$BASE_URL/search" \
        -H "Content-Type: application/json" \
        -d "{
            \"query\": \"$test_query\",
            \"top_k\": 3
        }")
    
    # 检查响应
    if echo "$response" | grep -q "results"; then
        log_success "搜索功能正常"
        echo "查询: $test_query"
        echo "结果: $(echo "$response" | jq -r '.results | length' 2>/dev/null || echo "未知") 条"
    else
        log_error "搜索功能失败"
        echo "响应: $response"
        return 1
    fi
}

# 测试文档上传
test_upload() {
    log_info "测试文档上传功能..."
    
    # 创建测试文档
    test_doc="这是一个测试文档。RAG（Retrieval-Augmented Generation）是一种结合检索和生成的AI技术。"
    
    # 发送上传请求
    response=$(curl -s -X POST "$BASE_URL/documents" \
        -H "Content-Type: application/json" \
        -d "{
            \"content\": \"$test_doc\",
            \"title\": \"测试文档\",
            \"metadata\": {\"type\": \"test\"}
        }")
    
    # 检查响应
    if echo "$response" | grep -q "document_id"; then
        log_success "文档上传功能正常"
        doc_id=$(echo "$response" | jq -r '.document_id' 2>/dev/null || echo "未知")
        echo "文档ID: $doc_id"
    else
        log_error "文档上传功能失败"
        echo "响应: $response"
        return 1
    fi
}

# 性能测试
test_performance() {
    log_info "执行性能测试..."
    
    local requests=10
    local start_time=$(date +%s)
    local success_count=0
    
    for i in $(seq 1 $requests); do
        if curl -s -f "$BASE_URL/health" &> /dev/null; then
            ((success_count++))
        fi
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local success_rate=$((success_count * 100 / requests))
    
    log_info "性能测试结果:"
    echo "  请求数: $requests"
    echo "  成功数: $success_count"
    echo "  成功率: $success_rate%"
    echo "  总耗时: ${duration}秒"
    echo "  平均响应时间: $((duration * 1000 / requests))ms"
    
    if [ $success_rate -ge 90 ]; then
        log_success "性能测试通过"
    else
        log_warning "性能测试未达到预期（成功率 < 90%）"
    fi
}

# 负载测试
test_load() {
    log_info "执行负载测试..."
    
    if ! command -v ab &> /dev/null; then
        log_warning "Apache Bench (ab) 未安装，跳过负载测试"
        log_info "安装命令: sudo apt-get install apache2-utils"
        return 0
    fi
    
    log_info "使用Apache Bench进行负载测试..."
    ab -n 100 -c 10 "$BASE_URL/health" || {
        log_warning "负载测试失败，可能是服务负载过高"
    }
}

# 基础测试套件
run_basic_tests() {
    log_info "运行基础测试套件..."
    
    local failed=0
    
    test_health || ((failed++))
    test_docs || ((failed++))
    test_chat || ((failed++))
    test_search || ((failed++))
    
    if [ $failed -eq 0 ]; then
        log_success "所有基础测试通过 ✅"
    else
        log_error "$failed 个测试失败 ❌"
        return 1
    fi
}

# 完整测试套件
run_full_tests() {
    log_info "运行完整测试套件..."
    
    local failed=0
    
    test_health || ((failed++))
    test_docs || ((failed++))
    test_chat || ((failed++))
    test_search || ((failed++))
    test_upload || ((failed++))
    test_performance || ((failed++))
    
    if [ $failed -eq 0 ]; then
        log_success "所有完整测试通过 ✅"
    else
        log_error "$failed 个测试失败 ❌"
        return 1
    fi
}

# 显示帮助信息
show_help() {
    echo "RAG服务测试脚本"
    echo ""
    echo "用法: $0 [测试类型]"
    echo ""
    echo "测试类型:"
    echo "  basic     基础功能测试（默认）"
    echo "  full      完整功能测试"
    echo "  load      负载测试"
    echo "  health    仅健康检查"
    echo "  chat      仅聊天功能测试"
    echo "  search    仅搜索功能测试"
    echo "  upload    仅上传功能测试"
    echo "  perf      仅性能测试"
    echo "  help      显示帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 basic    # 运行基础测试"
    echo "  $0 full     # 运行完整测试"
    echo "  $0 load     # 运行负载测试"
}

# 主函数
main() {
    # 检查服务状态
    check_service
    
    case "${1:-basic}" in
        basic)
            run_basic_tests
            ;;
        full)
            run_full_tests
            ;;
        load)
            test_load
            ;;
        health)
            test_health
            ;;
        chat)
            test_chat
            ;;
        search)
            test_search
            ;;
        upload)
            test_upload
            ;;
        perf)
            test_performance
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "未知测试类型: $1"
            show_help
            exit 1
            ;;
    esac
}

# 执行主函数
main "$@"