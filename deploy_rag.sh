#!/bin/bash

# RAG服务部署脚本
# 用法: ./deploy_rag.sh [start|stop|restart|logs|status|build]

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# 检查Docker和Docker Compose
check_dependencies() {
    log_info "检查依赖..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker未安装，请先安装Docker"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose未安装，请先安装Docker Compose"
        exit 1
    fi
    
    log_success "依赖检查通过"
}

# 检查环境变量
check_env() {
    log_info "检查环境变量..."
    
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            log_warning ".env文件不存在，从.env.example复制"
            cp .env.example .env
            log_warning "请编辑.env文件设置必要的环境变量"
        else
            log_error ".env文件不存在，请创建并设置环境变量"
            exit 1
        fi
    fi
    
    # 检查关键环境变量
    source .env
    if [ -z "$PINECONE_API_KEY" ] || [ -z "$OPENAI_API_KEY" ]; then
        log_warning "请确保在.env文件中设置了PINECONE_API_KEY和OPENAI_API_KEY"
    fi
    
    log_success "环境变量检查完成"
}

# 创建必要的目录
setup_directories() {
    log_info "创建必要的目录..."
    
    mkdir -p logs data config/nginx config/redis ssl
    
    # 创建Redis配置文件（如果不存在）
    if [ ! -f "config/redis.conf" ]; then
        cat > config/redis.conf << EOF
# Redis配置
bind 0.0.0.0
port 6379
timeout 0
tcp-keepalive 300
daemonize no
supervised no
pidfile /var/run/redis_6379.pid
loglevel notice
logfile ""
databases 16
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir ./
maxmemory 256mb
maxmemory-policy allkeys-lru
EOF
        log_info "创建了默认Redis配置文件"
    fi
    
    log_success "目录设置完成"
}

# 构建镜像
build_image() {
    log_info "构建RAG服务镜像..."
    docker-compose -f docker-compose.rag.yml build --no-cache
    log_success "镜像构建完成"
}

# 启动服务
start_services() {
    log_info "启动RAG服务..."
    docker-compose -f docker-compose.rag.yml up -d
    
    # 等待服务启动
    log_info "等待服务启动..."
    sleep 10
    
    # 检查服务状态
    if docker-compose -f docker-compose.rag.yml ps | grep -q "Up"; then
        log_success "RAG服务启动成功"
        log_info "服务地址: http://localhost:8000"
        log_info "API文档: http://localhost:8000/docs"
        log_info "健康检查: http://localhost:8000/health"
    else
        log_error "服务启动失败，请检查日志"
        docker-compose -f docker-compose.rag.yml logs
        exit 1
    fi
}

# 停止服务
stop_services() {
    log_info "停止RAG服务..."
    docker-compose -f docker-compose.rag.yml down
    log_success "服务已停止"
}

# 重启服务
restart_services() {
    log_info "重启RAG服务..."
    stop_services
    start_services
}

# 查看日志
view_logs() {
    log_info "查看服务日志..."
    docker-compose -f docker-compose.rag.yml logs -f
}

# 查看状态
check_status() {
    log_info "检查服务状态..."
    docker-compose -f docker-compose.rag.yml ps
    
    # 检查健康状态
    log_info "检查健康状态..."
    if curl -f http://localhost:8000/health &> /dev/null; then
        log_success "RAG服务运行正常"
    else
        log_warning "RAG服务可能未正常运行"
    fi
}

# 清理资源
cleanup() {
    log_info "清理Docker资源..."
    docker-compose -f docker-compose.rag.yml down -v --remove-orphans
    docker system prune -f
    log_success "清理完成"
}

# 显示帮助信息
show_help() {
    echo "RAG服务部署脚本"
    echo ""
    echo "用法: $0 [命令]"
    echo ""
    echo "命令:"
    echo "  start     启动RAG服务"
    echo "  stop      停止RAG服务"
    echo "  restart   重启RAG服务"
    echo "  build     构建Docker镜像"
    echo "  logs      查看服务日志"
    echo "  status    查看服务状态"
    echo "  cleanup   清理Docker资源"
    echo "  help      显示帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 start    # 启动服务"
    echo "  $0 logs     # 查看日志"
    echo "  $0 status   # 检查状态"
}

# 主函数
main() {
    case "$1" in
        start)
            check_dependencies
            check_env
            setup_directories
            start_services
            ;;
        stop)
            stop_services
            ;;
        restart)
            restart_services
            ;;
        build)
            check_dependencies
            build_image
            ;;
        logs)
            view_logs
            ;;
        status)
            check_status
            ;;
        cleanup)
            cleanup
            ;;
        help|--help|-h)
            show_help
            ;;
        "")
            log_warning "请指定命令"
            show_help
            exit 1
            ;;
        *)
            log_error "未知命令: $1"
            show_help
            exit 1
            ;;
    esac
}

# 执行主函数
main "$@"