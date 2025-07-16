# RAG服务快速部署指南

这是一个简化的RAG（检索增强生成）服务，专为快速部署和使用而设计。

## 🚀 快速开始

### 1. 环境准备

确保系统已安装：
- Docker
- Docker Compose
- curl（用于健康检查）

### 2. 配置环境变量

```bash
# 复制环境变量模板
cp .env.example .env

# 编辑环境变量文件
vim .env
```

必须设置的环境变量：
```bash
PINECONE_API_KEY=your_pinecone_api_key
OPENAI_API_KEY=your_openai_api_key
```

### 3. 一键部署

```bash
# 启动RAG服务
./deploy_rag.sh start
```

### 4. 验证部署

```bash
# 检查服务状态
./deploy_rag.sh status

# 访问API文档
open http://localhost:8000/docs

# 健康检查
curl http://localhost:8000/health
```

## 📋 可用命令

```bash
./deploy_rag.sh start     # 启动服务
./deploy_rag.sh stop      # 停止服务
./deploy_rag.sh restart   # 重启服务
./deploy_rag.sh logs      # 查看日志
./deploy_rag.sh status    # 检查状态
./deploy_rag.sh build     # 构建镜像
./deploy_rag.sh cleanup   # 清理资源
```

## 🔧 服务架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   RAG Service   │────│     Redis       │    │   Pinecone      │
│   (FastAPI)     │    │   (Cache)       │    │  (Vector DB)    │
│   Port: 8000    │    │   Port: 6379    │    │   (External)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │     OpenAI      │
                    │   (LLM API)     │
                    │   (External)    │
                    └─────────────────┘
```

## 📡 API端点

### 核心端点
- `GET /health` - 健康检查
- `POST /chat` - 聊天对话
- `POST /search` - 向量搜索
- `POST /documents` - 文档上传
- `GET /docs` - API文档

### 示例请求

```bash
# 健康检查
curl -X GET "http://localhost:8000/health"

# 聊天对话
curl -X POST "http://localhost:8000/chat" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "你好，请介绍一下RAG技术",
    "session_id": "test-session"
  }'

# 文档搜索
curl -X POST "http://localhost:8000/search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "RAG技术原理",
    "top_k": 5
  }'
```

## 🗂️ 项目结构

```
B_25OS/
├── src/
│   └── rag_service/           # RAG服务源码
│       ├── main.py           # FastAPI应用入口
│       ├── api/              # API路由
│       ├── core/             # 核心业务逻辑
│       ├── models/           # 数据模型
│       └── utils/            # 工具函数
├── config/                   # 配置文件
├── logs/                     # 日志文件
├── data/                     # 数据文件
├── requirements_rag.txt      # Python依赖
├── Dockerfile.rag           # Docker配置
├── docker-compose.rag.yml   # Docker Compose配置
├── deploy_rag.sh            # 部署脚本
├── .env.example             # 环境变量模板
└── README_RAG.md            # 本文档
```

## 🔍 监控和日志

### 查看实时日志
```bash
./deploy_rag.sh logs
```

### 日志文件位置
- 应用日志：`logs/rag_service.log`
- 错误日志：`logs/error.log`
- 访问日志：`logs/access.log`

### 监控指标
- 服务健康状态：`http://localhost:8000/health`
- 系统指标：`http://localhost:8000/metrics`（如果启用）

## 🛠️ 开发模式

### 本地开发
```bash
# 安装依赖
pip install -r requirements_rag.txt

# 启动开发服务器
uvicorn src.rag_service.main:app --reload --host 0.0.0.0 --port 8000
```

### 代码格式化
```bash
# 格式化代码
black src/
isort src/

# 代码检查
flake8 src/
mypy src/
```

### 运行测试
```bash
pytest tests/ -v --cov=src/
```

## 🔧 配置说明

### 环境变量
| 变量名 | 描述 | 默认值 | 必需 |
|--------|------|--------|------|
| `PINECONE_API_KEY` | Pinecone API密钥 | - | ✅ |
| `OPENAI_API_KEY` | OpenAI API密钥 | - | ✅ |
| `REDIS_URL` | Redis连接URL | `redis://localhost:6379/0` | ❌ |
| `LOG_LEVEL` | 日志级别 | `INFO` | ❌ |
| `MAX_TOKENS` | 最大token数 | `4000` | ❌ |
| `TEMPERATURE` | 生成温度 | `0.7` | ❌ |

### Redis配置
- 内存限制：256MB
- 淘汰策略：allkeys-lru
- 持久化：RDB快照

## 🚨 故障排除

### 常见问题

1. **服务启动失败**
   ```bash
   # 检查日志
   ./deploy_rag.sh logs
   
   # 检查端口占用
   netstat -tlnp | grep 8000
   ```

2. **API密钥错误**
   ```bash
   # 检查环境变量
   cat .env | grep API_KEY
   ```

3. **Redis连接失败**
   ```bash
   # 检查Redis状态
   docker-compose -f docker-compose.rag.yml ps redis
   ```

4. **内存不足**
   ```bash
   # 检查系统资源
   docker stats
   ```

### 重置服务
```bash
# 完全重置
./deploy_rag.sh cleanup
./deploy_rag.sh start
```

## 📈 性能优化

### 生产环境建议
1. 增加worker数量：修改`docker-compose.rag.yml`中的`--workers`参数
2. 启用Nginx反向代理：使用`production` profile
3. 配置SSL证书：将证书放入`ssl/`目录
4. 启用监控：使用`monitoring` profile

```bash
# 生产环境部署
docker-compose -f docker-compose.rag.yml --profile production --profile monitoring up -d
```

## 🔐 安全注意事项

1. **API密钥安全**：确保`.env`文件不被提交到版本控制
2. **网络安全**：生产环境建议使用HTTPS
3. **访问控制**：配置防火墙规则限制访问
4. **定期更新**：保持依赖包和基础镜像更新

## 📞 支持

如有问题，请：
1. 查看日志：`./deploy_rag.sh logs`
2. 检查状态：`./deploy_rag.sh status`
3. 查看文档：`http://localhost:8000/docs`
4. 提交Issue到项目仓库

## 📄 许可证

本项目采用MIT许可证，详见LICENSE文件。