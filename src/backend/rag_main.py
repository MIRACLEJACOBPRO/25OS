#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAG服务主启动脚本
启动和管理检索增强生成系统
"""

import asyncio
import logging
import signal
import sys
import os
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# FastAPI相关导入
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import uvicorn

# 项目模块导入
from src.backend.api.rag_api import router as rag_router
from src.backend.services.rag_service import RAGService
from src.backend.services.pinecone_service import PineconeService
from src.backend.services.knowledge_manager import KnowledgeManager
from src.backend.config.rag_config_loader import get_config_loader

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('rag_service.log')
    ]
)
logger = logging.getLogger(__name__)

class RAGApplication:
    """RAG应用程序管理器"""
    
    def __init__(self):
        self.app: Optional[FastAPI] = None
        self.rag_service: Optional[RAGService] = None
        self.pinecone_service: Optional[PineconeService] = None
        self.knowledge_manager: Optional[KnowledgeManager] = None
        self.config_loader = get_config_loader()
        self._shutdown_event = asyncio.Event()
        
    async def initialize_services(self) -> bool:
        """初始化所有服务"""
        try:
            logger.info("开始初始化RAG服务...")
            
            # 验证配置
            if not self.config_loader.validate_config():
                logger.error("配置验证失败")
                return False
            
            # 初始化Pinecone服务
            logger.info("初始化Pinecone服务...")
            self.pinecone_service = PineconeService()
            pinecone_init = await self.pinecone_service.initialize()
            if not pinecone_init:
                logger.error("Pinecone服务初始化失败")
                return False
            logger.info("Pinecone服务初始化成功")
            
            # 初始化RAG服务
            logger.info("初始化RAG服务...")
            self.rag_service = RAGService()
            rag_init = await self.rag_service.initialize()
            if not rag_init:
                logger.error("RAG服务初始化失败")
                return False
            logger.info("RAG服务初始化成功")
            
            # 初始化知识管理器
            logger.info("初始化知识管理器...")
            self.knowledge_manager = KnowledgeManager(self.pinecone_service)
            logger.info("知识管理器初始化成功")
            
            logger.info("所有服务初始化完成")
            return True
            
        except Exception as e:
            logger.error(f"服务初始化失败: {e}")
            return False
    
    async def cleanup_services(self) -> None:
        """清理所有服务"""
        try:
            logger.info("开始清理服务...")
            
            if self.rag_service:
                await self.rag_service.close()
                logger.info("RAG服务已关闭")
            
            if self.pinecone_service:
                await self.pinecone_service.close()
                logger.info("Pinecone服务已关闭")
            
            logger.info("所有服务清理完成")
            
        except Exception as e:
            logger.error(f"服务清理失败: {e}")
    
    def create_app(self) -> FastAPI:
        """创建FastAPI应用"""
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            # 启动时初始化服务
            logger.info("应用启动中...")
            init_success = await self.initialize_services()
            if not init_success:
                logger.error("服务初始化失败，应用启动中止")
                sys.exit(1)
            
            logger.info("应用启动完成")
            yield
            
            # 关闭时清理服务
            logger.info("应用关闭中...")
            await self.cleanup_services()
            logger.info("应用关闭完成")
        
        # 创建FastAPI应用
        app = FastAPI(
            title="RAG检索增强生成服务",
            description="提供知识检索和事件增强分析功能的API服务",
            version="1.0.0",
            docs_url="/docs",
            redoc_url="/redoc",
            lifespan=lifespan
        )
        
        # 添加中间件
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # 生产环境应该限制具体域名
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        app.add_middleware(GZipMiddleware, minimum_size=1000)
        
        # 添加路由
        app.include_router(rag_router)
        
        # 异常处理器
        @app.exception_handler(RequestValidationError)
        async def validation_exception_handler(request: Request, exc: RequestValidationError):
            logger.warning(f"请求验证失败: {exc}")
            return JSONResponse(
                status_code=422,
                content={
                    "error": "请求参数验证失败",
                    "details": exc.errors(),
                    "timestamp": str(asyncio.get_event_loop().time())
                }
            )
        
        @app.exception_handler(Exception)
        async def general_exception_handler(request: Request, exc: Exception):
            logger.error(f"未处理的异常: {exc}")
            return JSONResponse(
                status_code=500,
                content={
                    "error": "内部服务器错误",
                    "message": str(exc),
                    "timestamp": str(asyncio.get_event_loop().time())
                }
            )
        
        # 根路径
        @app.get("/")
        async def root():
            return {
                "service": "RAG检索增强生成服务",
                "version": "1.0.0",
                "status": "running",
                "docs": "/docs",
                "health": "/api/v1/rag/health"
            }
        
        self.app = app
        return app
    
    def setup_signal_handlers(self) -> None:
        """设置信号处理器"""
        def signal_handler(signum, frame):
            logger.info(f"收到信号 {signum}，准备关闭服务...")
            self._shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def run_server(self, host: str = "0.0.0.0", port: int = 8000, reload: bool = False) -> None:
        """运行服务器"""
        try:
            # 创建应用
            app = self.create_app()
            
            # 设置信号处理器
            self.setup_signal_handlers()
            
            # 配置uvicorn
            config = uvicorn.Config(
                app=app,
                host=host,
                port=port,
                reload=reload,
                log_level="info",
                access_log=True
            )
            
            server = uvicorn.Server(config)
            
            logger.info(f"RAG服务启动在 http://{host}:{port}")
            logger.info(f"API文档地址: http://{host}:{port}/docs")
            
            # 启动服务器
            await server.serve()
            
        except Exception as e:
            logger.error(f"服务器运行失败: {e}")
            raise

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="RAG检索增强生成服务")
    parser.add_argument("--host", default="0.0.0.0", help="服务器主机地址")
    parser.add_argument("--port", type=int, default=8000, help="服务器端口")
    parser.add_argument("--reload", action="store_true", help="启用自动重载")
    parser.add_argument("--config", help="配置文件路径")
    parser.add_argument("--test", action="store_true", help="运行测试模式")
    parser.add_argument("--init-knowledge", action="store_true", help="初始化知识库")
    
    args = parser.parse_args()
    
    # 设置配置文件路径
    if args.config:
        os.environ["RAG_CONFIG_PATH"] = args.config
    
    # 创建应用实例
    rag_app = RAGApplication()
    
    if args.test:
        # 测试模式
        logger.info("运行测试模式...")
        asyncio.run(run_tests(rag_app))
    elif args.init_knowledge:
        # 初始化知识库
        logger.info("初始化知识库...")
        asyncio.run(init_knowledge_base(rag_app))
    else:
        # 正常运行模式
        try:
            asyncio.run(rag_app.run_server(
                host=args.host,
                port=args.port,
                reload=args.reload
            ))
        except KeyboardInterrupt:
            logger.info("收到中断信号，服务正常关闭")
        except Exception as e:
            logger.error(f"服务运行失败: {e}")
            sys.exit(1)

async def run_tests(rag_app: RAGApplication) -> None:
    """运行测试"""
    try:
        logger.info("开始运行RAG服务测试...")
        
        # 初始化服务
        init_success = await rag_app.initialize_services()
        if not init_success:
            logger.error("服务初始化失败")
            return
        
        # 导入测试模块
        from test_rag_services import RAGServiceTester
        
        # 创建测试器
        tester = RAGServiceTester()
        
        # 设置服务实例
        tester.rag_service = rag_app.rag_service
        tester.pinecone_service = rag_app.pinecone_service
        tester.knowledge_manager = rag_app.knowledge_manager
        
        # 运行测试
        await tester.run_all_tests()
        
        logger.info("测试完成")
        
    except Exception as e:
        logger.error(f"测试运行失败: {e}")
    finally:
        # 清理服务
        await rag_app.cleanup_services()

async def init_knowledge_base(rag_app: RAGApplication) -> None:
    """初始化知识库"""
    try:
        logger.info("开始初始化知识库...")
        
        # 初始化服务
        init_success = await rag_app.initialize_services()
        if not init_success:
            logger.error("服务初始化失败")
            return
        
        # 创建示例知识项
        knowledge_items = [
            {
                "title": "SQL注入攻击检测规则",
                "content": "SQL注入是一种常见的Web应用安全漏洞，攻击者通过在输入字段中插入恶意SQL代码来操控数据库。检测特征包括：单引号、双引号、分号、UNION、SELECT、DROP等关键字的异常组合。",
                "knowledge_type": "security_rule",
                "tags": ["sql注入", "web安全", "数据库安全"]
            },
            {
                "title": "异常网络连接修复指南",
                "content": "发现异常网络连接时的处理步骤：1. 立即隔离受影响主机；2. 分析连接目标和数据传输内容；3. 检查系统日志和进程列表；4. 更新防火墙规则阻止恶意连接；5. 进行全面的恶意软件扫描。",
                "knowledge_type": "remediation_guide",
                "tags": ["网络安全", "异常连接", "应急响应"]
            },
            {
                "title": "文件完整性监控最佳实践",
                "content": "文件完整性监控(FIM)是检测未授权文件更改的重要安全控制措施。关键监控目录包括：/etc、/bin、/sbin、/usr/bin等系统目录，以及应用程序配置文件。建议使用哈希算法验证文件完整性。",
                "knowledge_type": "threat_pattern",
                "tags": ["文件监控", "完整性检查", "系统安全"]
            }
        ]
        
        # 批量导入知识
        for item in knowledge_items:
            try:
                from models.knowledge import KnowledgeType
                knowledge_item = await rag_app.knowledge_manager.create_knowledge_item(
                    title=item["title"],
                    content=item["content"],
                    knowledge_type=KnowledgeType(item["knowledge_type"]),
                    tags=item["tags"]
                )
                logger.info(f"成功创建知识项: {knowledge_item.title}")
            except Exception as e:
                logger.error(f"创建知识项失败: {e}")
        
        logger.info("知识库初始化完成")
        
    except Exception as e:
        logger.error(f"知识库初始化失败: {e}")
    finally:
        # 清理服务
        await rag_app.cleanup_services()

if __name__ == "__main__":
    main()