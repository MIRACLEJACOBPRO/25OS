#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS Backend Main Application
主应用程序入口
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
import sys
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.append(str(Path(__file__).parent))

# 导入配置和核心模块
from core.config import settings, validate_settings
from core.database import neo4j_driver
from services.graph_builder import GraphBuilder
from services.log_processor import LogProcessor
from api.events import router as events_router
from api.graph import router as graph_router
from api.graph_query import router as graph_query_router
from api.openai_analysis import router as openai_analysis_router

# 配置日志
logger.remove()
logger.add(
    settings.log_file,
    rotation="10 MB",
    retention="7 days",
    level=settings.log_level,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}"
)
logger.add(sys.stderr, level=settings.log_level)

# 全局变量
log_processor = None
graph_builder = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    global log_processor, graph_builder
    
    logger.info("Starting NeuronOS Backend...")
    
    try:
        # 验证配置
        validate_settings()
        logger.info("Configuration validated successfully")
        
        # 初始化Neo4j连接
        await neo4j_driver.connect()
        await neo4j_driver.verify_connectivity()
        await neo4j_driver.initialize_schema()
        logger.info("Neo4j connection established and schema initialized")
        
        # 初始化图谱构建器
        graph_builder = GraphBuilder()
        logger.info("Graph builder initialized")
        
        # 初始化日志处理器
        log_processor = LogProcessor(graph_builder)
        
        # 启动日志监控
        await log_processor.start_monitoring()
        logger.info("Log processor started and monitoring Falco logs")
        
        logger.info("NeuronOS Backend started successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start backend: {e}")
        raise
    finally:
        # 清理资源
        logger.info("Shutting down NeuronOS Backend...")
        
        if log_processor:
            await log_processor.stop_monitoring()
            logger.info("Log processor stopped")
        
        await neo4j_driver.close()
        logger.info("Neo4j connection closed")
        
        logger.info("NeuronOS Backend shutdown complete")

# 创建FastAPI应用
app = FastAPI(
    title=settings.app_name,
    description="智能安全监控系统后端API - 基于Falco日志分析和Neo4j知识图谱",
    version=settings.app_version,
    lifespan=lifespan
)

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 生产环境中应该限制具体域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册API路由
app.include_router(events_router, prefix="/api")
app.include_router(graph_router, prefix="/api")
app.include_router(graph_query_router, prefix="/api")
app.include_router(openai_analysis_router, prefix="/api")

# 根路径和基础路由
@app.get("/")
async def root():
    """根路径"""
    return {
        "message": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "description": "NeuronOS智能安全监控系统 - 实时分析Falco安全事件并构建知识图谱"
    }

@app.get("/health")
async def health_check():
    """健康检查"""
    try:
        # 检查Neo4j连接
        db_status = await neo4j_driver.verify_connectivity()
        
        # 检查日志处理器状态
        if log_processor:
            processor_stats = await log_processor.get_processing_stats()
            processor_status = processor_stats['is_running']
        else:
            processor_status = False
            processor_stats = {}
        
        # 获取图谱统计
        if graph_builder:
            graph_stats = await graph_builder.get_graph_stats()
        else:
            graph_stats = {}
        
        return {
            "status": "healthy" if db_status and processor_status else "degraded",
            "timestamp": datetime.now().isoformat(),
            "components": {
                "database": {
                    "status": "connected" if db_status else "disconnected",
                    "uri": settings.neo4j_uri
                },
                "log_processor": {
                    "status": "running" if processor_status else "stopped",
                    "stats": processor_stats
                },
                "graph_builder": {
                    "status": "initialized" if graph_builder else "not_initialized",
                    "stats": graph_stats
                }
            },
            "configuration": {
                "falco_log_path": settings.falco_log_path,
                "batch_size": settings.batch_size,
                "processing_interval": settings.processing_interval
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@app.get("/api/status")
async def get_system_status():
    """获取系统状态详情"""
    try:
        # 数据库统计
        from core.database import get_db_stats
        db_stats = await get_db_stats()
        
        # 处理器统计
        processor_stats = await log_processor.get_processing_stats() if log_processor else {}
        
        # 图谱统计
        graph_stats = await graph_builder.get_graph_stats() if graph_builder else {}
        
        return {
            "system": {
                "uptime": "running",
                "version": settings.app_version,
                "environment": "development" if settings.debug else "production"
            },
            "database": db_stats,
            "processor": processor_stats,
            "graph": graph_stats,
            "configuration": {
                "log_level": settings.log_level,
                "batch_size": settings.batch_size,
                "max_workers": settings.max_workers
            }
        }
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system status")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
        workers=1  # 单进程模式，避免多进程间的资源冲突
    )