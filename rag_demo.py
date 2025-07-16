#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAG服务演示 - 简化版本
用于快速演示RAG服务的核心功能
"""

import os
import json
from typing import Dict, List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from loguru import logger
import uvicorn

# 加载环境变量
load_dotenv()

# 配置日志
logger.add("logs/rag_demo.log", rotation="1 day", retention="7 days")

# 创建FastAPI应用
app = FastAPI(
    title="RAG服务演示",
    description="B_25OS项目的RAG服务简化演示版本",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 数据模型
class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = None
    max_tokens: Optional[int] = 1000
    temperature: Optional[float] = 0.7

class ChatResponse(BaseModel):
    response: str
    timestamp: str
    tokens_used: int
    context_used: bool

class SearchRequest(BaseModel):
    query: str
    top_k: Optional[int] = 5
    threshold: Optional[float] = 0.7

class SearchResponse(BaseModel):
    results: List[Dict]
    query: str
    total_results: int
    timestamp: str

class DocumentRequest(BaseModel):
    content: str
    title: Optional[str] = None
    metadata: Optional[Dict] = None

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    services: Dict[str, str]

# 模拟数据存储
knowledge_base = [
    {
        "id": "doc_1",
        "title": "B_25OS系统架构",
        "content": "B_25OS是一个基于AI的智能操作系统监控平台，集成了Falco安全监控、Neo4j图数据库、RAG智能问答等核心功能。",
        "metadata": {"category": "architecture", "priority": "high"}
    },
    {
        "id": "doc_2",
        "title": "RAG服务功能",
        "content": "RAG（检索增强生成）服务提供智能问答、文档搜索、知识管理等功能，支持多种数据源和向量检索。",
        "metadata": {"category": "features", "priority": "medium"}
    },
    {
        "id": "doc_3",
        "title": "安全监控",
        "content": "系统集成Falco进行实时安全监控，能够检测异常行为、入侵尝试和系统威胁，并提供智能告警。",
        "metadata": {"category": "security", "priority": "high"}
    }
]

# 工具函数
def get_current_timestamp() -> str:
    """获取当前时间戳"""
    return datetime.now().isoformat()

def simulate_openai_response(message: str, context: str = None) -> str:
    """模拟OpenAI API响应"""
    if not os.getenv("OPENAI_API_KEY"):
        return f"模拟回复：基于您的问题 '{message}'，这是一个演示回复。在实际部署中，这里会调用OpenAI API生成智能回复。"
    
    # 这里可以集成真实的OpenAI API调用
    base_response = f"关于 '{message}' 的问题，"
    
    if context:
        base_response += f"基于提供的上下文信息：{context[:100]}...，"
    
    base_response += "我建议您查看相关文档或联系技术支持获取更详细的信息。"
    
    return base_response

def search_knowledge_base(query: str, top_k: int = 5) -> List[Dict]:
    """搜索知识库"""
    results = []
    query_lower = query.lower()
    
    for doc in knowledge_base:
        # 简单的关键词匹配
        score = 0
        if query_lower in doc["title"].lower():
            score += 0.8
        if query_lower in doc["content"].lower():
            score += 0.6
        
        if score > 0:
            results.append({
                "id": doc["id"],
                "title": doc["title"],
                "content": doc["content"],
                "score": score,
                "metadata": doc["metadata"]
            })
    
    # 按分数排序
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:top_k]

# API端点
@app.get("/", response_model=Dict)
async def root():
    """根端点"""
    return {
        "message": "欢迎使用B_25OS RAG服务演示",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """健康检查"""
    services_status = {
        "fastapi": "running",
        "knowledge_base": "available",
        "openai_api": "configured" if os.getenv("OPENAI_API_KEY") else "not_configured",
        "pinecone": "configured" if os.getenv("PINECONE_API_KEY") else "not_configured"
    }
    
    return HealthResponse(
        status="healthy",
        timestamp=get_current_timestamp(),
        version="1.0.0",
        services=services_status
    )

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """智能对话"""
    try:
        logger.info(f"收到聊天请求: {request.message}")
        
        # 如果没有提供上下文，尝试从知识库搜索相关信息
        context = request.context
        context_used = False
        
        if not context:
            search_results = search_knowledge_base(request.message, top_k=2)
            if search_results:
                context = " ".join([result["content"] for result in search_results])
                context_used = True
        
        # 生成回复
        response_text = simulate_openai_response(request.message, context)
        
        return ChatResponse(
            response=response_text,
            timestamp=get_current_timestamp(),
            tokens_used=len(response_text.split()),
            context_used=context_used
        )
        
    except Exception as e:
        logger.error(f"聊天处理错误: {str(e)}")
        raise HTTPException(status_code=500, detail=f"处理聊天请求时发生错误: {str(e)}")

@app.post("/search", response_model=SearchResponse)
async def search(request: SearchRequest):
    """搜索知识库"""
    try:
        logger.info(f"收到搜索请求: {request.query}")
        
        results = search_knowledge_base(request.query, request.top_k)
        
        return SearchResponse(
            results=results,
            query=request.query,
            total_results=len(results),
            timestamp=get_current_timestamp()
        )
        
    except Exception as e:
        logger.error(f"搜索处理错误: {str(e)}")
        raise HTTPException(status_code=500, detail=f"处理搜索请求时发生错误: {str(e)}")

@app.post("/documents")
async def add_document(request: DocumentRequest):
    """添加文档到知识库"""
    try:
        logger.info(f"添加文档: {request.title or '无标题'}")
        
        new_doc = {
            "id": f"doc_{len(knowledge_base) + 1}",
            "title": request.title or f"文档_{len(knowledge_base) + 1}",
            "content": request.content,
            "metadata": request.metadata or {}
        }
        
        knowledge_base.append(new_doc)
        
        return {
            "message": "文档添加成功",
            "document_id": new_doc["id"],
            "timestamp": get_current_timestamp()
        }
        
    except Exception as e:
        logger.error(f"文档添加错误: {str(e)}")
        raise HTTPException(status_code=500, detail=f"添加文档时发生错误: {str(e)}")

@app.get("/documents")
async def list_documents():
    """列出所有文档"""
    return {
        "documents": [
            {
                "id": doc["id"],
                "title": doc["title"],
                "content_preview": doc["content"][:100] + "..." if len(doc["content"]) > 100 else doc["content"],
                "metadata": doc["metadata"]
            }
            for doc in knowledge_base
        ],
        "total": len(knowledge_base),
        "timestamp": get_current_timestamp()
    }

@app.get("/config")
async def get_config():
    """获取配置信息"""
    return {
        "environment": os.getenv("ENVIRONMENT", "development"),
        "openai_model": os.getenv("OPENAI_MODEL", "gpt-4"),
        "max_tokens": int(os.getenv("MAX_TOKENS", "4000")),
        "temperature": float(os.getenv("TEMPERATURE", "0.7")),
        "pinecone_index": os.getenv("PINECONE_INDEX_NAME", "neuronos-knowledge"),
        "timestamp": get_current_timestamp()
    }

if __name__ == "__main__":
    # 确保日志目录存在
    os.makedirs("logs", exist_ok=True)
    
    # 启动服务
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    
    logger.info(f"启动RAG服务演示，地址: http://{host}:{port}")
    logger.info(f"API文档: http://{host}:{port}/docs")
    
    uvicorn.run(
        "rag_demo:app",
        host=host,
        port=port,
        reload=True,
        log_level="info"
    )