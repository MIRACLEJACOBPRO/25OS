#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAG服务API接口
提供检索增强生成功能的REST API
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

# 导入服务和模型
from services.rag_service import RAGService
from services.pinecone_service import PineconeService
from services.knowledge_manager import KnowledgeManager
from models.knowledge import KnowledgeItem, KnowledgeType
from models.events import StandardizedEvent
from config.rag_config_loader import get_config_loader

# 配置日志
logger = logging.getLogger(__name__)

# 创建路由器
router = APIRouter(prefix="/api/v1/rag", tags=["RAG"])

# 请求和响应模型
class KnowledgeSearchRequest(BaseModel):
    """知识搜索请求"""
    query_text: str = Field(..., description="查询文本")
    top_k: int = Field(5, ge=1, le=20, description="返回结果数量")
    knowledge_types: Optional[List[str]] = Field(None, description="知识类型过滤")
    tags: Optional[List[str]] = Field(None, description="标签过滤")
    similarity_threshold: float = Field(0.7, ge=0.0, le=1.0, description="相似度阈值")
    
    @validator('knowledge_types')
    def validate_knowledge_types(cls, v):
        if v:
            valid_types = [kt.value for kt in KnowledgeType]
            for kt in v:
                if kt not in valid_types:
                    raise ValueError(f"无效的知识类型: {kt}")
        return v

class KnowledgeSearchResponse(BaseModel):
    """知识搜索响应"""
    results: List[Dict[str, Any]] = Field(..., description="搜索结果")
    total_count: int = Field(..., description="结果总数")
    query_time_ms: float = Field(..., description="查询耗时（毫秒）")
    timestamp: str = Field(..., description="查询时间戳")

class EventEnhancementRequest(BaseModel):
    """事件增强请求"""
    event_data: Dict[str, Any] = Field(..., description="事件数据")
    analysis_type: str = Field("comprehensive", description="分析类型")
    max_knowledge_items: int = Field(8, ge=1, le=20, description="最大知识项数量")
    include_recommendations: bool = Field(True, description="是否包含推荐建议")

class EventEnhancementResponse(BaseModel):
    """事件增强响应"""
    enhanced_event: Dict[str, Any] = Field(..., description="增强后的事件")
    knowledge_sources: List[Dict[str, Any]] = Field(..., description="知识来源")
    recommendations: List[str] = Field(..., description="推荐建议")
    confidence_boost: float = Field(..., description="置信度提升")
    processing_time_ms: float = Field(..., description="处理耗时（毫秒）")
    timestamp: str = Field(..., description="处理时间戳")

class KnowledgeUploadRequest(BaseModel):
    """知识上传请求"""
    title: str = Field(..., description="知识标题")
    content: str = Field(..., description="知识内容")
    knowledge_type: str = Field(..., description="知识类型")
    tags: List[str] = Field(default_factory=list, description="标签列表")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="元数据")
    
    @validator('knowledge_type')
    def validate_knowledge_type(cls, v):
        valid_types = [kt.value for kt in KnowledgeType]
        if v not in valid_types:
            raise ValueError(f"无效的知识类型: {v}")
        return v

class KnowledgeUploadResponse(BaseModel):
    """知识上传响应"""
    knowledge_id: str = Field(..., description="知识项ID")
    status: str = Field(..., description="上传状态")
    message: str = Field(..., description="状态消息")
    timestamp: str = Field(..., description="上传时间戳")

class BatchKnowledgeImportRequest(BaseModel):
    """批量知识导入请求"""
    content: str = Field(..., description="导入内容")
    format: str = Field("json", description="内容格式")
    default_knowledge_type: str = Field("security_rule", description="默认知识类型")
    default_tags: List[str] = Field(default_factory=list, description="默认标签")
    validation_level: str = Field("moderate", description="验证级别")
    auto_generate_id: bool = Field(True, description="自动生成ID")

class BatchKnowledgeImportResponse(BaseModel):
    """批量知识导入响应"""
    successful_imports: int = Field(..., description="成功导入数量")
    failed_imports: int = Field(..., description="失败导入数量")
    total_items: int = Field(..., description="总项目数量")
    errors: List[Dict[str, Any]] = Field(..., description="错误列表")
    processing_time_ms: float = Field(..., description="处理耗时（毫秒）")
    timestamp: str = Field(..., description="导入时间戳")

class ServiceStatusResponse(BaseModel):
    """服务状态响应"""
    rag_service_status: str = Field(..., description="RAG服务状态")
    pinecone_status: str = Field(..., description="Pinecone状态")
    knowledge_manager_status: str = Field(..., description="知识管理器状态")
    statistics: Dict[str, Any] = Field(..., description="统计信息")
    timestamp: str = Field(..., description="状态时间戳")

# 服务依赖
class RAGServiceDependency:
    """RAG服务依赖"""
    
    def __init__(self):
        self._rag_service: Optional[RAGService] = None
        self._pinecone_service: Optional[PineconeService] = None
        self._knowledge_manager: Optional[KnowledgeManager] = None
        self._initialized = False
    
    async def get_rag_service(self) -> RAGService:
        """获取RAG服务实例"""
        if not self._initialized:
            await self._initialize_services()
        
        if not self._rag_service:
            raise HTTPException(status_code=503, detail="RAG服务不可用")
        
        return self._rag_service
    
    async def get_pinecone_service(self) -> PineconeService:
        """获取Pinecone服务实例"""
        if not self._initialized:
            await self._initialize_services()
        
        if not self._pinecone_service:
            raise HTTPException(status_code=503, detail="Pinecone服务不可用")
        
        return self._pinecone_service
    
    async def get_knowledge_manager(self) -> KnowledgeManager:
        """获取知识管理器实例"""
        if not self._initialized:
            await self._initialize_services()
        
        if not self._knowledge_manager:
            raise HTTPException(status_code=503, detail="知识管理器不可用")
        
        return self._knowledge_manager
    
    async def _initialize_services(self) -> None:
        """初始化服务"""
        try:
            logger.info("初始化RAG服务...")
            
            # 初始化Pinecone服务
            self._pinecone_service = PineconeService()
            pinecone_init = await self._pinecone_service.initialize()
            if not pinecone_init:
                logger.error("Pinecone服务初始化失败")
                return
            
            # 初始化RAG服务
            self._rag_service = RAGService()
            rag_init = await self._rag_service.initialize()
            if not rag_init:
                logger.error("RAG服务初始化失败")
                return
            
            # 初始化知识管理器
            self._knowledge_manager = KnowledgeManager(self._pinecone_service)
            
            self._initialized = True
            logger.info("RAG服务初始化完成")
            
        except Exception as e:
            logger.error(f"RAG服务初始化失败: {e}")
            raise HTTPException(status_code=503, detail=f"服务初始化失败: {str(e)}")

# 创建服务依赖实例
rag_dependency = RAGServiceDependency()

# API端点
@router.post("/search", response_model=KnowledgeSearchResponse)
async def search_knowledge(
    request: KnowledgeSearchRequest,
    rag_service: RAGService = Depends(rag_dependency.get_rag_service)
) -> KnowledgeSearchResponse:
    """搜索相关知识"""
    try:
        start_time = datetime.now()
        
        # 执行知识搜索
        search_results = await rag_service.retrieve_relevant_knowledge(
            query_text=request.query_text,
            event_type=None,  # 可以从请求中获取
            max_items=request.top_k
        )
        
        # 格式化结果
        formatted_results = []
        for result in search_results:
            knowledge_item = result.knowledge_item
            formatted_result = {
                "id": knowledge_item.id,
                "title": knowledge_item.title,
                "content": knowledge_item.content,
                "knowledge_type": knowledge_item.knowledge_type.value,
                "tags": knowledge_item.tags,
                "similarity_score": result.similarity_score,
                "rank": result.rank,
                "metadata": knowledge_item.metadata
            }
            formatted_results.append(formatted_result)
        
        # 计算查询时间
        query_time = (datetime.now() - start_time).total_seconds() * 1000
        
        return KnowledgeSearchResponse(
            results=formatted_results,
            total_count=len(formatted_results),
            query_time_ms=query_time,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"知识搜索失败: {e}")
        raise HTTPException(status_code=500, detail=f"搜索失败: {str(e)}")

@router.post("/enhance", response_model=EventEnhancementResponse)
async def enhance_event(
    request: EventEnhancementRequest,
    rag_service: RAGService = Depends(rag_dependency.get_rag_service)
) -> EventEnhancementResponse:
    """使用知识增强事件分析"""
    try:
        start_time = datetime.now()
        
        # 创建标准化事件对象（简化处理）
        event_data = request.event_data
        
        # 执行知识增强
        enhanced_result = await rag_service.enhance_with_knowledge(
            anomaly_event=event_data,
            analysis_type=request.analysis_type
        )
        
        # 提取增强信息
        if isinstance(enhanced_result, dict):
            enhanced_context = enhanced_result.get('enhanced_context', {})
            metadata = enhanced_result.get('enhancement_metadata', {})
            recommendations = enhanced_result.get('recommendations', [])
            
            knowledge_sources = []
            for item in enhanced_context.get('knowledge_base', []):
                knowledge_sources.append({
                    "title": item.get('title', ''),
                    "type": item.get('type', ''),
                    "similarity_score": item.get('similarity_score', 0),
                    "tags": item.get('tags', [])
                })
        else:
            knowledge_sources = []
            recommendations = []
            metadata = {}
        
        # 计算处理时间
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        return EventEnhancementResponse(
            enhanced_event=enhanced_result if isinstance(enhanced_result, dict) else event_data,
            knowledge_sources=knowledge_sources,
            recommendations=recommendations,
            confidence_boost=metadata.get('confidence_boost', 0.0),
            processing_time_ms=processing_time,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"事件增强失败: {e}")
        raise HTTPException(status_code=500, detail=f"增强失败: {str(e)}")

@router.post("/knowledge", response_model=KnowledgeUploadResponse)
async def upload_knowledge(
    request: KnowledgeUploadRequest,
    knowledge_manager: KnowledgeManager = Depends(rag_dependency.get_knowledge_manager)
) -> KnowledgeUploadResponse:
    """上传单个知识项"""
    try:
        # 创建知识项
        knowledge_item = await knowledge_manager.create_knowledge_item(
            title=request.title,
            content=request.content,
            knowledge_type=KnowledgeType(request.knowledge_type),
            tags=request.tags,
            metadata=request.metadata
        )
        
        return KnowledgeUploadResponse(
            knowledge_id=knowledge_item.id,
            status="success",
            message="知识项上传成功",
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"知识上传失败: {e}")
        raise HTTPException(status_code=500, detail=f"上传失败: {str(e)}")

@router.post("/knowledge/batch", response_model=BatchKnowledgeImportResponse)
async def batch_import_knowledge(
    request: BatchKnowledgeImportRequest,
    background_tasks: BackgroundTasks,
    knowledge_manager: KnowledgeManager = Depends(rag_dependency.get_knowledge_manager)
) -> BatchKnowledgeImportResponse:
    """批量导入知识"""
    try:
        start_time = datetime.now()
        
        # 构建导入请求
        from services.knowledge_manager import ImportRequest, ImportFormat, ValidationLevel
        
        import_request = ImportRequest(
            content=request.content,
            format=ImportFormat(request.format),
            default_knowledge_type=KnowledgeType(request.default_knowledge_type),
            default_tags=request.default_tags,
            validation_level=ValidationLevel(request.validation_level.upper()),
            auto_generate_id=request.auto_generate_id
        )
        
        # 执行批量导入
        import_result = await knowledge_manager.import_knowledge(import_request)
        
        # 计算处理时间
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        return BatchKnowledgeImportResponse(
            successful_imports=import_result.successful_imports,
            failed_imports=import_result.failed_imports,
            total_items=import_result.total_items,
            errors=import_result.errors,
            processing_time_ms=processing_time,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"批量导入失败: {e}")
        raise HTTPException(status_code=500, detail=f"导入失败: {str(e)}")

@router.delete("/knowledge/{knowledge_id}")
async def delete_knowledge(
    knowledge_id: str,
    knowledge_manager: KnowledgeManager = Depends(rag_dependency.get_knowledge_manager)
) -> JSONResponse:
    """删除知识项"""
    try:
        # 删除知识项
        result = await knowledge_manager.delete_knowledge_items([knowledge_id])
        
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": f"知识项 {knowledge_id} 删除成功",
                "deleted_count": result.get('deleted_count', 0),
                "timestamp": datetime.now().isoformat()
            }
        )
        
    except Exception as e:
        logger.error(f"删除知识项失败: {e}")
        raise HTTPException(status_code=500, detail=f"删除失败: {str(e)}")

@router.get("/status", response_model=ServiceStatusResponse)
async def get_service_status(
    rag_service: RAGService = Depends(rag_dependency.get_rag_service),
    pinecone_service: PineconeService = Depends(rag_dependency.get_pinecone_service),
    knowledge_manager: KnowledgeManager = Depends(rag_dependency.get_knowledge_manager)
) -> ServiceStatusResponse:
    """获取服务状态"""
    try:
        # 获取各服务状态
        rag_stats = await rag_service.get_statistics()
        pinecone_stats = await pinecone_service.get_statistics()
        knowledge_stats = await knowledge_manager.get_statistics()
        
        # 合并统计信息
        combined_stats = {
            "rag_service": rag_stats,
            "pinecone_service": pinecone_stats,
            "knowledge_manager": knowledge_stats
        }
        
        return ServiceStatusResponse(
            rag_service_status="active" if rag_service.is_initialized else "inactive",
            pinecone_status="active" if pinecone_service.index else "inactive",
            knowledge_manager_status="active",
            statistics=combined_stats,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"获取服务状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"状态获取失败: {str(e)}")

@router.get("/statistics")
async def get_statistics(
    service: str = Query("all", description="服务类型 (all, rag, pinecone, knowledge)"),
    rag_service: RAGService = Depends(rag_dependency.get_rag_service),
    pinecone_service: PineconeService = Depends(rag_dependency.get_pinecone_service),
    knowledge_manager: KnowledgeManager = Depends(rag_dependency.get_knowledge_manager)
) -> JSONResponse:
    """获取详细统计信息"""
    try:
        stats = {}
        
        if service in ["all", "rag"]:
            stats["rag"] = await rag_service.get_statistics()
        
        if service in ["all", "pinecone"]:
            stats["pinecone"] = await pinecone_service.get_statistics()
        
        if service in ["all", "knowledge"]:
            stats["knowledge"] = await knowledge_manager.get_statistics()
        
        return JSONResponse(
            status_code=200,
            content={
                "statistics": stats,
                "timestamp": datetime.now().isoformat()
            }
        )
        
    except Exception as e:
        logger.error(f"获取统计信息失败: {e}")
        raise HTTPException(status_code=500, detail=f"统计信息获取失败: {str(e)}")

@router.post("/cache/clear")
async def clear_cache(
    service: str = Query("all", description="服务类型 (all, rag, pinecone)"),
    rag_service: RAGService = Depends(rag_dependency.get_rag_service),
    pinecone_service: PineconeService = Depends(rag_dependency.get_pinecone_service)
) -> JSONResponse:
    """清空缓存"""
    try:
        cleared_services = []
        
        if service in ["all", "rag"]:
            await rag_service.clear_cache()
            cleared_services.append("rag")
        
        if service in ["all", "pinecone"]:
            await pinecone_service.clear_cache()
            cleared_services.append("pinecone")
        
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": f"缓存清空成功: {', '.join(cleared_services)}",
                "cleared_services": cleared_services,
                "timestamp": datetime.now().isoformat()
            }
        )
        
    except Exception as e:
        logger.error(f"清空缓存失败: {e}")
        raise HTTPException(status_code=500, detail=f"缓存清空失败: {str(e)}")

# 健康检查端点
@router.get("/health")
async def health_check() -> JSONResponse:
    """健康检查"""
    try:
        # 检查配置
        config_loader = get_config_loader()
        config_valid = config_loader.validate_config()
        
        return JSONResponse(
            status_code=200 if config_valid else 503,
            content={
                "status": "healthy" if config_valid else "unhealthy",
                "config_valid": config_valid,
                "timestamp": datetime.now().isoformat(),
                "version": "1.0.0"
            }
        )
        
    except Exception as e:
        logger.error(f"健康检查失败: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )