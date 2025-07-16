#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
图查询优化API模块
提供图查询优化器的REST API接口
"""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, validator
from enum import Enum

from loguru import logger

from services.graph_query_optimizer import (
    GraphQueryOptimizer,
    QueryType,
    TimeWindow,
    QueryResult,
    create_query_optimizer
)
from services.graph_database import create_graph_manager
from config.query_optimizer_config import (
    query_optimizer_config,
    QueryOptimizationLevel,
    get_config_summary
)


# 创建路由器
router = APIRouter(prefix="/api/graph-query", tags=["Graph Query Optimization"])


# 全局查询优化器实例
_query_optimizer: Optional[GraphQueryOptimizer] = None


# Pydantic模型定义
class QueryTypeEnum(str, Enum):
    """查询类型枚举"""
    ATTACK_PATH = "attack_path"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    ANOMALY_DETECTION = "anomaly_detection"
    TIMELINE_ANALYSIS = "timeline_analysis"
    CORRELATION_ANALYSIS = "correlation_analysis"
    PATTERN_MATCHING = "pattern_matching"


class TimeWindowEnum(str, Enum):
    """时间窗口枚举"""
    LAST_HOUR = "1h"
    LAST_6_HOURS = "6h"
    LAST_DAY = "24h"
    LAST_WEEK = "7d"
    LAST_MONTH = "30d"
    CUSTOM = "custom"


class QueryTemplateRequest(BaseModel):
    """查询模板请求模型"""
    template_name: str = Field(..., description="查询模板名称")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="查询参数")
    use_cache: bool = Field(True, description="是否使用缓存")
    
    class Config:
        schema_extra = {
            "example": {
                "template_name": "attack_path_basic",
                "parameters": {
                    "start_time": "2024-01-01T00:00:00Z",
                    "end_time": "2024-01-01T23:59:59Z",
                    "max_results": 100
                },
                "use_cache": True
            }
        }


class AttackPathRequest(BaseModel):
    """攻击路径追踪请求模型"""
    start_event_id: str = Field(..., description="起始事件ID")
    end_event_id: Optional[str] = Field(None, description="结束事件ID（可选）")
    max_depth: int = Field(5, ge=1, le=10, description="最大搜索深度")
    time_window_hours: int = Field(24, ge=1, le=168, description="时间窗口（小时）")
    
    class Config:
        schema_extra = {
            "example": {
                "start_event_id": "event_12345",
                "end_event_id": "event_67890",
                "max_depth": 5,
                "time_window_hours": 24
            }
        }


class TimeWindowAnalysisRequest(BaseModel):
    """时间窗口分析请求模型"""
    time_window: TimeWindowEnum = Field(..., description="时间窗口类型")
    custom_start: Optional[datetime] = Field(None, description="自定义开始时间")
    custom_end: Optional[datetime] = Field(None, description="自定义结束时间")
    priority_filter: Optional[List[str]] = Field(None, description="优先级过滤")
    host_filter: Optional[str] = Field(None, description="主机过滤")
    
    @validator('custom_start', 'custom_end')
    def validate_custom_times(cls, v, values):
        if values.get('time_window') == TimeWindowEnum.CUSTOM:
            if v is None:
                raise ValueError('自定义时间窗口需要指定开始和结束时间')
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "time_window": "24h",
                "priority_filter": ["HIGH", "CRITICAL"],
                "host_filter": "web-server-01"
            }
        }


class CorrelationAnalysisRequest(BaseModel):
    """关联分析请求模型"""
    event_id: str = Field(..., description="中心事件ID")
    correlation_window_seconds: int = Field(3600, ge=60, le=86400, description="关联时间窗口（秒）")
    max_depth: int = Field(3, ge=1, le=5, description="最大关联深度")
    
    class Config:
        schema_extra = {
            "example": {
                "event_id": "event_12345",
                "correlation_window_seconds": 3600,
                "max_depth": 3
            }
        }


class QueryResultResponse(BaseModel):
    """查询结果响应模型"""
    query_id: str
    query_type: str
    execution_time: float
    result_count: int
    cache_hit: bool
    timestamp: datetime
    data: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class PerformanceMetricsResponse(BaseModel):
    """性能指标响应模型"""
    query_count: int
    total_execution_time: float
    avg_execution_time: float
    cache_hit_rate: float
    slow_queries: List[Dict[str, Any]]
    error_count: int


class CacheStatsResponse(BaseModel):
    """缓存统计响应模型"""
    total_entries: int
    valid_entries: int
    hit_rate: float
    memory_usage_estimate: int


class TemplateInfoResponse(BaseModel):
    """模板信息响应模型"""
    name: str
    type: str
    description: str
    parameters: List[str]
    cache_ttl: int
    max_results: int


# 依赖函数
async def get_query_optimizer() -> GraphQueryOptimizer:
    """获取查询优化器实例"""
    global _query_optimizer
    
    if _query_optimizer is None:
        try:
            # 需要从配置中获取数据库连接参数
            from config.settings import get_settings
            settings = get_settings()
            graph_manager = await create_graph_manager(
                settings.neo4j_uri,
                settings.neo4j_user,
                settings.neo4j_password
            )
            _query_optimizer = await create_query_optimizer(graph_manager)
            logger.info("Graph query optimizer initialized")
        except Exception as e:
            logger.error(f"Failed to initialize query optimizer: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to initialize query optimizer: {str(e)}"
            )
    
    return _query_optimizer


# API端点
@router.get("/templates", response_model=List[TemplateInfoResponse])
async def list_query_templates(
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    获取可用的查询模板列表
    
    Returns:
        List[TemplateInfoResponse]: 查询模板信息列表
    """
    try:
        templates = optimizer.list_available_templates()
        return [TemplateInfoResponse(**template) for template in templates]
    except Exception as e:
        logger.error(f"Failed to list query templates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute", response_model=QueryResultResponse)
async def execute_query_template(
    request: QueryTemplateRequest,
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    执行查询模板
    
    Args:
        request: 查询模板请求
        
    Returns:
        QueryResultResponse: 查询结果
    """
    try:
        # 验证参数
        warnings = query_optimizer_config.validate_query_parameters(
            request.template_name,
            request.parameters
        )
        
        if warnings:
            logger.warning(f"Query parameter warnings: {warnings}")
        
        # 执行查询
        result = await optimizer.execute_template_query(
            request.template_name,
            request.parameters,
            request.use_cache
        )
        
        return QueryResultResponse(
            query_id=result.query_id,
            query_type=result.query_type.value,
            execution_time=result.execution_time,
            result_count=result.result_count,
            cache_hit=result.cache_hit,
            timestamp=result.timestamp,
            data=result.data,
            metadata=result.metadata
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to execute query template: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack-path", response_model=Dict[str, Any])
async def trace_attack_path(
    request: AttackPathRequest,
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    追踪攻击路径
    
    Args:
        request: 攻击路径追踪请求
        
    Returns:
        Dict[str, Any]: 攻击路径分析结果
    """
    try:
        result = await optimizer.trace_attack_path(
            start_event_id=request.start_event_id,
            end_event_id=request.end_event_id,
            max_depth=request.max_depth,
            time_window_hours=request.time_window_hours
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to trace attack path: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/time-window-analysis", response_model=Dict[str, Any])
async def analyze_time_window(
    request: TimeWindowAnalysisRequest,
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    时间窗口分析
    
    Args:
        request: 时间窗口分析请求
        
    Returns:
        Dict[str, Any]: 时间窗口分析结果
    """
    try:
        # 转换时间窗口枚举
        time_window_mapping = {
            TimeWindowEnum.LAST_HOUR: TimeWindow.LAST_HOUR,
            TimeWindowEnum.LAST_6_HOURS: TimeWindow.LAST_6_HOURS,
            TimeWindowEnum.LAST_DAY: TimeWindow.LAST_DAY,
            TimeWindowEnum.LAST_WEEK: TimeWindow.LAST_WEEK,
            TimeWindowEnum.LAST_MONTH: TimeWindow.LAST_MONTH,
            TimeWindowEnum.CUSTOM: TimeWindow.CUSTOM
        }
        
        time_window = time_window_mapping[request.time_window]
        
        result = await optimizer.analyze_time_window(
            time_window=time_window,
            custom_start=request.custom_start,
            custom_end=request.custom_end,
            priority_filter=request.priority_filter,
            host_filter=request.host_filter
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to analyze time window: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/correlation-analysis", response_model=Dict[str, Any])
async def find_correlation_patterns(
    request: CorrelationAnalysisRequest,
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    查找事件关联模式
    
    Args:
        request: 关联分析请求
        
    Returns:
        Dict[str, Any]: 关联模式分析结果
    """
    try:
        result = await optimizer.find_correlation_patterns(
            event_id=request.event_id,
            correlation_window_seconds=request.correlation_window_seconds,
            max_depth=request.max_depth
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to find correlation patterns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/performance", response_model=PerformanceMetricsResponse)
async def get_performance_metrics(
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    获取查询性能指标
    
    Returns:
        PerformanceMetricsResponse: 性能指标
    """
    try:
        metrics = optimizer.get_performance_metrics()
        
        return PerformanceMetricsResponse(
            query_count=metrics.query_count,
            total_execution_time=metrics.total_execution_time,
            avg_execution_time=metrics.avg_execution_time,
            cache_hit_rate=metrics.cache_hit_rate,
            slow_queries=metrics.slow_queries,
            error_count=metrics.error_count
        )
        
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cache/stats", response_model=CacheStatsResponse)
async def get_cache_statistics(
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    获取缓存统计信息
    
    Returns:
        CacheStatsResponse: 缓存统计
    """
    try:
        stats = optimizer.get_cache_stats()
        
        return CacheStatsResponse(
            total_entries=stats["total_entries"],
            valid_entries=stats["valid_entries"],
            hit_rate=stats["hit_rate"],
            memory_usage_estimate=stats["memory_usage_estimate"]
        )
        
    except Exception as e:
        logger.error(f"Failed to get cache statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cache/clear")
async def clear_query_cache(
    background_tasks: BackgroundTasks,
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    清理查询缓存
    
    Returns:
        Dict[str, str]: 操作结果
    """
    try:
        # 在后台任务中清理缓存
        background_tasks.add_task(optimizer.clear_cache)
        
        return {"message": "Cache clearing initiated"}
        
    except Exception as e:
        logger.error(f"Failed to clear cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config")
async def get_optimizer_config():
    """
    获取查询优化器配置信息
    
    Returns:
        Dict[str, Any]: 配置信息
    """
    try:
        config_summary = get_config_summary()
        
        # 添加额外的配置信息
        config_summary["index_recommendations"] = query_optimizer_config.index_recommendations
        config_summary["rewrite_rules"] = query_optimizer_config.rewrite_rules
        
        return config_summary
        
    except Exception as e:
        logger.error(f"Failed to get optimizer config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check(
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    健康检查端点
    
    Returns:
        Dict[str, Any]: 健康状态信息
    """
    try:
        # 检查优化器状态
        metrics = optimizer.get_performance_metrics()
        cache_stats = optimizer.get_cache_stats()
        
        # 计算健康分数
        health_score = 100
        
        # 根据错误率降低健康分数
        if metrics.query_count > 0:
            error_rate = metrics.error_count / metrics.query_count
            health_score -= error_rate * 50
        
        # 根据平均执行时间降低健康分数
        if metrics.avg_execution_time > 10:  # 超过10秒
            health_score -= 20
        elif metrics.avg_execution_time > 5:  # 超过5秒
            health_score -= 10
        
        # 根据缓存命中率调整健康分数
        if metrics.cache_hit_rate < 0.3:  # 缓存命中率低于30%
            health_score -= 10
        
        health_score = max(0, min(100, health_score))
        
        status = "healthy" if health_score >= 80 else "degraded" if health_score >= 50 else "unhealthy"
        
        return {
            "status": status,
            "health_score": health_score,
            "timestamp": datetime.now().isoformat(),
            "metrics": {
                "query_count": metrics.query_count,
                "avg_execution_time": metrics.avg_execution_time,
                "cache_hit_rate": metrics.cache_hit_rate,
                "error_count": metrics.error_count
            },
            "cache": {
                "total_entries": cache_stats["total_entries"],
                "valid_entries": cache_stats["valid_entries"]
            }
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "health_score": 0,
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }


# 查询优化建议端点
@router.get("/optimization-hints/{template_name}")
async def get_optimization_hints(
    template_name: str,
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    获取查询优化建议
    
    Args:
        template_name: 模板名称
        
    Returns:
        Dict[str, Any]: 优化建议
    """
    try:
        if template_name not in optimizer.query_templates:
            raise HTTPException(status_code=404, detail=f"Template '{template_name}' not found")
        
        hints = query_optimizer_config.get_optimization_hints(template_name)
        template_config = query_optimizer_config.get_template_config(template_name)
        
        return {
            "template_name": template_name,
            "optimization_level": template_config.optimization_level.value,
            "performance_hints": hints,
            "cache_ttl": template_config.cache_ttl,
            "max_results": template_config.max_results,
            "priority": template_config.priority
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get optimization hints: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# 批量查询端点
@router.post("/batch-execute")
async def batch_execute_queries(
    requests: List[QueryTemplateRequest],
    optimizer: GraphQueryOptimizer = Depends(get_query_optimizer)
):
    """
    批量执行查询模板
    
    Args:
        requests: 查询模板请求列表
        
    Returns:
        List[Dict[str, Any]]: 批量查询结果
    """
    if len(requests) > 10:  # 限制批量查询数量
        raise HTTPException(status_code=400, detail="Batch size cannot exceed 10 queries")
    
    results = []
    
    for i, request in enumerate(requests):
        try:
            result = await optimizer.execute_template_query(
                request.template_name,
                request.parameters,
                request.use_cache
            )
            
            results.append({
                "index": i,
                "success": True,
                "result": {
                    "query_id": result.query_id,
                    "query_type": result.query_type.value,
                    "execution_time": result.execution_time,
                    "result_count": result.result_count,
                    "cache_hit": result.cache_hit,
                    "data": result.data
                }
            })
            
        except Exception as e:
            logger.error(f"Batch query {i} failed: {e}")
            results.append({
                "index": i,
                "success": False,
                "error": str(e)
            })
    
    return {
        "total_queries": len(requests),
        "successful_queries": sum(1 for r in results if r["success"]),
        "failed_queries": sum(1 for r in results if not r["success"]),
        "results": results
    }


# 注意：错误处理和生命周期事件应该在main.py的FastAPI应用级别处理
# APIRouter不支持exception_handler和on_event装饰器