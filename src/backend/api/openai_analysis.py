#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenAI分析API模块
提供OpenAI安全事件分析的REST API接口
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from fastapi.responses import JSONResponse
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, validator
from enum import Enum

from loguru import logger

from services.openai_service import (
    OpenAIService,
    AnalysisRequest,
    AnalysisResponse,
    AnalysisType,
    Priority,
    openai_service
)


router = APIRouter(prefix="/api/openai", tags=["OpenAI Analysis"])


class AnalysisTypeEnum(str, Enum):
    """分析类型枚举（用于API）"""
    SECURITY_ANALYSIS = "security_analysis"
    THREAT_ASSESSMENT = "threat_assessment"
    INCIDENT_RESPONSE = "incident_response"
    REMEDIATION_ADVICE = "remediation_advice"
    PATTERN_ANALYSIS = "pattern_analysis"
    RISK_EVALUATION = "risk_evaluation"


class PriorityEnum(str, Enum):
    """优先级枚举（用于API）"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventData(BaseModel):
    """事件数据模型"""
    event_id: Optional[str] = None
    timestamp: Optional[str] = None
    rule: Optional[str] = None
    priority: Optional[str] = None
    message: Optional[str] = None
    output: Optional[str] = None
    hostname: Optional[str] = None
    source: Optional[str] = None
    tags: Optional[List[str]] = None
    fields: Optional[Dict[str, Any]] = None
    
    class Config:
        schema_extra = {
            "example": {
                "event_id": "evt_12345",
                "timestamp": "2025-01-15T10:30:00Z",
                "rule": "Suspicious Process Execution",
                "priority": "HIGH",
                "message": "Suspicious process detected",
                "output": "Process /bin/bash executed with suspicious arguments",
                "hostname": "web-server-01",
                "source": "falco",
                "tags": ["process", "suspicious"],
                "fields": {
                    "proc.name": "bash",
                    "proc.cmdline": "/bin/bash -c 'whoami'",
                    "user.name": "www-data"
                }
            }
        }


class AnalysisRequestModel(BaseModel):
    """分析请求模型"""
    analysis_type: AnalysisTypeEnum = AnalysisTypeEnum.SECURITY_ANALYSIS
    events: List[EventData]
    context: Optional[Dict[str, Any]] = None
    priority: PriorityEnum = PriorityEnum.MEDIUM
    max_tokens: int = Field(default=2000, ge=100, le=4000)
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    request_id: Optional[str] = None
    
    @validator('events')
    def validate_events(cls, v):
        if not v:
            raise ValueError("At least one event is required")
        if len(v) > 50:
            raise ValueError("Maximum 50 events per request")
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "analysis_type": "security_analysis",
                "events": [
                    {
                        "event_id": "evt_12345",
                        "timestamp": "2025-01-15T10:30:00Z",
                        "rule": "Suspicious Process Execution",
                        "priority": "HIGH",
                        "message": "Suspicious process detected",
                        "hostname": "web-server-01"
                    }
                ],
                "context": {
                    "system_info": "Ubuntu 20.04 web server",
                    "recent_changes": "New deployment yesterday"
                },
                "priority": "HIGH",
                "max_tokens": 2000,
                "temperature": 0.1
            }
        }


class BatchAnalysisRequest(BaseModel):
    """批量分析请求模型"""
    requests: List[AnalysisRequestModel]
    max_concurrent: int = Field(default=5, ge=1, le=10)
    
    @validator('requests')
    def validate_requests(cls, v):
        if not v:
            raise ValueError("At least one analysis request is required")
        if len(v) > 20:
            raise ValueError("Maximum 20 requests per batch")
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "requests": [
                    {
                        "analysis_type": "security_analysis",
                        "events": [
                            {
                                "event_id": "evt_12345",
                                "rule": "Suspicious Process Execution",
                                "priority": "HIGH"
                            }
                        ]
                    }
                ],
                "max_concurrent": 3
            }
        }


class AnalysisResponseModel(BaseModel):
    """分析响应模型"""
    request_id: str
    analysis_type: str
    summary: str
    detailed_analysis: str
    recommendations: List[str]
    risk_score: float
    confidence: float
    priority: str
    affected_systems: List[str]
    attack_vectors: List[str]
    mitigation_steps: List[str]
    timestamp: str
    processing_time: float
    token_usage: Dict[str, int]
    
    class Config:
        schema_extra = {
            "example": {
                "request_id": "security_analysis_abc12345_1642234567",
                "analysis_type": "security_analysis",
                "summary": "Detected suspicious process execution on web server",
                "detailed_analysis": "The event shows execution of bash with suspicious arguments...",
                "recommendations": [
                    "Investigate the source of the command execution",
                    "Check for unauthorized access",
                    "Review system logs for related activities"
                ],
                "risk_score": 75.0,
                "confidence": 0.85,
                "priority": "HIGH",
                "affected_systems": ["web-server-01"],
                "attack_vectors": ["Command injection", "Privilege escalation"],
                "mitigation_steps": [
                    "Disable the compromised account",
                    "Update system patches",
                    "Implement additional monitoring"
                ],
                "timestamp": "2025-01-15T10:35:00Z",
                "processing_time": 3.45,
                "token_usage": {
                    "prompt_tokens": 1200,
                    "completion_tokens": 800,
                    "total_tokens": 2000
                }
            }
        }


class StatisticsResponse(BaseModel):
    """统计信息响应模型"""
    total_requests: int
    successful_requests: int
    failed_requests: int
    cache_hits: int
    total_tokens: int
    total_cost: float
    cache_size: int
    success_rate: float
    cache_hit_rate: float
    
    class Config:
        schema_extra = {
            "example": {
                "total_requests": 150,
                "successful_requests": 145,
                "failed_requests": 5,
                "cache_hits": 30,
                "total_tokens": 250000,
                "total_cost": 5.25,
                "cache_size": 25,
                "success_rate": 96.67,
                "cache_hit_rate": 20.0
            }
        }


def get_openai_service() -> OpenAIService:
    """获取OpenAI服务实例"""
    return openai_service


@router.post("/analyze", response_model=AnalysisResponseModel)
async def analyze_security_events(
    request: AnalysisRequestModel,
    service: OpenAIService = Depends(get_openai_service)
):
    """
    分析安全事件
    
    Args:
        request: 分析请求数据
        service: OpenAI服务实例
    
    Returns:
        AnalysisResponseModel: 分析结果
    
    Raises:
        HTTPException: 当分析失败时
    """
    try:
        # 转换事件数据
        events = [event.dict(exclude_none=True) for event in request.events]
        
        # 创建分析请求
        analysis_request = AnalysisRequest(
            analysis_type=AnalysisType(request.analysis_type.value),
            events=events,
            context=request.context,
            priority=Priority(request.priority.value),
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            request_id=request.request_id
        )
        
        # 执行分析
        response = await service.analyze_security_events(analysis_request)
        
        # 转换响应格式
        return AnalysisResponseModel(**response.to_dict())
        
    except ValueError as e:
        logger.error(f"Invalid request parameters: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Analysis failed")


@router.post("/batch-analyze", response_model=List[AnalysisResponseModel])
async def batch_analyze_events(
    request: BatchAnalysisRequest,
    service: OpenAIService = Depends(get_openai_service)
):
    """
    批量分析安全事件
    
    Args:
        request: 批量分析请求数据
        service: OpenAI服务实例
    
    Returns:
        List[AnalysisResponseModel]: 分析结果列表
    
    Raises:
        HTTPException: 当分析失败时
    """
    try:
        # 转换请求数据
        analysis_requests = []
        for req in request.requests:
            events = [event.dict(exclude_none=True) for event in req.events]
            analysis_request = AnalysisRequest(
                analysis_type=AnalysisType(req.analysis_type.value),
                events=events,
                context=req.context,
                priority=Priority(req.priority.value),
                max_tokens=req.max_tokens,
                temperature=req.temperature,
                request_id=req.request_id
            )
            analysis_requests.append(analysis_request)
        
        # 执行批量分析
        responses = await service.batch_analyze(
            analysis_requests,
            request.max_concurrent
        )
        
        # 转换响应格式
        return [AnalysisResponseModel(**response.to_dict()) for response in responses]
        
    except ValueError as e:
        logger.error(f"Invalid batch request parameters: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Batch analysis failed")


@router.post("/quick-analysis/{analysis_type}")
async def quick_analysis(
    analysis_type: AnalysisTypeEnum,
    events: List[EventData],
    context: Optional[Dict[str, Any]] = None,
    priority: PriorityEnum = PriorityEnum.MEDIUM,
    service: OpenAIService = Depends(get_openai_service)
):
    """
    快速分析接口
    
    Args:
        analysis_type: 分析类型
        events: 事件列表
        context: 上下文信息
        priority: 优先级
        service: OpenAI服务实例
    
    Returns:
        分析结果
    """
    try:
        if not events:
            raise HTTPException(status_code=400, detail="At least one event is required")
        
        if len(events) > 20:
            raise HTTPException(status_code=400, detail="Maximum 20 events for quick analysis")
        
        # 转换事件数据
        event_dicts = [event.dict(exclude_none=True) for event in events]
        
        # 创建分析请求
        analysis_request = AnalysisRequest(
            analysis_type=AnalysisType(analysis_type.value),
            events=event_dicts,
            context=context,
            priority=Priority(priority.value)
        )
        
        # 执行分析
        response = await service.analyze_security_events(analysis_request)
        
        return response.to_dict()
        
    except ValueError as e:
        logger.error(f"Invalid quick analysis parameters: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Quick analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Quick analysis failed")


@router.get("/remediation-advice")
async def get_remediation_advice(
    event_ids: List[str] = Query(..., description="事件ID列表"),
    context: Optional[str] = Query(None, description="上下文信息（JSON字符串）"),
    service: OpenAIService = Depends(get_openai_service)
):
    """
    获取修复建议
    
    Args:
        event_ids: 事件ID列表
        context: 上下文信息
        service: OpenAI服务实例
    
    Returns:
        修复建议
    """
    try:
        # 这里应该从数据库获取事件详情，暂时使用模拟数据
        events = [
            {
                "event_id": event_id,
                "message": f"Event {event_id} requires remediation",
                "priority": "HIGH"
            }
            for event_id in event_ids
        ]
        
        # 解析上下文
        context_dict = None
        if context:
            try:
                import json
                context_dict = json.loads(context)
            except json.JSONDecodeError:
                context_dict = {"raw_context": context}
        
        # 创建分析请求
        analysis_request = AnalysisRequest(
            analysis_type=AnalysisType.REMEDIATION_ADVICE,
            events=events,
            context=context_dict,
            priority=Priority.HIGH
        )
        
        # 执行分析
        response = await service.analyze_security_events(analysis_request)
        
        return {
            "request_id": response.request_id,
            "recommendations": response.recommendations,
            "mitigation_steps": response.mitigation_steps,
            "risk_score": response.risk_score,
            "confidence": response.confidence,
            "processing_time": response.processing_time
        }
        
    except Exception as e:
        logger.error(f"Failed to get remediation advice: {e}")
        raise HTTPException(status_code=500, detail="Failed to get remediation advice")


@router.get("/threat-assessment")
async def assess_threat(
    event_ids: List[str] = Query(..., description="事件ID列表"),
    context: Optional[str] = Query(None, description="上下文信息（JSON字符串）"),
    service: OpenAIService = Depends(get_openai_service)
):
    """
    威胁评估
    
    Args:
        event_ids: 事件ID列表
        context: 上下文信息
        service: OpenAI服务实例
    
    Returns:
        威胁评估结果
    """
    try:
        # 这里应该从数据库获取事件详情，暂时使用模拟数据
        events = [
            {
                "event_id": event_id,
                "message": f"Threat assessment for event {event_id}",
                "priority": "HIGH"
            }
            for event_id in event_ids
        ]
        
        # 解析上下文
        context_dict = None
        if context:
            try:
                import json
                context_dict = json.loads(context)
            except json.JSONDecodeError:
                context_dict = {"raw_context": context}
        
        # 创建分析请求
        analysis_request = AnalysisRequest(
            analysis_type=AnalysisType.THREAT_ASSESSMENT,
            events=events,
            context=context_dict,
            priority=Priority.HIGH
        )
        
        # 执行分析
        response = await service.analyze_security_events(analysis_request)
        
        return {
            "request_id": response.request_id,
            "summary": response.summary,
            "detailed_analysis": response.detailed_analysis,
            "risk_score": response.risk_score,
            "confidence": response.confidence,
            "attack_vectors": response.attack_vectors,
            "affected_systems": response.affected_systems,
            "processing_time": response.processing_time
        }
        
    except Exception as e:
        logger.error(f"Failed to assess threat: {e}")
        raise HTTPException(status_code=500, detail="Failed to assess threat")


@router.get("/statistics", response_model=StatisticsResponse)
async def get_statistics(
    service: OpenAIService = Depends(get_openai_service)
):
    """
    获取OpenAI服务统计信息
    
    Args:
        service: OpenAI服务实例
    
    Returns:
        StatisticsResponse: 统计信息
    """
    try:
        stats = service.get_statistics()
        return StatisticsResponse(**stats)
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get statistics")


@router.post("/cache/clear")
async def clear_cache(
    service: OpenAIService = Depends(get_openai_service)
):
    """
    清空缓存
    
    Args:
        service: OpenAI服务实例
    
    Returns:
        操作结果
    """
    try:
        service.clear_cache()
        return {"message": "Cache cleared successfully"}
    except Exception as e:
        logger.error(f"Failed to clear cache: {e}")
        raise HTTPException(status_code=500, detail="Failed to clear cache")


@router.post("/cache/cleanup")
async def cleanup_cache(
    service: OpenAIService = Depends(get_openai_service)
):
    """
    清理过期缓存
    
    Args:
        service: OpenAI服务实例
    
    Returns:
        操作结果
    """
    try:
        service.cleanup_expired_cache()
        return {"message": "Expired cache cleaned up successfully"}
    except Exception as e:
        logger.error(f"Failed to cleanup cache: {e}")
        raise HTTPException(status_code=500, detail="Failed to cleanup cache")


@router.get("/health")
async def health_check(
    service: OpenAIService = Depends(get_openai_service)
):
    """
    健康检查
    
    Args:
        service: OpenAI服务实例
    
    Returns:
        健康状态
    """
    try:
        stats = service.get_statistics()
        
        # 检查服务状态
        is_healthy = True
        issues = []
        
        # 检查成功率
        if stats['success_rate'] < 90:
            is_healthy = False
            issues.append(f"Low success rate: {stats['success_rate']:.2f}%")
        
        # 检查OpenAI客户端
        if service.client is None:
            is_healthy = False
            issues.append("OpenAI client not initialized")
        
        return {
            "status": "healthy" if is_healthy else "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "statistics": stats,
            "issues": issues
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }


@router.get("/templates")
async def get_analysis_templates():
    """
    获取分析模板信息
    
    Returns:
        模板信息
    """
    try:
        from services.openai_service import PromptTemplate
        
        templates = {}
        for analysis_type in AnalysisType:
            template = PromptTemplate.get_template(analysis_type)
            templates[analysis_type.value] = {
                "name": analysis_type.value,
                "description": f"Template for {analysis_type.value}",
                "template_length": len(template),
                "preview": template[:200] + "..." if len(template) > 200 else template
            }
        
        return {
            "templates": templates,
            "total_templates": len(templates)
        }
        
    except Exception as e:
        logger.error(f"Failed to get templates: {e}")
        raise HTTPException(status_code=500, detail="Failed to get templates")