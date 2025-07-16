#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS AI决策代理API接口

该模块提供AI决策代理的RESTful API接口，支持：
1. 安全事件处理和决策
2. 工作流状态查询和管理
3. 决策历史和统计信息
4. 系统健康检查和监控
5. 配置管理和更新

作者: NeuronOS Team
创建时间: 2024-12-19
"""

import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
import uvicorn

# 导入决策代理服务
from ..services.ai_decision_integration import AIDecisionIntegration, ExecutionMode
from ..services.ai_decision_agent import RiskLevel, DecisionType

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 创建FastAPI应用
app = FastAPI(
    title="NeuronOS AI决策代理API",
    description="AI驱动的安全事件自动化决策和执行系统",
    version="1.0.0",
    docs_url="/api/ai-decision/docs",
    redoc_url="/api/ai-decision/redoc"
)

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 全局变量
decision_integration: Optional[AIDecisionIntegration] = None

# Pydantic模型定义
class SecurityEvent(BaseModel):
    """安全事件模型"""
    event_type: str = Field(..., description="事件类型")
    severity: str = Field(..., description="严重程度")
    timestamp: str = Field(..., description="事件时间戳")
    source: Optional[str] = Field(None, description="事件来源")
    description: Optional[str] = Field(None, description="事件描述")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="事件元数据")
    
    @validator('severity')
    def validate_severity(cls, v):
        valid_severities = ['low', 'medium', 'high', 'critical']
        if v.lower() not in valid_severities:
            raise ValueError(f'严重程度必须是: {valid_severities}')
        return v.lower()

class ProcessSecurityEventsRequest(BaseModel):
    """处理安全事件请求模型"""
    events: List[SecurityEvent] = Field(..., description="安全事件列表")
    execution_mode: str = Field(default="semi_automatic", description="执行模式")
    user_id: Optional[str] = Field(None, description="用户ID")
    session_id: Optional[str] = Field(None, description="会话ID")
    priority: Optional[str] = Field(default="normal", description="处理优先级")
    
    @validator('execution_mode')
    def validate_execution_mode(cls, v):
        valid_modes = ['automatic', 'semi_automatic', 'manual', 'dry_run']
        if v.lower() not in valid_modes:
            raise ValueError(f'执行模式必须是: {valid_modes}')
        return v.lower()
    
    @validator('priority')
    def validate_priority(cls, v):
        valid_priorities = ['low', 'normal', 'high', 'urgent']
        if v.lower() not in valid_priorities:
            raise ValueError(f'优先级必须是: {valid_priorities}')
        return v.lower()

class WorkflowStatusResponse(BaseModel):
    """工作流状态响应模型"""
    workflow_id: str
    status: str
    current_stage: str
    start_time: str
    progress: Optional[Dict[str, Any]] = None
    error_info: Optional[Dict[str, Any]] = None

class DecisionApprovalRequest(BaseModel):
    """决策审批请求模型"""
    workflow_id: str = Field(..., description="工作流ID")
    approved: bool = Field(..., description="是否批准")
    approver: str = Field(..., description="审批人")
    reason: Optional[str] = Field(None, description="审批原因")
    comments: Optional[str] = Field(None, description="审批备注")

class SystemConfigUpdateRequest(BaseModel):
    """系统配置更新请求模型"""
    config_section: str = Field(..., description="配置节")
    config_data: Dict[str, Any] = Field(..., description="配置数据")
    apply_immediately: bool = Field(default=False, description="是否立即应用")

# 依赖注入
def get_decision_integration() -> AIDecisionIntegration:
    """获取决策集成服务实例"""
    global decision_integration
    if decision_integration is None:
        config_path = "/home/xzj/01_Project/B_25OS/config/ai_decision_config.yaml"
        decision_integration = AIDecisionIntegration(config_path)
    return decision_integration

# API路由定义
@app.post("/api/ai-decision/process-events", 
          response_model=Dict[str, Any],
          summary="处理安全事件",
          description="接收安全事件并启动AI决策流程")
async def process_security_events(
    request: ProcessSecurityEventsRequest,
    background_tasks: BackgroundTasks,
    integration: AIDecisionIntegration = Depends(get_decision_integration)
):
    """处理安全事件API"""
    try:
        logger.info(f"接收到安全事件处理请求，事件数量: {len(request.events)}")
        
        # 转换执行模式
        execution_mode_map = {
            'automatic': ExecutionMode.AUTOMATIC,
            'semi_automatic': ExecutionMode.SEMI_AUTOMATIC,
            'manual': ExecutionMode.MANUAL,
            'dry_run': ExecutionMode.DRY_RUN
        }
        execution_mode = execution_mode_map.get(request.execution_mode, ExecutionMode.SEMI_AUTOMATIC)
        
        # 转换事件格式
        events_data = [event.dict() for event in request.events]
        
        # 启动处理流程
        context = await integration.process_security_events(
            security_events=events_data,
            user_id=request.user_id,
            session_id=request.session_id,
            execution_mode=execution_mode
        )
        
        # 返回工作流信息
        response = {
            'success': True,
            'workflow_id': context.workflow_id,
            'status': context.status.value,
            'current_stage': context.current_stage.value,
            'message': '安全事件处理已启动',
            'estimated_completion_time': None,  # 可以根据历史数据估算
            'tracking_url': f'/api/ai-decision/workflows/{context.workflow_id}'
        }
        
        logger.info(f"安全事件处理启动成功，工作流ID: {context.workflow_id}")
        return response
        
    except Exception as e:
        logger.error(f"处理安全事件失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"处理安全事件失败: {str(e)}"
        )

@app.get("/api/ai-decision/workflows/{workflow_id}",
         response_model=Dict[str, Any],
         summary="获取工作流状态",
         description="查询指定工作流的当前状态和进度")
async def get_workflow_status(
    workflow_id: str,
    integration: AIDecisionIntegration = Depends(get_decision_integration)
):
    """获取工作流状态API"""
    try:
        workflow_data = integration.get_workflow_status(workflow_id)
        
        if not workflow_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"工作流不存在: {workflow_id}"
            )
        
        return {
            'success': True,
            'data': workflow_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取工作流状态失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取工作流状态失败: {str(e)}"
        )

@app.get("/api/ai-decision/workflows",
         response_model=Dict[str, Any],
         summary="获取工作流列表",
         description="获取活跃工作流列表或历史工作流")
async def get_workflows(
    active_only: bool = True,
    limit: int = 50,
    integration: AIDecisionIntegration = Depends(get_decision_integration)
):
    """获取工作流列表API"""
    try:
        if active_only:
            workflows = integration.get_active_workflows()
            workflow_type = "active"
        else:
            workflows = integration.get_workflow_history(limit=limit)
            workflow_type = "history"
        
        return {
            'success': True,
            'type': workflow_type,
            'count': len(workflows),
            'data': workflows
        }
        
    except Exception as e:
        logger.error(f"获取工作流列表失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取工作流列表失败: {str(e)}"
        )

@app.post("/api/ai-decision/workflows/{workflow_id}/approve",
          response_model=Dict[str, Any],
          summary="审批决策",
          description="对待审批的决策进行批准或拒绝")
async def approve_decision(
    workflow_id: str,
    request: DecisionApprovalRequest,
    integration: AIDecisionIntegration = Depends(get_decision_integration)
):
    """审批决策API"""
    try:
        # 验证工作流存在
        workflow_data = integration.get_workflow_status(workflow_id)
        if not workflow_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"工作流不存在: {workflow_id}"
            )
        
        # 检查工作流状态
        if workflow_data.get('current_stage') != 'approval':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="工作流当前不在审批阶段"
            )
        
        # 这里应该实现实际的审批逻辑
        # 目前返回模拟结果
        approval_result = {
            'workflow_id': workflow_id,
            'approved': request.approved,
            'approver': request.approver,
            'approval_time': datetime.now().isoformat(),
            'reason': request.reason,
            'comments': request.comments
        }
        
        logger.info(f"决策审批完成: {workflow_id}, 结果: {request.approved}")
        
        return {
            'success': True,
            'message': '审批完成',
            'data': approval_result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"审批决策失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"审批决策失败: {str(e)}"
        )

@app.delete("/api/ai-decision/workflows/{workflow_id}",
            response_model=Dict[str, Any],
            summary="取消工作流",
            description="取消正在执行的工作流")
async def cancel_workflow(
    workflow_id: str,
    integration: AIDecisionIntegration = Depends(get_decision_integration)
):
    """取消工作流API"""
    try:
        success = await integration.cancel_workflow(workflow_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"工作流不存在或无法取消: {workflow_id}"
            )
        
        return {
            'success': True,
            'message': '工作流已取消',
            'workflow_id': workflow_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"取消工作流失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"取消工作流失败: {str(e)}"
        )

@app.get("/api/ai-decision/statistics",
         response_model=Dict[str, Any],
         summary="获取统计信息",
         description="获取AI决策代理的运行统计信息")
async def get_statistics(
    integration: AIDecisionIntegration = Depends(get_decision_integration)
):
    """获取统计信息API"""
    try:
        stats = integration.get_statistics()
        
        # 添加额外的统计信息
        enhanced_stats = {
            **stats,
            'active_workflows_count': len(integration.get_active_workflows()),
            'success_rate': (
                stats['successful_workflows'] / stats['total_workflows'] 
                if stats['total_workflows'] > 0 else 0
            ),
            'failure_rate': (
                stats['failed_workflows'] / stats['total_workflows'] 
                if stats['total_workflows'] > 0 else 0
            ),
            'rollback_rate': (
                stats['rolled_back_workflows'] / stats['total_workflows'] 
                if stats['total_workflows'] > 0 else 0
            )
        }
        
        return {
            'success': True,
            'data': enhanced_stats
        }
        
    except Exception as e:
        logger.error(f"获取统计信息失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取统计信息失败: {str(e)}"
        )

@app.get("/api/ai-decision/health",
         response_model=Dict[str, Any],
         summary="健康检查",
         description="检查AI决策代理系统的健康状态")
async def health_check(
    integration: AIDecisionIntegration = Depends(get_decision_integration)
):
    """健康检查API"""
    try:
        health_status = await integration.health_check()
        
        # 根据健康状态设置HTTP状态码
        if health_status['status'] == 'healthy':
            status_code = status.HTTP_200_OK
        elif health_status['status'] == 'degraded':
            status_code = status.HTTP_200_OK  # 降级但仍可用
        else:
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        
        return JSONResponse(
            status_code=status_code,
            content={
                'success': health_status['status'] != 'unhealthy',
                'data': health_status
            }
        )
        
    except Exception as e:
        logger.error(f"健康检查失败: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                'success': False,
                'error': f"健康检查失败: {str(e)}"
            }
        )

@app.post("/api/ai-decision/config/update",
          response_model=Dict[str, Any],
          summary="更新配置",
          description="更新AI决策代理的配置参数")
async def update_config(
    request: SystemConfigUpdateRequest,
    integration: AIDecisionIntegration = Depends(get_decision_integration)
):
    """更新配置API"""
    try:
        # 这里应该实现配置更新逻辑
        # 目前返回模拟结果
        
        logger.info(f"配置更新请求: {request.config_section}")
        
        # 验证配置数据
        if not request.config_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="配置数据不能为空"
            )
        
        # 模拟配置更新
        update_result = {
            'config_section': request.config_section,
            'updated_keys': list(request.config_data.keys()),
            'applied_immediately': request.apply_immediately,
            'update_time': datetime.now().isoformat()
        }
        
        return {
            'success': True,
            'message': '配置更新成功',
            'data': update_result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"更新配置失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"更新配置失败: {str(e)}"
        )

@app.get("/api/ai-decision/config",
         response_model=Dict[str, Any],
         summary="获取配置",
         description="获取AI决策代理的当前配置")
async def get_config(
    section: Optional[str] = None,
    integration: AIDecisionIntegration = Depends(get_decision_integration)
):
    """获取配置API"""
    try:
        # 这里应该实现配置获取逻辑
        # 目前返回模拟配置
        
        mock_config = {
            'basic': {
                'default_execution_mode': 'semi_automatic',
                'risk_threshold': 60.0,
                'max_concurrent_executions': 3
            },
            'risk_levels': {
                'very_low': {'range': [0, 20], 'auto_execute': True},
                'low': {'range': [21, 40], 'auto_execute': True},
                'medium': {'range': [41, 60], 'auto_execute': False}
            },
            'notifications': {
                'decision_notifications': {'enabled': True},
                'execution_notifications': {'enabled': True}
            }
        }
        
        if section:
            if section not in mock_config:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"配置节不存在: {section}"
                )
            config_data = {section: mock_config[section]}
        else:
            config_data = mock_config
        
        return {
            'success': True,
            'data': config_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取配置失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取配置失败: {str(e)}"
        )

# 事件处理器
@app.on_event("startup")
async def startup_event():
    """应用启动事件"""
    logger.info("AI决策代理API服务启动")
    
    # 初始化决策集成服务
    global decision_integration
    try:
        config_path = "/home/xzj/01_Project/B_25OS/config/ai_decision_config.yaml"
        decision_integration = AIDecisionIntegration(config_path)
        logger.info("决策集成服务初始化成功")
    except Exception as e:
        logger.error(f"决策集成服务初始化失败: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭事件"""
    logger.info("AI决策代理API服务关闭")
    
    # 清理资源
    global decision_integration
    if decision_integration:
        # 取消所有活跃工作流
        active_workflows = decision_integration.get_active_workflows()
        for workflow in active_workflows:
            try:
                await decision_integration.cancel_workflow(workflow['workflow_id'])
            except Exception as e:
                logger.error(f"取消工作流失败: {workflow['workflow_id']}, 错误: {e}")

# 异常处理器
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """全局异常处理器"""
    logger.error(f"未处理的异常: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            'success': False,
            'error': '内部服务器错误',
            'detail': str(exc) if app.debug else '请联系系统管理员'
        }
    )

# 主函数
if __name__ == "__main__":
    uvicorn.run(
        "ai_decision_api:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )