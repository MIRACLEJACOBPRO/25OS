#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS AI决策代理集成模块

该模块负责整合AI决策代理的所有组件，提供统一的接口和工作流程。
主要功能：
1. 集成OpenAI分析服务、决策代理、命令执行器和效果验证器
2. 提供完整的决策-执行-验证工作流
3. 管理决策上下文和执行状态
4. 处理异常情况和回滚操作
5. 提供监控和审计功能

作者: NeuronOS Team
创建时间: 2024-12-19
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import yaml
import json

# 导入相关服务模块
from .openai_service import OpenAIService, AnalysisResponse
from .ai_decision_agent import AIDecisionAgent, DecisionContext, DecisionResult, ExecutionMode
from .command_executor import CommandExecutor, ExecutionResult, ExecutionStatus
from .effect_validator import EffectValidator, EffectValidationResult, ValidationType
from .command_template_manager import CommandTemplateManager

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IntegrationStatus(Enum):
    """集成状态枚举"""
    IDLE = "idle"
    ANALYZING = "analyzing"
    DECIDING = "deciding"
    EXECUTING = "executing"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

class WorkflowStage(Enum):
    """工作流阶段枚举"""
    PREPARATION = "preparation"
    ANALYSIS = "analysis"
    DECISION = "decision"
    APPROVAL = "approval"
    EXECUTION = "execution"
    VALIDATION = "validation"
    COMPLETION = "completion"
    ROLLBACK = "rollback"

@dataclass
class WorkflowContext:
    """工作流上下文"""
    workflow_id: str
    session_id: str
    user_id: Optional[str] = None
    start_time: datetime = field(default_factory=datetime.now)
    current_stage: WorkflowStage = WorkflowStage.PREPARATION
    status: IntegrationStatus = IntegrationStatus.IDLE
    
    # 输入数据
    security_events: List[Dict[str, Any]] = field(default_factory=list)
    analysis_request: Optional[Dict[str, Any]] = None
    
    # 处理结果
    analysis_result: Optional[AnalysisResponse] = None
    decision_result: Optional[DecisionResult] = None
    execution_results: List[ExecutionResult] = field(default_factory=list)
    validation_results: List[EffectValidationResult] = field(default_factory=list)
    
    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_info: Optional[Dict[str, Any]] = None
    rollback_info: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'workflow_id': self.workflow_id,
            'session_id': self.session_id,
            'user_id': self.user_id,
            'start_time': self.start_time.isoformat(),
            'current_stage': self.current_stage.value,
            'status': self.status.value,
            'security_events': self.security_events,
            'analysis_request': self.analysis_request,
            'analysis_result': self.analysis_result.to_dict() if self.analysis_result else None,
            'decision_result': self.decision_result.to_dict() if self.decision_result else None,
            'execution_results': [result.to_dict() for result in self.execution_results],
            'validation_results': [result.to_dict() for result in self.validation_results],
            'metadata': self.metadata,
            'error_info': self.error_info,
            'rollback_info': self.rollback_info
        }

@dataclass
class IntegrationConfig:
    """集成配置"""
    # 基础配置
    max_concurrent_workflows: int = 5
    workflow_timeout: int = 1800  # 30分钟
    stage_timeout: int = 300      # 5分钟
    
    # 重试配置
    max_retries: int = 3
    retry_delay: float = 1.0
    
    # 审批配置
    require_approval: bool = True
    approval_timeout: int = 1800  # 30分钟
    
    # 验证配置
    enable_validation: bool = True
    validation_timeout: int = 120  # 2分钟
    
    # 回滚配置
    enable_rollback: bool = True
    auto_rollback_on_failure: bool = True
    rollback_timeout: int = 300   # 5分钟
    
    # 监控配置
    enable_monitoring: bool = True
    metrics_collection: bool = True
    audit_logging: bool = True
    
    @classmethod
    def from_yaml(cls, config_path: str) -> 'IntegrationConfig':
        """从YAML文件加载配置"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            # 提取相关配置
            basic_config = config_data.get('basic', {})
            
            return cls(
                max_concurrent_workflows=basic_config.get('max_concurrent_executions', 5),
                workflow_timeout=basic_config.get('execution_timeout', 1800),
                require_approval=basic_config.get('risk_threshold', 60) > 0,
                approval_timeout=basic_config.get('approval_timeout', 1800),
                enable_rollback=basic_config.get('enable_rollback', True),
                audit_logging=basic_config.get('audit_log_enabled', True)
            )
        except Exception as e:
            logger.warning(f"加载配置文件失败，使用默认配置: {e}")
            return cls()

class AIDecisionIntegration:
    """AI决策代理集成服务"""
    
    def __init__(self, config_path: Optional[str] = None):
        """初始化集成服务"""
        self.config = IntegrationConfig.from_yaml(config_path) if config_path else IntegrationConfig()
        
        # 初始化各个服务组件
        self.openai_service = OpenAIService()
        self.decision_agent = AIDecisionAgent(config_path)
        self.command_executor = CommandExecutor()
        self.effect_validator = EffectValidator()
        self.template_manager = CommandTemplateManager()
        
        # 工作流管理
        self.active_workflows: Dict[str, WorkflowContext] = {}
        self.workflow_history: List[WorkflowContext] = []
        
        # 统计信息
        self.stats = {
            'total_workflows': 0,
            'successful_workflows': 0,
            'failed_workflows': 0,
            'rolled_back_workflows': 0,
            'average_execution_time': 0.0,
            'last_updated': datetime.now()
        }
        
        logger.info("AI决策代理集成服务初始化完成")
    
    async def process_security_events(self, 
                                    security_events: List[Dict[str, Any]],
                                    user_id: Optional[str] = None,
                                    session_id: Optional[str] = None,
                                    execution_mode: ExecutionMode = ExecutionMode.SEMI_AUTOMATIC) -> WorkflowContext:
        """处理安全事件的完整工作流"""
        
        # 创建工作流上下文
        workflow_id = str(uuid.uuid4())
        context = WorkflowContext(
            workflow_id=workflow_id,
            session_id=session_id or str(uuid.uuid4()),
            user_id=user_id,
            security_events=security_events
        )
        
        try:
            # 检查并发限制
            if len(self.active_workflows) >= self.config.max_concurrent_workflows:
                raise Exception(f"超过最大并发工作流限制: {self.config.max_concurrent_workflows}")
            
            # 注册工作流
            self.active_workflows[workflow_id] = context
            self.stats['total_workflows'] += 1
            
            logger.info(f"开始处理安全事件工作流: {workflow_id}")
            
            # 阶段1: 分析阶段
            await self._stage_analysis(context)
            
            # 阶段2: 决策阶段
            await self._stage_decision(context, execution_mode)
            
            # 阶段3: 审批阶段（如果需要）
            if (context.decision_result and 
                context.decision_result.execution_plan and 
                context.decision_result.execution_plan.approval_required):
                await self._stage_approval(context)
            
            # 阶段4: 执行阶段
            await self._stage_execution(context)
            
            # 阶段5: 验证阶段
            if self.config.enable_validation:
                await self._stage_validation(context)
            
            # 阶段6: 完成阶段
            await self._stage_completion(context)
            
            # 更新统计信息
            self.stats['successful_workflows'] += 1
            
            logger.info(f"工作流处理完成: {workflow_id}")
            
        except Exception as e:
            logger.error(f"工作流处理失败: {workflow_id}, 错误: {e}")
            context.status = IntegrationStatus.FAILED
            context.error_info = {
                'error_type': type(e).__name__,
                'error_message': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
            # 尝试回滚
            if self.config.enable_rollback and self.config.auto_rollback_on_failure:
                await self._stage_rollback(context)
            
            self.stats['failed_workflows'] += 1
            
        finally:
            # 清理活跃工作流
            if workflow_id in self.active_workflows:
                del self.active_workflows[workflow_id]
            
            # 添加到历史记录
            self.workflow_history.append(context)
            
            # 更新统计信息
            self._update_stats(context)
        
        return context
    
    async def _stage_analysis(self, context: WorkflowContext):
        """分析阶段"""
        context.current_stage = WorkflowStage.ANALYSIS
        context.status = IntegrationStatus.ANALYZING
        
        logger.info(f"开始分析阶段: {context.workflow_id}")
        
        try:
            # 创建分析请求
            from .openai_service import AnalysisRequest, AnalysisType, Priority
            analysis_request = AnalysisRequest(
                analysis_type=AnalysisType.SECURITY_ANALYSIS,
                events=context.security_events,
                priority=Priority.HIGH
            )
            
            # 调用OpenAI服务进行分析
            analysis_result = await self.openai_service.analyze_security_events(analysis_request)
            
            context.analysis_result = analysis_result
            context.metadata['analysis_completed_at'] = datetime.now().isoformat()
            
            logger.info(f"分析阶段完成: {context.workflow_id}, 风险评分: {analysis_result.risk_score}")
            
        except Exception as e:
            logger.error(f"分析阶段失败: {context.workflow_id}, 错误: {e}")
            raise
    
    async def _stage_decision(self, context: WorkflowContext, execution_mode: ExecutionMode):
        """决策阶段"""
        context.current_stage = WorkflowStage.DECISION
        context.status = IntegrationStatus.DECIDING
        
        logger.info(f"开始决策阶段: {context.workflow_id}")
        
        try:
            if not context.analysis_result:
                raise Exception("缺少分析结果")
            
            # 创建决策上下文
            decision_context = DecisionContext(
                analysis_response=context.analysis_result,
                system_state=context.metadata.get('system_state', {}),
                execution_mode=execution_mode,
                user_id=context.user_id,
                session_id=context.session_id
            )
            
            # 调用决策代理
            decision_result = await self.decision_agent.make_decision(decision_context)
            
            context.decision_result = decision_result
            context.metadata['decision_completed_at'] = datetime.now().isoformat()
            
            decision_type = decision_result.execution_plan.decision_type.value if decision_result.execution_plan else "no_plan"
            logger.info(f"决策阶段完成: {context.workflow_id}, 决策类型: {decision_type}")
            
        except Exception as e:
            logger.error(f"决策阶段失败: {context.workflow_id}, 错误: {e}")
            raise
    
    async def _stage_approval(self, context: WorkflowContext):
        """审批阶段"""
        context.current_stage = WorkflowStage.APPROVAL
        
        logger.info(f"开始审批阶段: {context.workflow_id}")
        
        try:
            # 发送审批请求
            approval_request = {
                'workflow_id': context.workflow_id,
                'decision_summary': context.decision_result.summary,
                'risk_level': context.decision_result.risk_level.value,
                'execution_plan': [step.to_dict() for step in context.decision_result.execution_plan.steps],
                'estimated_impact': context.decision_result.estimated_impact,
                'timeout': self.config.approval_timeout
            }
            
            # 这里应该集成实际的审批系统
            # 目前使用模拟审批
            approval_result = await self._simulate_approval(approval_request)
            
            if not approval_result['approved']:
                raise Exception(f"审批被拒绝: {approval_result.get('reason', '未知原因')}")
            
            context.metadata['approval_completed_at'] = datetime.now().isoformat()
            context.metadata['approval_result'] = approval_result
            
            logger.info(f"审批阶段完成: {context.workflow_id}")
            
        except Exception as e:
            logger.error(f"审批阶段失败: {context.workflow_id}, 错误: {e}")
            raise
    
    async def _stage_execution(self, context: WorkflowContext):
        """执行阶段"""
        context.current_stage = WorkflowStage.EXECUTION
        context.status = IntegrationStatus.EXECUTING
        
        logger.info(f"开始执行阶段: {context.workflow_id}")
        
        try:
            if not context.decision_result or not context.decision_result.execution_plan:
                raise Exception("缺少执行计划")
            
            # 执行命令
            execution_results = await self.command_executor.execute_plan(
                context.decision_result.execution_plan
            )
            
            context.execution_results = execution_results
            context.metadata['execution_completed_at'] = datetime.now().isoformat()
            
            # 检查执行结果
            failed_executions = [r for r in execution_results if r.status == ExecutionStatus.FAILED]
            if failed_executions:
                logger.warning(f"部分命令执行失败: {context.workflow_id}, 失败数量: {len(failed_executions)}")
            
            logger.info(f"执行阶段完成: {context.workflow_id}, 总命令数: {len(execution_results)}")
            
        except Exception as e:
            logger.error(f"执行阶段失败: {context.workflow_id}, 错误: {e}")
            raise
    
    async def _stage_validation(self, context: WorkflowContext):
        """验证阶段"""
        context.current_stage = WorkflowStage.VALIDATION
        context.status = IntegrationStatus.VALIDATING
        
        logger.info(f"开始验证阶段: {context.workflow_id}")
        
        try:
            if not context.execution_results:
                logger.warning(f"没有执行结果需要验证: {context.workflow_id}")
                return
            
            # 验证执行效果
            validation_results = []
            for execution_result in context.execution_results:
                if execution_result.status == ExecutionStatus.COMPLETED:
                    validation_result = await self.effect_validator.validate_execution_effect(
                        execution_result
                    )
                    validation_results.append(validation_result)
            
            context.validation_results = validation_results
            context.metadata['validation_completed_at'] = datetime.now().isoformat()
            
            # 检查验证结果
            failed_validations = [r for r in validation_results if not r.success]
            if failed_validations:
                logger.warning(f"部分验证失败: {context.workflow_id}, 失败数量: {len(failed_validations)}")
                
                # 如果启用自动回滚，触发回滚
                if self.config.auto_rollback_on_failure:
                    await self._stage_rollback(context)
                    return
            
            logger.info(f"验证阶段完成: {context.workflow_id}, 验证数量: {len(validation_results)}")
            
        except Exception as e:
            logger.error(f"验证阶段失败: {context.workflow_id}, 错误: {e}")
            raise
    
    async def _stage_completion(self, context: WorkflowContext):
        """完成阶段"""
        context.current_stage = WorkflowStage.COMPLETION
        context.status = IntegrationStatus.COMPLETED
        
        logger.info(f"开始完成阶段: {context.workflow_id}")
        
        try:
            # 生成执行报告
            execution_report = self._generate_execution_report(context)
            context.metadata['execution_report'] = execution_report
            context.metadata['completed_at'] = datetime.now().isoformat()
            
            # 发送完成通知
            await self._send_completion_notification(context)
            
            logger.info(f"完成阶段完成: {context.workflow_id}")
            
        except Exception as e:
            logger.error(f"完成阶段失败: {context.workflow_id}, 错误: {e}")
            # 完成阶段的错误不应该影响整体流程
    
    async def _stage_rollback(self, context: WorkflowContext):
        """回滚阶段"""
        context.current_stage = WorkflowStage.ROLLBACK
        context.status = IntegrationStatus.ROLLED_BACK
        
        logger.info(f"开始回滚阶段: {context.workflow_id}")
        
        try:
            if not context.execution_results:
                logger.warning(f"没有执行结果需要回滚: {context.workflow_id}")
                return
            
            # 执行回滚
            rollback_results = await self.command_executor.rollback_executions(
                context.execution_results
            )
            
            context.rollback_info = {
                'rollback_results': [r.to_dict() for r in rollback_results],
                'rollback_completed_at': datetime.now().isoformat()
            }
            
            self.stats['rolled_back_workflows'] += 1
            
            logger.info(f"回滚阶段完成: {context.workflow_id}")
            
        except Exception as e:
            logger.error(f"回滚阶段失败: {context.workflow_id}, 错误: {e}")
            # 回滚失败是严重问题，需要人工干预
            context.error_info = context.error_info or {}
            context.error_info['rollback_error'] = {
                'error_type': type(e).__name__,
                'error_message': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    async def _simulate_approval(self, approval_request: Dict[str, Any]) -> Dict[str, Any]:
        """模拟审批过程"""
        # 这里应该集成实际的审批系统
        # 目前基于风险等级自动决定
        
        risk_level = approval_request.get('risk_level', 'medium')
        
        if risk_level in ['very_low', 'low']:
            return {
                'approved': True,
                'approver': 'system',
                'approval_time': datetime.now().isoformat(),
                'reason': '低风险自动批准'
            }
        elif risk_level == 'medium':
            # 模拟人工审批延迟
            await asyncio.sleep(2)
            return {
                'approved': True,
                'approver': 'admin',
                'approval_time': datetime.now().isoformat(),
                'reason': '中等风险人工批准'
            }
        else:
            return {
                'approved': False,
                'approver': 'admin',
                'approval_time': datetime.now().isoformat(),
                'reason': '高风险需要进一步评估'
            }
    
    def _generate_execution_report(self, context: WorkflowContext) -> Dict[str, Any]:
        """生成执行报告"""
        total_commands = len(context.execution_results)
        successful_commands = len([r for r in context.execution_results if r.status == ExecutionStatus.COMPLETED])
        failed_commands = total_commands - successful_commands
        
        total_validations = len(context.validation_results)
        successful_validations = len([r for r in context.validation_results if r.success])
        failed_validations = total_validations - successful_validations
        
        execution_time = (datetime.now() - context.start_time).total_seconds()
        
        return {
            'workflow_id': context.workflow_id,
            'execution_summary': {
                'total_commands': total_commands,
                'successful_commands': successful_commands,
                'failed_commands': failed_commands,
                'success_rate': successful_commands / total_commands if total_commands > 0 else 0
            },
            'validation_summary': {
                'total_validations': total_validations,
                'successful_validations': successful_validations,
                'failed_validations': failed_validations,
                'validation_rate': successful_validations / total_validations if total_validations > 0 else 0
            },
            'timing': {
                'start_time': context.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_execution_time': execution_time
            },
            'risk_assessment': {
                'initial_risk_score': context.analysis_result.risk_score if context.analysis_result else 0,
                'final_status': context.status.value
            }
        }
    
    async def _send_completion_notification(self, context: WorkflowContext):
        """发送完成通知"""
        # 这里应该集成实际的通知系统
        notification = {
            'type': 'workflow_completed',
            'workflow_id': context.workflow_id,
            'status': context.status.value,
            'summary': context.decision_result.summary if context.decision_result else 'N/A',
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"发送完成通知: {notification}")
    
    def _update_stats(self, context: WorkflowContext):
        """更新统计信息"""
        execution_time = (datetime.now() - context.start_time).total_seconds()
        
        # 更新平均执行时间
        total_workflows = self.stats['total_workflows']
        current_avg = self.stats['average_execution_time']
        self.stats['average_execution_time'] = (
            (current_avg * (total_workflows - 1) + execution_time) / total_workflows
        )
        
        self.stats['last_updated'] = datetime.now()
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """获取工作流状态"""
        # 检查活跃工作流
        if workflow_id in self.active_workflows:
            return self.active_workflows[workflow_id].to_dict()
        
        # 检查历史工作流
        for workflow in self.workflow_history:
            if workflow.workflow_id == workflow_id:
                return workflow.to_dict()
        
        return None
    
    def get_active_workflows(self) -> List[Dict[str, Any]]:
        """获取所有活跃工作流"""
        return [context.to_dict() for context in self.active_workflows.values()]
    
    def get_workflow_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取工作流历史"""
        return [context.to_dict() for context in self.workflow_history[-limit:]]
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self.stats.copy()
    
    async def cancel_workflow(self, workflow_id: str) -> bool:
        """取消工作流"""
        if workflow_id not in self.active_workflows:
            return False
        
        context = self.active_workflows[workflow_id]
        
        try:
            # 如果正在执行，尝试取消执行
            if context.status == IntegrationStatus.EXECUTING:
                await self.command_executor.cancel_all_executions()
            
            # 标记为失败
            context.status = IntegrationStatus.FAILED
            context.error_info = {
                'error_type': 'UserCancellation',
                'error_message': '用户取消工作流',
                'timestamp': datetime.now().isoformat()
            }
            
            # 移动到历史记录
            del self.active_workflows[workflow_id]
            self.workflow_history.append(context)
            
            logger.info(f"工作流已取消: {workflow_id}")
            return True
            
        except Exception as e:
            logger.error(f"取消工作流失败: {workflow_id}, 错误: {e}")
            return False
    
    async def health_check(self) -> Dict[str, Any]:
        """健康检查"""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'components': {},
            'metrics': self.get_statistics()
        }
        
        try:
            # 检查各个组件
            components = {
                'openai_service': self.openai_service,
                'decision_agent': self.decision_agent,
                'command_executor': self.command_executor,
                'effect_validator': self.effect_validator
            }
            
            for name, component in components.items():
                try:
                    # 假设每个组件都有health_check方法
                    if hasattr(component, 'health_check'):
                        component_health = await component.health_check()
                        health_status['components'][name] = component_health
                    else:
                        health_status['components'][name] = {'status': 'unknown'}
                except Exception as e:
                    health_status['components'][name] = {
                        'status': 'unhealthy',
                        'error': str(e)
                    }
                    health_status['status'] = 'degraded'
            
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['error'] = str(e)
        
        return health_status

# 便捷函数
async def process_security_events_simple(security_events: List[Dict[str, Any]], 
                                       config_path: Optional[str] = None) -> Dict[str, Any]:
    """简化的安全事件处理函数"""
    integration = AIDecisionIntegration(config_path)
    context = await integration.process_security_events(security_events)
    return context.to_dict()

if __name__ == "__main__":
    # 测试代码
    async def test_integration():
        # 模拟安全事件
        test_events = [
            {
                'event_type': 'suspicious_process',
                'process_name': 'malware.exe',
                'pid': 1234,
                'severity': 'high',
                'timestamp': datetime.now().isoformat()
            }
        ]
        
        # 处理事件
        result = await process_security_events_simple(test_events)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    
    # 运行测试
    asyncio.run(test_integration())