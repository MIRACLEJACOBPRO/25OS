#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS AI决策代理服务模块

实现1.5 AI决策代理与自动执行的核心功能:
1. 分析OpenAI输出结果
2. 制定执行决策
3. 生成执行计划
4. 协调命令执行
5. 监控执行状态
6. 验证执行效果

设计原则:
- 安全优先: 严格的权限控制和命令白名单
- 智能决策: 基于风险评估的智能决策
- 可追溯性: 完整的执行日志和审计记录
- 人机协同: 支持人工干预和确认机制
- 渐进执行: 分步骤执行，支持回滚
"""

import asyncio
import json
import time
from typing import Dict, List, Any, Optional, Union, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
from pathlib import Path

from loguru import logger

# 导入相关服务
from .openai_service import AnalysisResponse, AnalysisType, Priority
from .command_executor import CommandExecutor, ExecutionResult, ExecutionStatus
from .command_template_manager import CommandTemplateManager, CommandTemplate
from .effect_validator import EffectValidator, ValidationResult


class DecisionType(Enum):
    """决策类型枚举"""
    IMMEDIATE_ACTION = "immediate_action"      # 立即执行
    SCHEDULED_ACTION = "scheduled_action"      # 计划执行
    MANUAL_APPROVAL = "manual_approval"        # 需要人工确认
    NO_ACTION = "no_action"                    # 不执行任何操作
    ESCALATION = "escalation"                  # 升级处理


class ExecutionMode(Enum):
    """执行模式枚举"""
    AUTOMATIC = "automatic"        # 自动执行
    SEMI_AUTOMATIC = "semi_automatic"  # 半自动（需要确认）
    MANUAL = "manual"              # 手动执行
    DRY_RUN = "dry_run"            # 模拟执行


class RiskLevel(Enum):
    """风险等级枚举"""
    VERY_LOW = "very_low"      # 0-20
    LOW = "low"                # 21-40
    MEDIUM = "medium"          # 41-60
    HIGH = "high"              # 61-80
    VERY_HIGH = "very_high"    # 81-100


@dataclass
class DecisionContext:
    """决策上下文数据结构"""
    analysis_response: AnalysisResponse
    system_state: Dict[str, Any]
    execution_mode: ExecutionMode
    risk_threshold: float = 60.0
    require_approval: bool = True
    max_execution_time: int = 300  # 最大执行时间（秒）
    allow_rollback: bool = True
    user_id: Optional[str] = None
    session_id: Optional[str] = None


@dataclass
class ExecutionPlan:
    """执行计划数据结构"""
    plan_id: str
    decision_type: DecisionType
    risk_level: RiskLevel
    commands: List[Dict[str, Any]]
    execution_order: List[int]
    estimated_duration: float
    rollback_plan: List[Dict[str, Any]]
    approval_required: bool
    created_at: datetime
    created_by: str
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = asdict(self)
        result['decision_type'] = self.decision_type.value
        result['risk_level'] = self.risk_level.value
        result['created_at'] = self.created_at.isoformat()
        return result


@dataclass
class DecisionResult:
    """决策结果数据结构"""
    decision_id: str
    context: DecisionContext
    execution_plan: Optional[ExecutionPlan]
    decision_reasoning: str
    confidence_score: float
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    warnings: List[str]
    timestamp: datetime
    processing_time: float
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = {
            'decision_id': self.decision_id,
            'execution_plan': self.execution_plan.to_dict() if self.execution_plan else None,
            'decision_reasoning': self.decision_reasoning,
            'confidence_score': self.confidence_score,
            'risk_assessment': self.risk_assessment,
            'recommendations': self.recommendations,
            'warnings': self.warnings,
            'timestamp': self.timestamp.isoformat(),
            'processing_time': self.processing_time
        }
        return result


class AIDecisionAgent:
    """AI决策代理类"""
    
    def __init__(self, config_path: Optional[str] = None):
        """初始化AI决策代理"""
        self.config = self._load_config(config_path)
        self.command_executor = CommandExecutor()
        self.template_manager = CommandTemplateManager()
        self.effect_validator = EffectValidator()
        
        # 决策统计
        self.stats = {
            'total_decisions': 0,
            'automatic_executions': 0,
            'manual_approvals': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'rollbacks': 0
        }
        
        # 执行历史
        self.execution_history = []
        
        # 风险阈值配置
        self.risk_thresholds = {
            RiskLevel.VERY_LOW: (0, 20),
            RiskLevel.LOW: (21, 40),
            RiskLevel.MEDIUM: (41, 60),
            RiskLevel.HIGH: (61, 80),
            RiskLevel.VERY_HIGH: (81, 100)
        }
        
        logger.info("AI Decision Agent initialized successfully")
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """加载配置文件"""
        default_config = {
            'execution_mode': ExecutionMode.SEMI_AUTOMATIC.value,
            'risk_threshold': 60.0,
            'max_concurrent_executions': 3,
            'execution_timeout': 300,
            'enable_rollback': True,
            'audit_log_enabled': True,
            'approval_timeout': 1800,  # 30分钟
            'command_whitelist': [
                'kill_process',
                'restart_service',
                'block_ip',
                'isolate_container',
                'backup_file',
                'scan_file',
                'update_firewall',
                'check_system_status'
            ]
        }
        
        if config_path and Path(config_path).exists():
            try:
                import yaml
                with open(config_path, 'r', encoding='utf-8') as f:
                    if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                        user_config = yaml.safe_load(f)
                    else:
                        user_config = json.load(f)
                
                # 处理YAML配置的嵌套结构
                if 'basic' in user_config:
                    default_config.update(user_config['basic'])
                if 'command_whitelist' in user_config:
                    # 提取命令白名单中的action名称
                    whitelist_actions = [cmd['action'] for cmd in user_config['command_whitelist']]
                    default_config['command_whitelist'] = whitelist_actions
                
                logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}. Using default config.")
        
        return default_config
    
    def _assess_risk_level(self, risk_score: float) -> RiskLevel:
        """评估风险等级"""
        for level, (min_score, max_score) in self.risk_thresholds.items():
            if min_score <= risk_score <= max_score:
                return level
        return RiskLevel.VERY_HIGH
    
    def _generate_decision_id(self, analysis_response: AnalysisResponse) -> str:
        """生成决策ID"""
        content = f"{analysis_response.request_id}_{analysis_response.timestamp.isoformat()}"
        hash_value = hashlib.md5(content.encode()).hexdigest()[:8]
        timestamp = int(time.time() * 1000)
        return f"decision_{hash_value}_{timestamp}"
    
    def _analyze_recommendations(self, analysis_response: AnalysisResponse) -> Tuple[List[Dict], List[str]]:
        """分析推荐建议，提取可执行的命令"""
        executable_commands = []
        warnings = []
        
        for recommendation in analysis_response.recommendations:
            try:
                # 尝试将推荐建议映射到命令模板
                command_info = self.template_manager.parse_recommendation(recommendation)
                
                if command_info:
                    # 检查命令是否在白名单中
                    if command_info['action'] in self.config['command_whitelist']:
                        executable_commands.append(command_info)
                    else:
                        warnings.append(f"Command '{command_info['action']}' not in whitelist")
                else:
                    warnings.append(f"Cannot parse recommendation: {recommendation}")
                    
            except Exception as e:
                warnings.append(f"Error parsing recommendation '{recommendation}': {e}")
                logger.warning(f"Failed to parse recommendation: {e}")
        
        return executable_commands, warnings
    
    def _determine_decision_type(self, context: DecisionContext, risk_level: RiskLevel) -> DecisionType:
        """确定决策类型"""
        risk_score = context.analysis_response.risk_score
        
        # 极高风险需要人工确认
        if risk_level == RiskLevel.VERY_HIGH:
            return DecisionType.MANUAL_APPROVAL
        
        # 高风险需要升级处理
        if risk_level == RiskLevel.HIGH and risk_score > 80:
            return DecisionType.ESCALATION
        
        # 超过风险阈值需要人工确认
        if risk_score > context.risk_threshold:
            return DecisionType.MANUAL_APPROVAL
        
        # 半自动模式需要确认
        if context.execution_mode == ExecutionMode.SEMI_AUTOMATIC:
            return DecisionType.MANUAL_APPROVAL
        
        # 自动模式且风险可接受
        if context.execution_mode == ExecutionMode.AUTOMATIC and risk_score <= context.risk_threshold:
            return DecisionType.IMMEDIATE_ACTION
        
        # 手动模式不自动执行
        if context.execution_mode == ExecutionMode.MANUAL:
            return DecisionType.NO_ACTION
        
        # 默认需要人工确认
        return DecisionType.MANUAL_APPROVAL
    
    def _create_execution_plan(self, 
                              commands: List[Dict], 
                              decision_type: DecisionType,
                              risk_level: RiskLevel,
                              context: DecisionContext) -> ExecutionPlan:
        """创建执行计划"""
        plan_id = f"plan_{int(time.time() * 1000)}"
        
        # 生成执行顺序（基于优先级和依赖关系）
        execution_order = self._optimize_execution_order(commands)
        
        # 估算执行时间
        estimated_duration = sum(cmd.get('estimated_time', 10) for cmd in commands)
        
        # 生成回滚计划
        rollback_plan = self._generate_rollback_plan(commands)
        
        # 确定是否需要审批
        approval_required = (
            decision_type == DecisionType.MANUAL_APPROVAL or
            risk_level in [RiskLevel.HIGH, RiskLevel.VERY_HIGH] or
            context.require_approval
        )
        
        return ExecutionPlan(
            plan_id=plan_id,
            decision_type=decision_type,
            risk_level=risk_level,
            commands=commands,
            execution_order=execution_order,
            estimated_duration=estimated_duration,
            rollback_plan=rollback_plan,
            approval_required=approval_required,
            created_at=datetime.now(),
            created_by=context.user_id or "system"
        )
    
    def _optimize_execution_order(self, commands: List[Dict]) -> List[int]:
        """优化执行顺序"""
        # 简单的优先级排序，后续可以实现更复杂的依赖关系分析
        priority_map = {
            'stop_attack': 1,
            'isolate_system': 2,
            'kill_process': 3,
            'block_ip': 4,
            'backup_file': 5,
            'scan_file': 6,
            'restart_service': 7,
            'update_config': 8,
            'check_status': 9
        }
        
        indexed_commands = [(i, cmd) for i, cmd in enumerate(commands)]
        indexed_commands.sort(key=lambda x: priority_map.get(x[1].get('action', ''), 10))
        
        return [i for i, _ in indexed_commands]
    
    def _generate_rollback_plan(self, commands: List[Dict]) -> List[Dict]:
        """生成回滚计划"""
        rollback_commands = []
        
        for cmd in reversed(commands):
            rollback_cmd = self.template_manager.generate_rollback_command(cmd)
            if rollback_cmd:
                rollback_commands.append(rollback_cmd)
        
        return rollback_commands
    
    async def make_decision(self, context: DecisionContext) -> DecisionResult:
        """制定决策"""
        start_time = time.time()
        
        try:
            self.stats['total_decisions'] += 1
            
            # 生成决策ID
            decision_id = self._generate_decision_id(context.analysis_response)
            
            logger.info(f"Making decision for analysis {context.analysis_response.request_id}")
            
            # 评估风险等级
            risk_level = self._assess_risk_level(context.analysis_response.risk_score)
            
            # 分析推荐建议
            executable_commands, warnings = self._analyze_recommendations(context.analysis_response)
            
            # 确定决策类型
            decision_type = self._determine_decision_type(context, risk_level)
            
            # 创建执行计划
            execution_plan = None
            if executable_commands and decision_type != DecisionType.NO_ACTION:
                execution_plan = self._create_execution_plan(
                    executable_commands, decision_type, risk_level, context
                )
            
            # 生成决策推理
            decision_reasoning = self._generate_decision_reasoning(
                context, risk_level, decision_type, executable_commands
            )
            
            # 计算置信度
            confidence_score = self._calculate_confidence_score(
                context.analysis_response, executable_commands, risk_level
            )
            
            # 风险评估
            risk_assessment = {
                'risk_score': context.analysis_response.risk_score,
                'risk_level': risk_level.value,
                'confidence': context.analysis_response.confidence,
                'affected_systems': context.analysis_response.affected_systems,
                'attack_vectors': context.analysis_response.attack_vectors
            }
            
            # 生成推荐
            recommendations = self._generate_recommendations(context, decision_type, risk_level)
            
            # 创建决策结果
            decision_result = DecisionResult(
                decision_id=decision_id,
                context=context,
                execution_plan=execution_plan,
                decision_reasoning=decision_reasoning,
                confidence_score=confidence_score,
                risk_assessment=risk_assessment,
                recommendations=recommendations,
                warnings=warnings,
                timestamp=datetime.now(),
                processing_time=time.time() - start_time
            )
            
            logger.info(
                f"Decision made: {decision_type.value}, Risk: {risk_level.value}, "
                f"Commands: {len(executable_commands)}, Confidence: {confidence_score:.2f}"
            )
            
            return decision_result
            
        except Exception as e:
            logger.error(f"Failed to make decision: {e}")
            raise
    
    def _generate_decision_reasoning(self, 
                                   context: DecisionContext, 
                                   risk_level: RiskLevel,
                                   decision_type: DecisionType,
                                   commands: List[Dict]) -> str:
        """生成决策推理"""
        reasoning_parts = []
        
        # 风险分析
        reasoning_parts.append(
            f"Risk assessment: {context.analysis_response.risk_score:.1f}/100 ({risk_level.value})"
        )
        
        # 置信度分析
        reasoning_parts.append(
            f"Analysis confidence: {context.analysis_response.confidence:.2f}"
        )
        
        # 命令分析
        if commands:
            reasoning_parts.append(f"Identified {len(commands)} executable commands")
        else:
            reasoning_parts.append("No executable commands identified")
        
        # 决策类型说明
        decision_explanations = {
            DecisionType.IMMEDIATE_ACTION: "Low risk, automatic execution approved",
            DecisionType.MANUAL_APPROVAL: "Requires manual approval due to risk level or policy",
            DecisionType.ESCALATION: "High risk situation requiring escalation",
            DecisionType.NO_ACTION: "No action required or manual mode enabled",
            DecisionType.SCHEDULED_ACTION: "Scheduled for later execution"
        }
        
        reasoning_parts.append(decision_explanations.get(decision_type, "Unknown decision type"))
        
        return "; ".join(reasoning_parts)
    
    def _calculate_confidence_score(self, 
                                  analysis_response: AnalysisResponse,
                                  commands: List[Dict],
                                  risk_level: RiskLevel) -> float:
        """计算决策置信度"""
        base_confidence = analysis_response.confidence
        
        # 根据可执行命令数量调整
        command_factor = min(len(commands) / 5.0, 1.0) if commands else 0.0
        
        # 根据风险等级调整
        risk_factors = {
            RiskLevel.VERY_LOW: 1.0,
            RiskLevel.LOW: 0.9,
            RiskLevel.MEDIUM: 0.8,
            RiskLevel.HIGH: 0.7,
            RiskLevel.VERY_HIGH: 0.6
        }
        risk_factor = risk_factors.get(risk_level, 0.5)
        
        # 综合计算
        confidence = base_confidence * 0.6 + command_factor * 0.2 + risk_factor * 0.2
        
        return min(max(confidence, 0.0), 1.0)
    
    def _generate_recommendations(self, 
                                context: DecisionContext,
                                decision_type: DecisionType,
                                risk_level: RiskLevel) -> List[str]:
        """生成推荐建议"""
        recommendations = []
        
        if decision_type == DecisionType.MANUAL_APPROVAL:
            recommendations.append("Review the execution plan before approval")
            recommendations.append("Verify system state before execution")
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.VERY_HIGH]:
            recommendations.append("Consider manual intervention")
            recommendations.append("Prepare rollback plan")
            recommendations.append("Monitor execution closely")
        
        if context.execution_mode == ExecutionMode.DRY_RUN:
            recommendations.append("This is a dry run - no actual commands will be executed")
        
        recommendations.append("Review execution logs after completion")
        
        return recommendations
    
    async def execute_plan(self, execution_plan: ExecutionPlan, 
                          approved_by: Optional[str] = None) -> List[ExecutionResult]:
        """执行计划"""
        if execution_plan.approval_required and not approved_by:
            raise ValueError("Execution plan requires approval but no approver specified")
        
        logger.info(f"Executing plan {execution_plan.plan_id} with {len(execution_plan.commands)} commands")
        
        results = []
        
        try:
            # 按顺序执行命令
            for i in execution_plan.execution_order:
                command = execution_plan.commands[i]
                
                logger.info(f"Executing command {i+1}/{len(execution_plan.commands)}: {command['action']}")
                
                result = await self.command_executor.execute_command(command)
                results.append(result)
                
                # 如果命令失败且不允许继续，停止执行
                if result.status == ExecutionStatus.FAILED and not command.get('continue_on_failure', False):
                    logger.error(f"Command execution failed, stopping plan execution")
                    break
                
                # 验证执行效果
                if result.status == ExecutionStatus.SUCCESS:
                    validation_result = await self.effect_validator.validate_effect(command, result)
                    if not validation_result.is_valid:
                        logger.warning(f"Command executed but validation failed: {validation_result.message}")
            
            # 更新统计
            successful_commands = sum(1 for r in results if r.status == ExecutionStatus.SUCCESS)
            if successful_commands == len(results):
                self.stats['successful_executions'] += 1
            else:
                self.stats['failed_executions'] += 1
            
            # 记录执行历史
            self.execution_history.append({
                'plan_id': execution_plan.plan_id,
                'executed_at': datetime.now(),
                'approved_by': approved_by,
                'results': [r.to_dict() for r in results]
            })
            
            logger.info(f"Plan execution completed: {successful_commands}/{len(results)} commands successful")
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to execute plan {execution_plan.plan_id}: {e}")
            self.stats['failed_executions'] += 1
            raise
    
    async def rollback_execution(self, execution_plan: ExecutionPlan) -> List[ExecutionResult]:
        """回滚执行"""
        if not execution_plan.rollback_plan:
            raise ValueError("No rollback plan available")
        
        logger.info(f"Rolling back execution for plan {execution_plan.plan_id}")
        
        rollback_results = []
        
        try:
            # 执行回滚命令
            for rollback_command in execution_plan.rollback_plan:
                result = await self.command_executor.execute_command(rollback_command)
                rollback_results.append(result)
            
            self.stats['rollbacks'] += 1
            
            logger.info(f"Rollback completed for plan {execution_plan.plan_id}")
            
            return rollback_results
            
        except Exception as e:
            logger.error(f"Failed to rollback plan {execution_plan.plan_id}: {e}")
            raise
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            'execution_history_count': len(self.execution_history),
            'success_rate': (
                self.stats['successful_executions'] / 
                max(self.stats['successful_executions'] + self.stats['failed_executions'], 1)
            ) * 100
        }
    
    def get_execution_history(self, limit: int = 100) -> List[Dict]:
        """获取执行历史"""
        return self.execution_history[-limit:]


# 创建全局AI决策代理实例
ai_decision_agent = AIDecisionAgent()


# 便捷函数
async def make_decision_from_analysis(analysis_response: AnalysisResponse,
                                    execution_mode: ExecutionMode = ExecutionMode.SEMI_AUTOMATIC,
                                    user_id: Optional[str] = None) -> DecisionResult:
    """从分析结果制定决策"""
    context = DecisionContext(
        analysis_response=analysis_response,
        system_state={},  # 可以从系统状态服务获取
        execution_mode=execution_mode,
        user_id=user_id
    )
    
    return await ai_decision_agent.make_decision(context)


async def execute_decision(decision_result: DecisionResult,
                         approved_by: Optional[str] = None) -> List[ExecutionResult]:
    """执行决策"""
    if not decision_result.execution_plan:
        raise ValueError("No execution plan in decision result")
    
    return await ai_decision_agent.execute_plan(decision_result.execution_plan, approved_by)