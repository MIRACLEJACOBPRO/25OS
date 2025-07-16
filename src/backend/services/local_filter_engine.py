#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS 本地过滤引擎主模块

本模块是1.3.1本地过滤引擎的主要入口点，整合了:
1. 事件过滤管道 - 多级过滤器链式处理
2. 异常检测引擎 - 综合异常检测和评分
3. 事件关联分析 - 时间窗口内的事件关联
4. 白名单管理 - 动态白名单规则管理
5. 配置管理 - 统一的配置接口
6. 监控和统计 - 性能监控和统计信息

架构特点:
- 模块化设计: 各组件独立可测试
- 异步处理: 高性能异步事件处理
- 配置驱动: 支持动态配置更新
- 可扩展性: 支持插件式过滤器扩展
- 可观测性: 详细的监控和日志记录
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional, Callable, Union
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
import json

# 导入核心组件
from .interfaces import (
    IAnomalyDetectionEngine, IEventFilter, FilterResult, 
    FilterContext, AnomalyScore, EventPriority, FilterDecision
)
from .anomaly_detection import (
    EventFilterPipeline, EventCorrelator, AnomalyScorer
)
from .filters import (
    PriorityFilter, FrequencyFilter, IPWhitelistFilter, 
    RulePatternFilter, WhitelistManager, AdaptiveFilter
)

# 导入事件定义
try:
    from .falco_log_parser import StandardizedEvent
    from ..core.config import Settings
except ImportError:
    from dataclasses import dataclass
    from typing import Dict, Any
    
    @dataclass
    class StandardizedEvent:
        event_id: str
        timestamp: datetime
        priority: EventPriority
        rule: str
        output: str
        fields: Dict[str, Any]
        triplet: Dict[str, str]


@dataclass
class FilterEngineConfig:
    """过滤引擎配置"""
    # 基础配置
    enabled: bool = True
    max_concurrent_filters: int = 10
    correlation_window: int = 300  # 秒
    
    # 过滤器配置
    priority_filter_enabled: bool = True
    min_priority: str = "MEDIUM"
    
    frequency_filter_enabled: bool = True
    max_events_per_minute: int = 100
    frequency_time_window: int = 60
    
    ip_whitelist_enabled: bool = True
    whitelist_ips: List[str] = field(default_factory=lambda: ["127.0.0.1", "192.168.1.0/24"])
    
    process_whitelist_enabled: bool = True
    whitelist_processes: List[str] = field(default_factory=lambda: ["systemd", "kernel"])
    
    whitelist_users: List[str] = field(default_factory=lambda: ["root"])
    
    pattern_filter_enabled: bool = True
    block_patterns: List[str] = field(default_factory=list)
    allow_patterns: List[str] = field(default_factory=list)
    
    adaptive_filter_enabled: bool = False
    adaptive_learning_window: int = 1000
    
    anomaly_detection_enabled: bool = True
    
    # 白名单配置
    whitelist_file: Optional[str] = None
    
    # 性能配置
    enable_statistics: bool = True
    statistics_interval: int = 60  # 秒
    
    # 日志配置
    log_level: str = "INFO"
    log_filtered_events: bool = True
    
    def validate(self) -> bool:
        """验证配置"""
        if self.max_concurrent_filters <= 0:
            return False
        if self.correlation_window <= 0:
            return False
        return True


@dataclass
class EngineStatistics:
    """引擎统计信息"""
    total_processed: int = 0
    total_passed: int = 0
    total_blocked: int = 0
    total_suspicious: int = 0
    total_whitelisted: int = 0
    average_processing_time: float = 0.0
    uptime_seconds: float = 0.0
    last_reset: datetime = field(default_factory=datetime.now)
    
    def reset(self):
        """重置统计信息"""
        self.total_processed = 0
        self.total_passed = 0
        self.total_blocked = 0
        self.total_suspicious = 0
        self.total_whitelisted = 0
        self.average_processing_time = 0.0
        self.last_reset = datetime.now()


class LocalFilterEngine:
    """本地过滤引擎主类
    
    负责协调所有过滤组件，提供统一的事件处理接口
    """
    
    def __init__(self, config: FilterEngineConfig = None):
        self._config = config or FilterEngineConfig()
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # 核心组件
        self._filter_pipeline = EventFilterPipeline(self._config.max_concurrent_filters)
        self._event_correlator = EventCorrelator(default_window=self._config.correlation_window)
        self._anomaly_scorer = AnomalyScorer()
        self._whitelist_manager = WhitelistManager(self._config.whitelist_file)
        
        # 状态管理
        self._is_running = False
        self._start_time: Optional[datetime] = None
        self._statistics = EngineStatistics()
        
        # 回调函数
        self._event_callbacks: List[Callable] = []
        
        # 异步任务
        self._statistics_task: Optional[asyncio.Task] = None
        
        # 初始化过滤器将在 start_engine 中进行
    
    async def _initialize_filters(self):
        """初始化默认过滤器"""
        try:
            # 优先级过滤器
            if self._config.priority_filter_enabled:
                priority_filter = PriorityFilter(
                    min_priority=EventPriority[self._config.min_priority.upper()]
                )
                await self._filter_pipeline.add_filter(priority_filter)
            
            # 频率过滤器
            if self._config.frequency_filter_enabled:
                frequency_filter = FrequencyFilter(
                    max_events_per_minute=self._config.max_events_per_minute,
                    time_window=self._config.frequency_time_window
                )
                await self._filter_pipeline.add_filter(frequency_filter)
            
            # IP白名单过滤器
            if self._config.ip_whitelist_enabled and self._config.whitelist_ips:
                ip_filter = IPWhitelistFilter(self._config.whitelist_ips)
                await self._filter_pipeline.add_filter(ip_filter)
            
            # 规则模式过滤器
            if self._config.pattern_filter_enabled:
                pattern_filter = RulePatternFilter(
                    block_patterns=self._config.block_patterns,
                    allow_patterns=self._config.allow_patterns
                )
                await self._filter_pipeline.add_filter(pattern_filter)
            
            # 自适应过滤器
            if self._config.adaptive_filter_enabled:
                adaptive_filter = AdaptiveFilter(
                    learning_window=self._config.adaptive_learning_window
                )
                await self._filter_pipeline.add_filter(adaptive_filter)
            
            self._logger.info("过滤器初始化完成")
            
        except Exception as e:
            self._logger.error(f"过滤器初始化失败: {e}")
    
    async def start_engine(self) -> None:
        """启动过滤引擎"""
        if self._is_running:
            self._logger.warning("过滤引擎已在运行")
            return
        
        try:
            # 初始化过滤器
            await self._initialize_filters()
            
            self._is_running = True
            self._start_time = datetime.now()
            
            # 启动统计任务
            if self._config.enable_statistics:
                self._statistics_task = asyncio.create_task(self._statistics_loop())
            
            self._logger.info("本地过滤引擎已启动")
            
        except Exception as e:
            self._logger.error(f"启动过滤引擎失败: {e}")
            self._is_running = False
            raise
    
    async def stop_engine(self) -> None:
        """停止过滤引擎"""
        if not self._is_running:
            self._logger.warning("过滤引擎未在运行")
            return
        
        try:
            self._is_running = False
            
            # 停止统计任务
            if self._statistics_task:
                self._statistics_task.cancel()
                try:
                    await self._statistics_task
                except asyncio.CancelledError:
                    pass
            
            self._logger.info("本地过滤引擎已停止")
            
        except Exception as e:
            self._logger.error(f"停止过滤引擎失败: {e}")
    
    async def process_event(self, event: StandardizedEvent) -> Dict[str, Any]:
        """处理单个事件
        
        Args:
            event: 标准化事件
            
        Returns:
            Dict[str, Any]: 处理结果
        """
        if not self._is_running:
            raise RuntimeError("过滤引擎未启动")
        
        # 处理 None 事件
        if event is None:
            return {
                'event_id': 'null_event',
                'decision': FilterDecision.BLOCK.value,
                'reason': '无效事件: 事件为空',
                'confidence': 1.0,
                'processing_time': 0.0,
                'error': True
            }
        
        start_time = time.time()
        
        try:
            # 1. 检查引擎是否启用
            if not self._config.enabled:
                result = {
                    'event_id': event.event_id,
                    'decision': FilterDecision.PASS.value,
                    'reason': 'Engine disabled',
                    'confidence': 1.0,
                    'processing_time': (time.time() - start_time) * 1000,
                    'filter_chain': [],
                    'bypass_reason': 'engine_disabled'
                }
                return result
            
            # 2. 检查白名单
            whitelist_reason = None
            
            # 检查进程白名单（优先级更高）
            if (self._config.process_whitelist_enabled and
                hasattr(event, 'process_info') and event.process_info and 
                'name' in event.process_info and 
                event.process_info['name'] in self._config.whitelist_processes):
                whitelist_reason = 'process'
            
            # 检查IP白名单
            elif (self._config.ip_whitelist_enabled and 
                  hasattr(event, 'host_info') and event.host_info and 
                  'ip' in event.host_info and 
                  event.host_info['ip'] in self._config.whitelist_ips):
                whitelist_reason = 'ip'
            
            if whitelist_reason:
                result = {
                    'event_id': event.event_id,
                    'decision': FilterDecision.WHITELIST.value,
                    'reason': '事件在白名单中',
                    'confidence': 1.0,
                    'processing_time': (time.time() - start_time) * 1000,
                    'filter_results': [],
                    'correlations': [],
                    'anomaly_score': None,
                    'whitelist_reason': whitelist_reason
                }
                
                self._update_statistics(FilterDecision.WHITELIST.value, time.time() - start_time)
                await self._notify_callbacks(event, result)
                return result
            
            # 3. 执行过滤管道
            filter_results = await self._filter_pipeline.process(event)
            
            # 4. 事件关联分析
            correlations = await self._event_correlator.correlate(event)
            
            # 5. 异常评分
            anomaly_score = await self._anomaly_scorer.score(event, correlations, filter_results)
            
            # 6. 决策逻辑
            decision, reason, confidence = self._make_decision(filter_results, anomaly_score)
            
            # 7. 构建结果
            result = {
                'event_id': event.event_id,
                'decision': decision,
                'reason': reason,
                'confidence': confidence,
                'processing_time': (time.time() - start_time) * 1000,
                'filter_chain': [
                    {
                        'filter_name': fr.filter_name,
                        'decision': fr.result.value,
                        'confidence': fr.confidence,
                        'reason': fr.reason,
                        'processing_time': fr.processing_time
                    } for fr in filter_results
                ],
                'filter_results': [
                    {
                        'filter_name': fr.filter_name,
                        'result': fr.result.value,
                        'confidence': fr.confidence,
                        'reason': fr.reason,
                        'processing_time': fr.processing_time
                    } for fr in filter_results
                ],
                'correlations': [
                    {
                        'event_id': ce.event_id,
                        'rule': ce.rule_name,
                        'timestamp': ce.timestamp.isoformat(),
                        'priority': ce.priority.name
                    } for ce in correlations[:10]  # 限制返回数量
                ],
                'anomaly_score': {
                    'total_score': anomaly_score.total_score,
                    'risk_level': anomaly_score.risk_level.name,
                    'confidence': anomaly_score.confidence,
                    'explanation': anomaly_score.explanation,
                    'indicators': anomaly_score.indicators
                }
            }
            
            # 8. 更新统计信息
            self._update_statistics(decision, time.time() - start_time)
            
            # 9. 通知回调函数
            await self._notify_callbacks(event, result)
            
            # 9. 记录日志
            if self._config.log_filtered_events and decision in ['BLOCK', 'SUSPICIOUS']:
                self._logger.info(f"事件 {event.event_id} 被{decision}: {reason}")
            
            return result
            
        except Exception as e:
            self._logger.error(f"处理事件失败: {e}")
            processing_time = (time.time() - start_time) * 1000
            
            error_result = {
                'event_id': getattr(event, 'event_id', 'unknown') if event else 'null_event',
                'decision': FilterDecision.BLOCK.value,
                'reason': f'处理异常: {str(e)}',
                'confidence': 0.0,
                'processing_time': processing_time,
                'error': True
            }
            
            return error_result
    
    def _make_decision(self, filter_results: List[FilterContext], 
                      anomaly_score: AnomalyScore) -> tuple[str, str, float]:
        """基于过滤结果和异常分数做出决策
        
        Returns:
            tuple: (decision, reason, confidence)
        """
        # 检查是否有过滤器明确阻止
        blocked_filters = [fr for fr in filter_results if fr.result == FilterResult.BLOCK]
        if blocked_filters:
            return (
                FilterDecision.BLOCK.value,
                f"被过滤器阻止: {', '.join([fr.filter_name for fr in blocked_filters])}",
                max([fr.confidence for fr in blocked_filters])
            )
        
        # 检查是否有白名单通过
        whitelisted_filters = [fr for fr in filter_results if fr.result == FilterResult.WHITELIST]
        if whitelisted_filters:
            return (
                FilterDecision.WHITELIST.value,
                f"白名单通过: {', '.join([fr.filter_name for fr in whitelisted_filters])}",
                max([fr.confidence for fr in whitelisted_filters])
            )
        
        # 基于异常分数决策
        if anomaly_score.total_score >= 0.7:
            return (
                FilterDecision.BLOCK.value,
                f"高异常分数: {anomaly_score.total_score:.3f} - {anomaly_score.explanation}",
                anomaly_score.confidence
            )
        elif anomaly_score.total_score >= 0.5:
            return (
                FilterDecision.SUSPICIOUS.value,
                f"中等异常分数: {anomaly_score.total_score:.3f} - {anomaly_score.explanation}",
                anomaly_score.confidence
            )
        
        # 检查可疑过滤器
        suspicious_filters = [fr for fr in filter_results if fr.result == FilterResult.SUSPICIOUS]
        if suspicious_filters:
            return (
                FilterDecision.SUSPICIOUS.value,
                f"可疑事件: {', '.join([fr.filter_name for fr in suspicious_filters])}",
                max([fr.confidence for fr in suspicious_filters])
            )
        
        # 默认通过
        return (
            FilterDecision.PASS.value,
            '通过所有过滤器检查',
            0.8
        )
    
    def _update_statistics(self, decision: str, processing_time: float):
        """更新统计信息"""
        self._statistics.total_processed += 1
        
        if decision == FilterDecision.PASS.value:
            self._statistics.total_passed += 1
        elif decision == FilterDecision.BLOCK.value:
            self._statistics.total_blocked += 1
        elif decision == FilterDecision.SUSPICIOUS.value:
            self._statistics.total_suspicious += 1
        elif decision == FilterDecision.WHITELIST.value:
            self._statistics.total_whitelisted += 1
        
        # 更新平均处理时间
        total_time = (self._statistics.average_processing_time * 
                     (self._statistics.total_processed - 1) + processing_time * 1000)
        self._statistics.average_processing_time = total_time / self._statistics.total_processed
    
    async def _notify_callbacks(self, event: StandardizedEvent, result: Dict[str, Any]):
        """通知回调函数"""
        for callback in self._event_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event, result)
                else:
                    callback(event, result)
            except Exception as e:
                self._logger.error(f"回调函数执行失败: {e}")
    
    async def _statistics_loop(self):
        """统计信息循环任务"""
        while self._is_running:
            try:
                await asyncio.sleep(self._config.statistics_interval)
                
                if self._start_time:
                    self._statistics.uptime_seconds = (datetime.now() - self._start_time).total_seconds()
                
                # 记录统计信息
                self._logger.info(
                    f"过滤引擎统计 - 处理: {self._statistics.total_processed}, "
                    f"通过: {self._statistics.total_passed}, "
                    f"阻止: {self._statistics.total_blocked}, "
                    f"可疑: {self._statistics.total_suspicious}, "
                    f"白名单: {self._statistics.total_whitelisted}, "
                    f"平均处理时间: {self._statistics.average_processing_time:.2f}ms"
                )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._logger.error(f"统计循环异常: {e}")
    
    # 公共接口方法
    
    async def add_filter(self, filter_instance: IEventFilter) -> None:
        """添加过滤器"""
        await self._filter_pipeline.add_filter(filter_instance)
    
    async def remove_filter(self, filter_name: str) -> None:
        """移除过滤器"""
        await self._filter_pipeline.remove_filter(filter_name)
    
    async def add_whitelist_rule(self, rule: Dict[str, Any]) -> None:
        """添加白名单规则"""
        await self._whitelist_manager.add_whitelist_rule(rule)
    
    async def remove_whitelist_rule(self, rule_id: str) -> None:
        """移除白名单规则"""
        await self._whitelist_manager.remove_whitelist_rule(rule_id)
    
    async def get_whitelist_rules(self) -> List[Dict[str, Any]]:
        """获取白名单规则"""
        return await self._whitelist_manager.get_whitelist_rules()
    
    def add_event_callback(self, callback: Callable) -> None:
        """添加事件处理回调"""
        self._event_callbacks.append(callback)
    
    def remove_event_callback(self, callback: Callable) -> None:
        """移除事件处理回调"""
        if callback in self._event_callbacks:
            self._event_callbacks.remove(callback)
    
    async def get_engine_status(self) -> Dict[str, Any]:
        """获取引擎状态"""
        pipeline_status = await self._filter_pipeline.get_pipeline_status()
        whitelist_stats = await self._whitelist_manager.get_statistics()
        
        return {
            'is_running': self._is_running,
            'start_time': self._start_time.isoformat() if self._start_time else None,
            'uptime_seconds': self._statistics.uptime_seconds,
            'statistics': {
                'total_processed': self._statistics.total_processed,
                'total_passed': self._statistics.total_passed,
                'total_blocked': self._statistics.total_blocked,
                'total_suspicious': self._statistics.total_suspicious,
                'total_whitelisted': self._statistics.total_whitelisted,
                'average_processing_time': self._statistics.average_processing_time,
                'last_reset': self._statistics.last_reset.isoformat()
            },
            'pipeline_status': pipeline_status,
            'whitelist_statistics': whitelist_stats,
            'configuration': {
                'enabled': self._config.enabled,
                'max_concurrent_filters': self._config.max_concurrent_filters,
                'correlation_window': self._config.correlation_window,
                'statistics_interval': self._config.statistics_interval
            }
        }
    
    async def update_configuration(self, config_updates: Dict[str, Any]) -> None:
        """更新配置"""
        try:
            # 更新配置对象
            for key, value in config_updates.items():
                if hasattr(self._config, key):
                    setattr(self._config, key, value)
                    self._logger.info(f"配置已更新: {key} = {value}")
                else:
                    self._logger.warning(f"未知配置项: {key}")
            
            # 重新初始化过滤器（如果需要）
            if any(key.endswith('_enabled') for key in config_updates.keys()):
                self._logger.info("重新初始化过滤器")
                # 这里可以添加重新初始化逻辑
            
        except Exception as e:
            self._logger.error(f"更新配置失败: {e}")
            raise
    
    async def reset_statistics(self) -> None:
        """重置统计信息"""
        self._statistics.reset()
        self._logger.info("统计信息已重置")
    
    async def export_configuration(self, file_path: str) -> None:
        """导出配置到文件"""
        try:
            config_dict = {
                'enabled': self._config.enabled,
                'max_concurrent_filters': self._config.max_concurrent_filters,
                'correlation_window': self._config.correlation_window,
                'priority_filter_enabled': self._config.priority_filter_enabled,
                'min_priority': self._config.min_priority,
                'frequency_filter_enabled': self._config.frequency_filter_enabled,
                'max_events_per_minute': self._config.max_events_per_minute,
                'frequency_time_window': self._config.frequency_time_window,
                'ip_whitelist_enabled': self._config.ip_whitelist_enabled,
                'whitelist_ips': self._config.whitelist_ips,
                'pattern_filter_enabled': self._config.pattern_filter_enabled,
                'block_patterns': self._config.block_patterns,
                'allow_patterns': self._config.allow_patterns,
                'adaptive_filter_enabled': self._config.adaptive_filter_enabled,
                'adaptive_learning_window': self._config.adaptive_learning_window,
                'whitelist_file': self._config.whitelist_file,
                'enable_statistics': self._config.enable_statistics,
                'statistics_interval': self._config.statistics_interval,
                'log_level': self._config.log_level,
                'log_filtered_events': self._config.log_filtered_events
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, indent=2, ensure_ascii=False)
            
            self._logger.info(f"配置已导出到: {file_path}")
            
        except Exception as e:
            self._logger.error(f"导出配置失败: {e}")
            raise
    
    async def import_configuration(self, file_path: str) -> None:
        """从文件导入配置"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config_dict = json.load(f)
            
            await self.update_configuration(config_dict)
            self._logger.info(f"配置已从文件导入: {file_path}")
            
        except Exception as e:
            self._logger.error(f"导入配置失败: {e}")
            raise
    
    # 测试兼容性方法
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息 - 测试兼容性方法"""
        return {
            'total_events': self._statistics.total_processed,
            'passed_events': self._statistics.total_passed,
            'blocked_events': self._statistics.total_blocked,
            'suspicious_events': self._statistics.total_suspicious,
            'whitelisted_events': self._statistics.total_whitelisted,
            'average_processing_time': self._statistics.average_processing_time,
            'uptime_seconds': self._statistics.uptime_seconds
        }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """获取性能指标 - 测试兼容性方法"""
        import psutil
        process = psutil.Process()
        
        events_per_second = 0
        if self._statistics.uptime_seconds > 0:
            events_per_second = self._statistics.total_processed / self._statistics.uptime_seconds
        
        filter_efficiency = 0
        if self._statistics.total_processed > 0:
            filter_efficiency = (self._statistics.total_passed + self._statistics.total_whitelisted) / self._statistics.total_processed
        
        return {
            'avg_processing_time': self._statistics.average_processing_time,
            'events_per_second': events_per_second,
            'filter_efficiency': filter_efficiency,
            'memory_usage': process.memory_info().rss / 1024 / 1024  # MB
        }
    
    async def update_config(self, new_config: FilterEngineConfig) -> None:
        """更新配置 - 测试兼容性方法"""
        self._config = new_config
        self._logger.info("配置已更新")
    
    def add_to_ip_whitelist(self, ip: str) -> None:
        """添加IP到白名单 - 测试兼容性方法"""
        if ip not in self._config.whitelist_ips:
            self._config.whitelist_ips.append(ip)
    
    def remove_from_ip_whitelist(self, ip: str) -> None:
        """从白名单移除IP - 测试兼容性方法"""
        if ip in self._config.whitelist_ips:
            self._config.whitelist_ips.remove(ip)
    
    def add_to_process_whitelist(self, process: str) -> None:
        """添加进程到白名单 - 测试兼容性方法"""
        if not hasattr(self._config, 'whitelist_processes'):
            self._config.whitelist_processes = []
        if process not in self._config.whitelist_processes:
            self._config.whitelist_processes.append(process)
    
    def remove_from_process_whitelist(self, process: str) -> None:
        """从白名单移除进程 - 测试兼容性方法"""
        if hasattr(self._config, 'whitelist_processes') and process in self._config.whitelist_processes:
            self._config.whitelist_processes.remove(process)
    
    @property
    def config(self) -> FilterEngineConfig:
        """获取配置 - 测试兼容性属性"""
        return self._config
    
    @property
    def _active_filters(self) -> int:
        """获取活跃过滤器数量 - 测试兼容性属性"""
        return len(self._filter_pipeline._filters) if hasattr(self._filter_pipeline, '_filters') else 0


# 工厂函数
def create_filter_engine(config: Optional[Union[str, FilterEngineConfig, Dict[str, Any]]] = None) -> LocalFilterEngine:
    """创建过滤引擎实例
    
    Args:
        config: 配置，可以是:
            - str: 配置文件路径
            - FilterEngineConfig: 配置对象
            - Dict[str, Any]: 配置字典
            - None: 使用默认配置
        
    Returns:
        LocalFilterEngine: 过滤引擎实例
    """
    if config is None:
        # 使用默认配置
        engine_config = FilterEngineConfig()
    elif isinstance(config, FilterEngineConfig):
        # 直接使用配置对象
        engine_config = config
    elif isinstance(config, str):
        # 从文件加载配置
        engine_config = FilterEngineConfig()
        if Path(config).exists():
            try:
                with open(config, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                
                for key, value in file_config.items():
                    if hasattr(engine_config, key):
                        setattr(engine_config, key, value)
            except Exception as e:
                logging.error(f"加载配置文件失败: {e}")
    elif isinstance(config, dict):
        # 从字典创建配置
        engine_config = FilterEngineConfig()
        for key, value in config.items():
            if hasattr(engine_config, key):
                setattr(engine_config, key, value)
    else:
        raise TypeError(f"不支持的配置类型: {type(config)}")
    
    return LocalFilterEngine(engine_config)