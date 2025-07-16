#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS 异常检测与过滤模块 - 本地过滤引擎实现

本模块实现1.3.1本地过滤引擎的核心功能:
1. 事件过滤管道 - 多级过滤器链式处理
2. 异常检测策略 - 可插拔的检测算法
3. 事件关联分析 - 时间窗口内的事件关联
4. 异常评分系统 - 综合评分和风险评估
5. 白名单管理 - 动态白名单规则管理

设计原则:
- 高内聚低耦合: 各组件职责明确，接口清晰
- 可扩展性: 支持动态添加过滤器和检测策略
- 配置驱动: 通过配置文件控制行为
- 性能优化: 异步处理，批量操作，缓存机制
"""

import asyncio
import time
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import json
import hashlib
from pathlib import Path

# 导入接口定义
from .interfaces import (
    IEventFilter, IDetectionStrategy, IEventCorrelator, IAnomalyScorer,
    IFilterPipeline, IAnomalyDetectionEngine, IWhitelistManager,
    AbstractEventFilter, AbstractDetectionStrategy,
    FilterResult, FilterContext, AnomalyScore, EventPriority
)

# 导入现有组件
try:
    from .falco_log_parser import StandardizedEvent
    from ..core.config import Settings
except ImportError:
    # 如果导入失败，使用基础定义
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


class EventFilterPipeline:
    """事件过滤管道实现
    
    负责管理多个过滤器的执行顺序和结果聚合
    支持动态添加/移除过滤器，按优先级排序执行
    """
    
    def __init__(self, max_concurrent_filters: int = 10):
        self._filters: List[IEventFilter] = []
        self._filter_map: Dict[str, IEventFilter] = {}
        self._max_concurrent = max_concurrent_filters
        self._pipeline_stats = {
            'total_processed': 0,
            'total_passed': 0,
            'total_blocked': 0,
            'average_processing_time': 0.0,
            'filter_performance': {}
        }
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def add_filter(self, filter_instance: IEventFilter) -> None:
        """添加过滤器到管道
        
        Args:
            filter_instance: 过滤器实例
        """
        if filter_instance.name in self._filter_map:
            self._logger.warning(f"过滤器 {filter_instance.name} 已存在，将被替换")
            await self.remove_filter(filter_instance.name)
        
        self._filters.append(filter_instance)
        self._filter_map[filter_instance.name] = filter_instance
        
        # 按优先级排序
        self._filters.sort(key=lambda f: f.priority)
        
        self._logger.info(f"已添加过滤器: {filter_instance.name}, 优先级: {filter_instance.priority}")
    
    async def remove_filter(self, filter_name: str) -> None:
        """从管道中移除过滤器
        
        Args:
            filter_name: 过滤器名称
        """
        if filter_name not in self._filter_map:
            self._logger.warning(f"过滤器 {filter_name} 不存在")
            return
        
        filter_instance = self._filter_map[filter_name]
        self._filters.remove(filter_instance)
        del self._filter_map[filter_name]
        
        self._logger.info(f"已移除过滤器: {filter_name}")
    
    async def process(self, event: StandardizedEvent) -> List[FilterContext]:
        """处理事件通过过滤管道
        
        Args:
            event: 标准化事件
            
        Returns:
            List[FilterContext]: 所有过滤器的处理结果
        """
        start_time = time.time()
        results = []
        
        try:
            # 并发执行过滤器（如果数量不多）或分批执行
            if len(self._filters) <= self._max_concurrent:
                tasks = [filter_inst.filter(event) for filter_inst in self._filters]
                results = await asyncio.gather(*tasks, return_exceptions=True)
            else:
                # 分批处理
                for i in range(0, len(self._filters), self._max_concurrent):
                    batch = self._filters[i:i + self._max_concurrent]
                    tasks = [filter_inst.filter(event) for filter_inst in batch]
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    results.extend(batch_results)
            
            # 处理异常结果
            valid_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    self._logger.error(f"过滤器 {self._filters[i].name} 执行失败: {result}")
                    # 创建错误结果
                    error_context = FilterContext(
                        filter_name=self._filters[i].name,
                        result=FilterResult.PASS,  # 默认通过，避免误杀
                        confidence=0.0,
                        reason=f"过滤器执行异常: {str(result)}",
                        metadata={'error': True, 'exception': str(result)},
                        processing_time=0.0,
                        timestamp=datetime.now()
                    )
                    valid_results.append(error_context)
                else:
                    valid_results.append(result)
            
            # 更新统计信息
            processing_time = (time.time() - start_time) * 1000  # 转换为毫秒
            self._update_pipeline_stats(valid_results, processing_time)
            
            return valid_results
            
        except Exception as e:
            self._logger.error(f"管道处理事件失败: {e}")
            return []
    
    async def get_pipeline_status(self) -> Dict[str, Any]:
        """获取管道状态信息"""
        filter_status = []
        for filter_inst in self._filters:
            try:
                stats = await filter_inst.get_statistics()
                filter_status.append({
                    'name': filter_inst.name,
                    'priority': filter_inst.priority,
                    'statistics': stats
                })
            except Exception as e:
                filter_status.append({
                    'name': filter_inst.name,
                    'priority': filter_inst.priority,
                    'error': str(e)
                })
        
        return {
            'total_filters': len(self._filters),
            'pipeline_statistics': self._pipeline_stats,
            'filters': filter_status
        }
    
    def _update_pipeline_stats(self, results: List[FilterContext], processing_time: float):
        """更新管道统计信息"""
        self._pipeline_stats['total_processed'] += 1
        
        # 统计结果分布
        for result in results:
            if result.result == FilterResult.PASS:
                self._pipeline_stats['total_passed'] += 1
            elif result.result == FilterResult.BLOCK:
                self._pipeline_stats['total_blocked'] += 1
        
        # 更新平均处理时间
        total_time = (self._pipeline_stats['average_processing_time'] * 
                     (self._pipeline_stats['total_processed'] - 1) + processing_time)
        self._pipeline_stats['average_processing_time'] = total_time / self._pipeline_stats['total_processed']


class EventCorrelator:
    """事件关联器实现
    
    负责在时间窗口内查找相关事件，识别事件模式
    使用滑动窗口和事件缓存机制提高性能
    """
    
    def __init__(self, max_cache_size: int = 10000, default_window: int = 300):
        self._event_cache: deque = deque(maxlen=max_cache_size)
        self._default_window = default_window
        self._correlation_patterns = {
            'same_source': self._correlate_by_source,
            'same_target': self._correlate_by_target,
            'same_rule': self._correlate_by_rule,
            'temporal_sequence': self._correlate_by_temporal_sequence
        }
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def correlate(self, event: StandardizedEvent, 
                       time_window: int = None) -> List[StandardizedEvent]:
        """关联相关事件
        
        Args:
            event: 当前事件
            time_window: 时间窗口(秒)
            
        Returns:
            List[StandardizedEvent]: 相关事件列表
        """
        if time_window is None:
            time_window = self._default_window
        
        # 添加当前事件到缓存
        self._event_cache.append(event)
        
        # 计算时间窗口
        window_start = event.timestamp - timedelta(seconds=time_window)
        window_end = event.timestamp + timedelta(seconds=time_window)
        
        # 在时间窗口内查找事件
        window_events = [
            cached_event for cached_event in self._event_cache
            if window_start <= cached_event.timestamp <= window_end
            and cached_event.event_id != event.event_id
        ]
        
        # 应用关联模式
        correlated_events = []
        seen_event_ids = set()
        for pattern_name, pattern_func in self._correlation_patterns.items():
            try:
                pattern_events = await pattern_func(event, window_events)
                for e in pattern_events:
                    if e.event_id not in seen_event_ids:
                        correlated_events.append(e)
                        seen_event_ids.add(e.event_id)
            except Exception as e:
                self._logger.error(f"关联模式 {pattern_name} 执行失败: {e}")
        
        return correlated_events
    
    async def find_patterns(self, events: List[StandardizedEvent]) -> List[Dict[str, Any]]:
        """查找事件模式
        
        Args:
            events: 事件列表
            
        Returns:
            List[Dict[str, Any]]: 发现的模式列表
        """
        patterns = []
        
        # 按时间排序
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # 检测频率模式
        frequency_patterns = self._detect_frequency_patterns(sorted_events)
        patterns.extend(frequency_patterns)
        
        # 检测序列模式
        sequence_patterns = self._detect_sequence_patterns(sorted_events)
        patterns.extend(sequence_patterns)
        
        # 检测异常聚集模式
        cluster_patterns = self._detect_cluster_patterns(sorted_events)
        patterns.extend(cluster_patterns)
        
        return patterns
    
    async def _correlate_by_source(self, event: StandardizedEvent, 
                                  window_events: List[StandardizedEvent]) -> List[StandardizedEvent]:
        """基于源地址关联事件"""
        source_ip = event.triple.subject if event.triple else ''
        if not source_ip:
            return []
        
        return [
            e for e in window_events
            if e.triple and e.triple.subject == source_ip
        ]
    
    async def _correlate_by_target(self, event: StandardizedEvent, 
                                  window_events: List[StandardizedEvent]) -> List[StandardizedEvent]:
        """基于目标地址关联事件"""
        target_ip = event.triple.object if event.triple else ''
        if not target_ip:
            return []
        
        return [
            e for e in window_events
            if e.triple and e.triple.object == target_ip
        ]
    
    async def _correlate_by_rule(self, event: StandardizedEvent, 
                                window_events: List[StandardizedEvent]) -> List[StandardizedEvent]:
        """基于规则关联事件"""
        return [
            e for e in window_events
            if e.rule_name == event.rule_name
        ]
    
    async def _correlate_by_temporal_sequence(self, event: StandardizedEvent, 
                                            window_events: List[StandardizedEvent]) -> List[StandardizedEvent]:
        """基于时间序列关联事件"""
        # 查找在当前事件前后短时间内的事件
        short_window = timedelta(seconds=30)  # 30秒的短窗口
        
        return [
            e for e in window_events
            if abs((e.timestamp - event.timestamp).total_seconds()) <= 30
        ]
    
    def _detect_frequency_patterns(self, events: List[StandardizedEvent]) -> List[Dict[str, Any]]:
        """检测频率异常模式"""
        patterns = []
        
        # 按规则分组统计频率
        rule_counts = defaultdict(int)
        for event in events:
            rule_counts[event.rule_name] += 1
        
        # 检测高频规则
        avg_count = sum(rule_counts.values()) / len(rule_counts) if rule_counts else 0
        for rule, count in rule_counts.items():
            if count > avg_count * 3:  # 超过平均值3倍
                patterns.append({
                    'type': 'high_frequency',
                    'rule': rule,
                    'count': count,
                    'threshold': avg_count * 3,
                    'severity': 'medium' if count < avg_count * 5 else 'high'
                })
        
        return patterns
    
    def _detect_sequence_patterns(self, events: List[StandardizedEvent]) -> List[Dict[str, Any]]:
        """检测序列模式"""
        patterns = []
        
        # 检测连续相同规则触发
        consecutive_count = 1
        current_rule = None
        
        for event in events:
            if event.rule_name == current_rule:
                consecutive_count += 1
            else:
                if consecutive_count >= 5:  # 连续5次以上
                    patterns.append({
                        'type': 'consecutive_triggers',
                        'rule': current_rule,
                        'count': consecutive_count,
                        'severity': 'medium'
                    })
                current_rule = event.rule_name
                consecutive_count = 1
        
        return patterns
    
    def _detect_cluster_patterns(self, events: List[StandardizedEvent]) -> List[Dict[str, Any]]:
        """检测聚集模式"""
        patterns = []
        
        # 检测时间聚集
        if len(events) >= 10:  # 至少10个事件
            time_span = (events[-1].timestamp - events[0].timestamp).total_seconds()
            if time_span <= 60:  # 1分钟内
                patterns.append({
                    'type': 'time_cluster',
                    'event_count': len(events),
                    'time_span': time_span,
                    'severity': 'high'
                })
        
        return patterns


class AnomalyScorer:
    """异常评分器实现
    
    综合多个维度计算事件的异常分数
    支持动态权重调整和基线学习
    """
    
    def __init__(self):
        self._scoring_weights = {
            'priority_weight': 0.5,      # 事件优先级权重
            'frequency_weight': 0.2,     # 频率异常权重
            'correlation_weight': 0.15,  # 关联事件权重
            'filter_weight': 0.1,        # 过滤器结果权重
            'pattern_weight': 0.05       # 模式匹配权重
        }
        self._baseline_stats = {
            'rule_frequencies': defaultdict(float),
            'avg_correlation_count': 0.0,
            'total_events': 0
        }
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def score(self, event: StandardizedEvent, 
                   correlations: List[StandardizedEvent],
                   filter_results: List[FilterContext]) -> AnomalyScore:
        """计算异常评分
        
        Args:
            event: 当前事件
            correlations: 关联事件
            filter_results: 过滤结果
            
        Returns:
            AnomalyScore: 异常评分
        """
        try:
            # 计算各维度分数
            priority_score = self._calculate_priority_score(event)
            frequency_score = self._calculate_frequency_score(event)
            correlation_score = self._calculate_correlation_score(correlations)
            filter_score = self._calculate_filter_score(filter_results)
            pattern_score = self._calculate_pattern_score(event, correlations)
            
            # 加权计算总分
            total_score = (
                priority_score * self._scoring_weights['priority_weight'] +
                frequency_score * self._scoring_weights['frequency_weight'] +
                correlation_score * self._scoring_weights['correlation_weight'] +
                filter_score * self._scoring_weights['filter_weight'] +
                pattern_score * self._scoring_weights['pattern_weight']
            )
            
            # 确保分数在0-1范围内
            total_score = max(0.0, min(1.0, total_score))
            
            # 计算风险等级
            risk_level = self._calculate_risk_level(total_score)
            
            # 生成异常指标
            indicators = self._generate_indicators(event, correlations, filter_results)
            
            # 计算置信度
            confidence = self._calculate_confidence(filter_results, len(correlations))
            
            # 生成解释
            explanation = self._generate_explanation(total_score, {
                'priority': priority_score,
                'frequency': frequency_score,
                'correlation': correlation_score,
                'filter': filter_score,
                'pattern': pattern_score
            })
            
            return AnomalyScore(
                total_score=total_score,
                category_scores={
                    'priority': priority_score,
                    'frequency': frequency_score,
                    'correlation': correlation_score,
                    'filter': filter_score,
                    'pattern': pattern_score
                },
                risk_level=risk_level,
                indicators=indicators,
                confidence=confidence,
                explanation=explanation
            )
            
        except Exception as e:
            self._logger.error(f"异常评分计算失败: {e}")
            # 返回默认低分
            return AnomalyScore(
                total_score=0.1,
                category_scores={},
                risk_level=EventPriority.LOW,
                indicators=["评分计算异常"],
                confidence=0.0,
                explanation=f"评分计算失败: {str(e)}"
            )
    
    async def update_baseline(self, events: List[StandardizedEvent]) -> None:
        """更新基线模型
        
        Args:
            events: 基线事件数据
        """
        if not events:
            return
        
        # 更新规则频率基线
        rule_counts = defaultdict(int)
        for event in events:
            rule_counts[event.rule_name] += 1
        
        total_events = len(events)
        for rule, count in rule_counts.items():
            self._baseline_stats['rule_frequencies'][rule] = count / total_events
        
        self._baseline_stats['total_events'] = total_events
        
        self._logger.info(f"基线模型已更新，包含 {total_events} 个事件，{len(rule_counts)} 个规则")
    
    def _calculate_priority_score(self, event: StandardizedEvent) -> float:
        """计算优先级分数"""
        priority_scores = {
            EventPriority.CRITICAL: 1.0,
            EventPriority.HIGH: 0.8,
            EventPriority.MEDIUM: 0.5,
            EventPriority.LOW: 0.2,
            EventPriority.DEBUG: 0.1
        }
        return priority_scores.get(event.priority, 0.5)
    
    def _calculate_frequency_score(self, event: StandardizedEvent) -> float:
        """计算频率异常分数"""
        baseline_freq = self._baseline_stats['rule_frequencies'].get(event.rule_name, 0.01)
        
        # 如果规则很少见，分数较高
        if baseline_freq < 0.001:  # 非常罕见
            return 0.9
        elif baseline_freq < 0.01:  # 罕见
            return 0.7
        elif baseline_freq < 0.1:  # 不常见
            return 0.4
        else:  # 常见
            return 0.2
    
    def _calculate_correlation_score(self, correlations: List[StandardizedEvent]) -> float:
        """计算关联事件分数"""
        correlation_count = len(correlations)
        
        # 关联事件越多，异常分数越高
        if correlation_count == 0:
            return 0.1
        elif correlation_count <= 2:
            return 0.3
        elif correlation_count <= 5:
            return 0.6
        else:
            return 0.9
    
    def _calculate_filter_score(self, filter_results: List[FilterContext]) -> float:
        """计算过滤器结果分数"""
        if not filter_results:
            return 0.5
        
        # 统计过滤结果
        blocked_count = sum(1 for r in filter_results if r.result == FilterResult.BLOCK)
        suspicious_count = sum(1 for r in filter_results if r.result == FilterResult.SUSPICIOUS)
        total_count = len(filter_results)
        
        # 计算异常比例
        anomaly_ratio = (blocked_count + suspicious_count * 0.5) / total_count
        return anomaly_ratio
    
    def _calculate_pattern_score(self, event: StandardizedEvent, 
                               correlations: List[StandardizedEvent]) -> float:
        """计算模式匹配分数"""
        # 简单的模式检测
        score = 0.0
        
        # 检查是否有相同源IP的多个事件
        source_ip = event.triple.subject if event.triple else ''
        if source_ip:
            same_source_count = sum(
                1 for e in correlations 
                if e.triple and e.triple.subject == source_ip
            )
            if same_source_count >= 3:
                score += 0.3
        
        # 检查是否有相同目标的多个事件
        target_ip = event.triple.object if event.triple else ''
        if target_ip:
            same_target_count = sum(
                1 for e in correlations 
                if e.triple and e.triple.object == target_ip
            )
            if same_target_count >= 3:
                score += 0.3
        
        return min(score, 1.0)
    
    def _calculate_risk_level(self, total_score: float) -> EventPriority:
        """根据总分计算风险等级"""
        if total_score >= 0.8:
            return EventPriority.CRITICAL
        elif total_score >= 0.6:
            return EventPriority.HIGH
        elif total_score >= 0.4:
            return EventPriority.MEDIUM
        else:
            return EventPriority.LOW
    
    def _generate_indicators(self, event: StandardizedEvent, 
                           correlations: List[StandardizedEvent],
                           filter_results: List[FilterContext]) -> List[str]:
        """生成异常指标列表"""
        indicators = []
        
        # 基于优先级的指标
        if event.priority in [EventPriority.CRITICAL, EventPriority.HIGH]:
            indicators.append(f"高优先级事件: {event.priority.name}")
        
        # 基于关联事件的指标
        if len(correlations) > 5:
            indicators.append(f"大量关联事件: {len(correlations)}个")
        
        # 基于过滤结果的指标
        blocked_filters = [r.filter_name for r in filter_results if r.result == FilterResult.BLOCK]
        if blocked_filters:
            indicators.append(f"被过滤器阻止: {', '.join(blocked_filters)}")
        
        suspicious_filters = [r.filter_name for r in filter_results if r.result == FilterResult.SUSPICIOUS]
        if suspicious_filters:
            indicators.append(f"可疑事件: {', '.join(suspicious_filters)}")
        
        return indicators
    
    def _calculate_confidence(self, filter_results: List[FilterContext], 
                            correlation_count: int) -> float:
        """计算评分置信度"""
        confidence = 0.5  # 基础置信度
        
        # 过滤器数量越多，置信度越高
        if filter_results:
            confidence += min(len(filter_results) * 0.1, 0.3)
        
        # 关联事件数量适中时置信度较高
        if 1 <= correlation_count <= 10:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _generate_explanation(self, total_score: float, 
                            category_scores: Dict[str, float]) -> str:
        """生成评分解释"""
        explanations = []
        
        # 总分解释
        if total_score >= 0.8:
            explanations.append("高风险事件")
        elif total_score >= 0.6:
            explanations.append("中高风险事件")
        elif total_score >= 0.4:
            explanations.append("中等风险事件")
        else:
            explanations.append("低风险事件")
        
        # 主要贡献因素
        max_category = max(category_scores.items(), key=lambda x: x[1])
        explanations.append(f"主要风险因素: {max_category[0]} ({max_category[1]:.2f})")
        
        return "; ".join(explanations)