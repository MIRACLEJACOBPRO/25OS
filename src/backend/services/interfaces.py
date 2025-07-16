#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS 核心接口定义
定义系统中各个组件的抽象接口，确保模块间的解耦和可扩展性

接口设计原则:
1. 单一职责原则 - 每个接口专注于特定功能
2. 开闭原则 - 对扩展开放，对修改封闭
3. 依赖倒置原则 - 依赖抽象而非具体实现
4. 接口隔离原则 - 接口应该小而专一
"""

from abc import ABC, abstractmethod
from typing import Protocol, List, Dict, Any, Optional, AsyncIterator, Union
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field

# 导入现有的数据结构
try:
    from services.falco_log_parser import StandardizedEvent, EventPriority
except ImportError:
    # 如果导入失败，定义基础数据结构
    from enum import Enum
    
    class EventPriority(Enum):
        CRITICAL = 1
        HIGH = 2
        MEDIUM = 3
        LOW = 4
        DEBUG = 5
        INFO = 4  # 别名，映射到 LOW
        WARNING = 2  # 别名，映射到 HIGH


class QueryType(Enum):
    """查询类型枚举"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    UPDATE = "update"
    COMPLEX = "complex"


class OptimizationLevel(Enum):
    """优化级别枚举"""
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


class CacheStrategy(Enum):
    """缓存策略枚举"""
    LRU = "lru"
    LFU = "lfu"
    TTL = "ttl"
    NONE = "none"


class FilterResult(Enum):
    """过滤结果枚举"""
    PASS = "pass"           # 通过过滤
    BLOCK = "block"         # 被过滤阻止
    SUSPICIOUS = "suspicious" # 可疑，需要进一步分析
    WHITELIST = "whitelist" # 白名单，直接通过


class FilterDecision(Enum):
    """过滤决策枚举 - 与FilterResult相同，为了兼容性"""
    PASS = "pass"           # 通过过滤
    BLOCK = "block"         # 被过滤阻止
    SUSPICIOUS = "suspicious" # 可疑，需要进一步分析
    WHITELIST = "whitelist" # 白名单，直接通过


@dataclass
class FilterContext:
    """过滤上下文信息"""
    filter_name: str                    # 过滤器名称
    result: FilterResult                # 过滤结果
    confidence: float                   # 置信度 (0.0-1.0)
    reason: str                         # 过滤原因
    metadata: Dict[str, Any]            # 额外元数据
    processing_time: float              # 处理时间(毫秒)
    timestamp: datetime                 # 处理时间戳


@dataclass
class AnomalyScore:
    """异常评分结果"""
    total_score: float                  # 总体异常分数 (0.0-1.0)
    category_scores: Dict[str, float]   # 分类评分
    risk_level: EventPriority           # 风险等级
    indicators: List[str]               # 异常指标列表
    confidence: float                   # 评分置信度
    explanation: str                    # 评分解释


class IEventFilter(Protocol):
    """事件过滤器接口"""
    
    @property
    def name(self) -> str:
        """过滤器名称"""
        ...
    
    @property
    def priority(self) -> int:
        """过滤器优先级，数值越小优先级越高"""
        ...
    
    async def filter(self, event: StandardizedEvent) -> FilterContext:
        """过滤事件
        
        Args:
            event: 标准化事件
            
        Returns:
            FilterContext: 过滤上下文结果
        """
        ...
    
    async def configure(self, config: Dict[str, Any]) -> None:
        """配置过滤器
        
        Args:
            config: 配置参数
        """
        ...
    
    async def get_statistics(self) -> Dict[str, Any]:
        """获取过滤器统计信息"""
        ...


class IDetectionStrategy(Protocol):
    """检测策略接口"""
    
    @property
    def strategy_name(self) -> str:
        """策略名称"""
        ...
    
    async def detect(self, event: StandardizedEvent, context: Dict[str, Any]) -> AnomalyScore:
        """执行异常检测
        
        Args:
            event: 标准化事件
            context: 检测上下文
            
        Returns:
            AnomalyScore: 异常评分结果
        """
        ...
    
    async def update_model(self, events: List[StandardizedEvent]) -> None:
        """更新检测模型
        
        Args:
            events: 训练事件列表
        """
        ...


class IEventCorrelator(Protocol):
    """事件关联器接口"""
    
    async def correlate(self, event: StandardizedEvent, 
                       time_window: int = 300) -> List[StandardizedEvent]:
        """关联相关事件
        
        Args:
            event: 当前事件
            time_window: 时间窗口(秒)
            
        Returns:
            List[StandardizedEvent]: 相关事件列表
        """
        ...
    
    async def find_patterns(self, events: List[StandardizedEvent]) -> List[Dict[str, Any]]:
        """查找事件模式
        
        Args:
            events: 事件列表
            
        Returns:
            List[Dict[str, Any]]: 发现的模式列表
        """
        ...


class IAnomalyScorer(Protocol):
    """异常评分器接口"""
    
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
        ...
    
    async def update_baseline(self, events: List[StandardizedEvent]) -> None:
        """更新基线模型
        
        Args:
            events: 基线事件数据
        """
        ...


class IFilterPipeline(Protocol):
    """过滤管道接口"""
    
    async def add_filter(self, filter_instance: IEventFilter) -> None:
        """添加过滤器
        
        Args:
            filter_instance: 过滤器实例
        """
        ...
    
    async def remove_filter(self, filter_name: str) -> None:
        """移除过滤器
        
        Args:
            filter_name: 过滤器名称
        """
        ...
    
    async def process(self, event: StandardizedEvent) -> List[FilterContext]:
        """处理事件通过管道
        
        Args:
            event: 标准化事件
            
        Returns:
            List[FilterContext]: 所有过滤器的处理结果
        """
        ...
    
    async def get_pipeline_status(self) -> Dict[str, Any]:
        """获取管道状态"""
        ...


class IAnomalyDetectionEngine(Protocol):
    """异常检测引擎接口"""
    
    async def detect_anomaly(self, event: StandardizedEvent) -> AnomalyScore:
        """检测事件异常
        
        Args:
            event: 标准化事件
            
        Returns:
            AnomalyScore: 异常评分结果
        """
        ...
    
    async def configure_engine(self, config: Dict[str, Any]) -> None:
        """配置检测引擎
        
        Args:
            config: 引擎配置
        """
        ...
    
    async def get_engine_metrics(self) -> Dict[str, Any]:
        """获取引擎指标"""
        ...
    
    async def start_engine(self) -> None:
        """启动检测引擎"""
        ...
    
    async def stop_engine(self) -> None:
        """停止检测引擎"""
        ...


class IWhitelistManager(Protocol):
    """白名单管理器接口"""
    
    async def is_whitelisted(self, event: StandardizedEvent) -> bool:
        """检查事件是否在白名单中
        
        Args:
            event: 标准化事件
            
        Returns:
            bool: 是否在白名单中
        """
        ...
    
    async def add_whitelist_rule(self, rule: Dict[str, Any]) -> None:
        """添加白名单规则
        
        Args:
            rule: 白名单规则
        """
        ...
    
    async def remove_whitelist_rule(self, rule_id: str) -> None:
        """移除白名单规则
        
        Args:
            rule_id: 规则ID
        """
        ...
    
    async def get_whitelist_rules(self) -> List[Dict[str, Any]]:
        """获取所有白名单规则"""
        ...


# 抽象基类实现
class AbstractEventFilter(ABC):
    """事件过滤器抽象基类"""
    
    def __init__(self, name: str, priority: int = 100):
        self._name = name
        self._priority = priority
        self._statistics = {
            'processed_count': 0,
            'passed_count': 0,
            'blocked_count': 0,
            'suspicious_count': 0,
            'average_processing_time': 0.0
        }
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def priority(self) -> int:
        return self._priority
    
    @abstractmethod
    async def filter(self, event: StandardizedEvent) -> FilterContext:
        """实现具体的过滤逻辑"""
        pass
    
    async def configure(self, config: Dict[str, Any]) -> None:
        """默认配置实现"""
        pass
    
    async def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self._statistics.copy()
    
    def _update_statistics(self, result: FilterResult, processing_time: float):
        """更新统计信息"""
        self._statistics['processed_count'] += 1
        
        if result == FilterResult.PASS:
            self._statistics['passed_count'] += 1
        elif result == FilterResult.BLOCK:
            self._statistics['blocked_count'] += 1
        elif result == FilterResult.SUSPICIOUS:
            self._statistics['suspicious_count'] += 1
        
        # 更新平均处理时间
        total_time = (self._statistics['average_processing_time'] * 
                     (self._statistics['processed_count'] - 1) + processing_time)
        self._statistics['average_processing_time'] = total_time / self._statistics['processed_count']


class AbstractDetectionStrategy(ABC):
    """检测策略抽象基类"""
    
    def __init__(self, strategy_name: str):
        self._strategy_name = strategy_name
    
    @property
    def strategy_name(self) -> str:
        return self._strategy_name
    
    @abstractmethod
    async def detect(self, event: StandardizedEvent, context: Dict[str, Any]) -> AnomalyScore:
        """实现具体的检测逻辑"""
        pass
    
    async def update_model(self, events: List[StandardizedEvent]) -> None:
        """默认模型更新实现"""
        pass