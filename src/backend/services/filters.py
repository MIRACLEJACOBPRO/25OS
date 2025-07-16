#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS 过滤器实现模块

本模块包含各种具体的事件过滤器实现:
1. 基础过滤器 - 优先级、频率、规则过滤
2. 安全过滤器 - IP白名单、端口过滤、协议过滤
3. 行为过滤器 - 异常行为检测、模式匹配
4. 白名单管理器 - 动态白名单规则管理
5. 自适应过滤器 - 基于机器学习的过滤

设计特点:
- 可配置: 所有过滤器支持动态配置
- 高性能: 优化的算法和缓存机制
- 可扩展: 易于添加新的过滤逻辑
- 可观测: 详细的统计和日志记录
"""

import asyncio
import time
import re
import ipaddress
import json
from typing import List, Dict, Any, Set, Optional, Pattern
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass
import logging
from pathlib import Path

# 导入接口和基类
from .interfaces import (
    AbstractEventFilter, IWhitelistManager,
    FilterResult, FilterContext, EventPriority
)

# 导入事件定义
try:
    from .falco_log_parser import StandardizedEvent
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


class PriorityFilter(AbstractEventFilter):
    """优先级过滤器
    
    根据事件优先级进行过滤，可配置最低通过优先级
    """
    
    def __init__(self, min_priority: EventPriority = EventPriority.MEDIUM):
        super().__init__("priority_filter", priority=10)
        self._min_priority = min_priority
        self._priority_order = {
            EventPriority.CRITICAL: 1,
            EventPriority.HIGH: 2,
            EventPriority.MEDIUM: 3,
            EventPriority.LOW: 4,
            EventPriority.DEBUG: 5
        }
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def filter(self, event: StandardizedEvent) -> FilterContext:
        """根据优先级过滤事件"""
        start_time = time.time()
        
        try:
            event_priority_level = self._priority_order.get(event.priority, 5)
            min_priority_level = self._priority_order.get(self._min_priority, 3)
            
            if event_priority_level <= min_priority_level:
                result = FilterResult.PASS
                reason = f"事件优先级 {event.priority.name} 满足最低要求 {self._min_priority.name}"
                confidence = 0.9
            else:
                result = FilterResult.BLOCK
                reason = f"事件优先级 {event.priority.name} 低于最低要求 {self._min_priority.name}"
                confidence = 0.8
            
            processing_time = (time.time() - start_time) * 1000
            self._update_statistics(result, processing_time)
            
            return FilterContext(
                filter_name=self.name,
                result=result,
                confidence=confidence,
                reason=reason,
                metadata={
                    'event_priority': event.priority.name,
                    'min_priority': self._min_priority.name,
                    'priority_level': event_priority_level
                },
                processing_time=processing_time,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            self._logger.error(f"优先级过滤失败: {e}")
            processing_time = (time.time() - start_time) * 1000
            return FilterContext(
                filter_name=self.name,
                result=FilterResult.PASS,  # 异常时默认通过
                confidence=0.0,
                reason=f"过滤器异常: {str(e)}",
                metadata={'error': True},
                processing_time=processing_time,
                timestamp=datetime.now()
            )
    
    async def configure(self, config: Dict[str, Any]) -> None:
        """配置过滤器"""
        if 'min_priority' in config:
            try:
                self._min_priority = EventPriority[config['min_priority'].upper()]
                self._logger.info(f"最低优先级已更新为: {self._min_priority.name}")
            except (KeyError, AttributeError) as e:
                self._logger.error(f"无效的优先级配置: {config['min_priority']}")


class FrequencyFilter(AbstractEventFilter):
    """频率过滤器
    
    检测事件频率异常，防止事件风暴
    """
    
    def __init__(self, max_events_per_minute: int = 100, time_window: int = 60):
        super().__init__("frequency_filter", priority=20)
        self._max_events_per_minute = max_events_per_minute
        self._time_window = time_window
        self._event_timestamps: Dict[str, deque] = defaultdict(lambda: deque())
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def filter(self, event: StandardizedEvent) -> FilterContext:
        """根据频率过滤事件"""
        start_time = time.time()
        
        try:
            # 使用规则作为频率统计的键
            rule_key = event.rule_name
            current_time = event.timestamp
            
            # 清理过期的时间戳
            cutoff_time = current_time - timedelta(seconds=self._time_window)
            timestamps = self._event_timestamps[rule_key]
            
            while timestamps and timestamps[0] < cutoff_time:
                timestamps.popleft()
            
            # 添加当前事件时间戳
            timestamps.append(current_time)
            
            # 计算当前频率
            current_frequency = len(timestamps)
            frequency_per_minute = (current_frequency * 60) / self._time_window
            
            if frequency_per_minute > self._max_events_per_minute:
                result = FilterResult.SUSPICIOUS
                reason = f"规则 {rule_key} 频率过高: {frequency_per_minute:.1f}/分钟 > {self._max_events_per_minute}/分钟"
                confidence = min(0.9, frequency_per_minute / self._max_events_per_minute - 1)
            else:
                result = FilterResult.PASS
                reason = f"规则 {rule_key} 频率正常: {frequency_per_minute:.1f}/分钟"
                confidence = 0.7
            
            processing_time = (time.time() - start_time) * 1000
            self._update_statistics(result, processing_time)
            
            return FilterContext(
                filter_name=self.name,
                result=result,
                confidence=confidence,
                reason=reason,
                metadata={
                    'rule': rule_key,
                    'current_frequency': frequency_per_minute,
                    'max_frequency': self._max_events_per_minute,
                    'event_count_in_window': current_frequency
                },
                processing_time=processing_time,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            self._logger.error(f"频率过滤失败: {e}")
            processing_time = (time.time() - start_time) * 1000
            return FilterContext(
                filter_name=self.name,
                result=FilterResult.PASS,
                confidence=0.0,
                reason=f"过滤器异常: {str(e)}",
                metadata={'error': True},
                processing_time=processing_time,
                timestamp=datetime.now()
            )
    
    async def configure(self, config: Dict[str, Any]) -> None:
        """配置过滤器"""
        if 'max_events_per_minute' in config:
            self._max_events_per_minute = int(config['max_events_per_minute'])
            self._logger.info(f"最大频率已更新为: {self._max_events_per_minute}/分钟")
        
        if 'time_window' in config:
            self._time_window = int(config['time_window'])
            self._logger.info(f"时间窗口已更新为: {self._time_window}秒")


class IPWhitelistFilter(AbstractEventFilter):
    """IP白名单过滤器
    
    根据IP白名单过滤事件，支持CIDR格式
    """
    
    def __init__(self, whitelist_ips: List[str] = None):
        super().__init__("ip_whitelist_filter", priority=5)
        self._whitelist_networks = set()
        self._whitelist_ips = set()
        
        if whitelist_ips:
            self._load_whitelist(whitelist_ips)
        
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def _load_whitelist(self, ip_list: List[str]):
        """加载IP白名单"""
        for ip_str in ip_list:
            try:
                if '/' in ip_str:
                    # CIDR格式
                    network = ipaddress.ip_network(ip_str, strict=False)
                    self._whitelist_networks.add(network)
                else:
                    # 单个IP
                    ip = ipaddress.ip_address(ip_str)
                    self._whitelist_ips.add(ip)
            except ValueError as e:
                self._logger.warning(f"无效的IP地址: {ip_str}, 错误: {e}")
    
    def _is_ip_whitelisted(self, ip_str: str) -> bool:
        """检查IP是否在白名单中"""
        if not ip_str:
            return False
        
        try:
            ip = ipaddress.ip_address(ip_str)
            
            # 检查单个IP
            if ip in self._whitelist_ips:
                return True
            
            # 检查网络段
            for network in self._whitelist_networks:
                if ip in network:
                    return True
            
            return False
            
        except ValueError:
            return False
    
    async def filter(self, event: StandardizedEvent) -> FilterContext:
        """根据IP白名单过滤事件"""
        start_time = time.time()
        
        try:
            source_ip = event.triple.subject if hasattr(event.triple, 'subject') else ''
            target_ip = event.triple.object if hasattr(event.triple, 'object') else ''
            
            source_whitelisted = self._is_ip_whitelisted(source_ip) if source_ip else False
            target_whitelisted = self._is_ip_whitelisted(target_ip) if target_ip else False
            
            if source_whitelisted or target_whitelisted:
                result = FilterResult.WHITELIST
                reason = f"IP在白名单中: 源IP={source_ip}({source_whitelisted}), 目标IP={target_ip}({target_whitelisted})"
                confidence = 0.95
            else:
                result = FilterResult.PASS
                reason = f"IP不在白名单中: 源IP={source_ip}, 目标IP={target_ip}"
                confidence = 0.8
            
            processing_time = (time.time() - start_time) * 1000
            self._update_statistics(result, processing_time)
            
            return FilterContext(
                filter_name=self.name,
                result=result,
                confidence=confidence,
                reason=reason,
                metadata={
                    'source_ip': source_ip,
                    'target_ip': target_ip,
                    'source_whitelisted': source_whitelisted,
                    'target_whitelisted': target_whitelisted
                },
                processing_time=processing_time,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            self._logger.error(f"IP白名单过滤失败: {e}")
            processing_time = (time.time() - start_time) * 1000
            return FilterContext(
                filter_name=self.name,
                result=FilterResult.PASS,
                confidence=0.0,
                reason=f"过滤器异常: {str(e)}",
                metadata={'error': True},
                processing_time=processing_time,
                timestamp=datetime.now()
            )
    
    async def configure(self, config: Dict[str, Any]) -> None:
        """配置过滤器"""
        if 'whitelist_ips' in config:
            self._whitelist_networks.clear()
            self._whitelist_ips.clear()
            self._load_whitelist(config['whitelist_ips'])
            self._logger.info(f"IP白名单已更新，包含 {len(self._whitelist_ips)} 个IP和 {len(self._whitelist_networks)} 个网络段")


class RulePatternFilter(AbstractEventFilter):
    """规则模式过滤器
    
    基于正则表达式模式过滤事件
    """
    
    def __init__(self, block_patterns: List[str] = None, allow_patterns: List[str] = None):
        super().__init__("rule_pattern_filter", priority=30)
        self._block_patterns: List[Pattern] = []
        self._allow_patterns: List[Pattern] = []
        
        if block_patterns:
            self._compile_patterns(block_patterns, self._block_patterns)
        
        if allow_patterns:
            self._compile_patterns(allow_patterns, self._allow_patterns)
        
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def _compile_patterns(self, pattern_strings: List[str], pattern_list: List[Pattern]):
        """编译正则表达式模式"""
        for pattern_str in pattern_strings:
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                pattern_list.append(pattern)
            except re.error as e:
                self._logger.error(f"无效的正则表达式: {pattern_str}, 错误: {e}")
    
    async def filter(self, event: StandardizedEvent) -> FilterContext:
        """根据规则模式过滤事件"""
        start_time = time.time()
        
        try:
            rule_text = event.rule_name
            output_text = event.message
            
            # 检查允许模式
            for pattern in self._allow_patterns:
                if pattern.search(rule_text) or pattern.search(output_text):
                    result = FilterResult.WHITELIST
                    reason = f"匹配允许模式: {pattern.pattern}"
                    confidence = 0.9
                    
                    processing_time = (time.time() - start_time) * 1000
                    self._update_statistics(result, processing_time)
                    
                    return FilterContext(
                        filter_name=self.name,
                        result=result,
                        confidence=confidence,
                        reason=reason,
                        metadata={
                            'matched_pattern': pattern.pattern,
                            'pattern_type': 'allow',
                            'rule': rule_text
                        },
                        processing_time=processing_time,
                        timestamp=datetime.now()
                    )
            
            # 检查阻止模式
            for pattern in self._block_patterns:
                if pattern.search(rule_text) or pattern.search(output_text):
                    result = FilterResult.BLOCK
                    reason = f"匹配阻止模式: {pattern.pattern}"
                    confidence = 0.85
                    
                    processing_time = (time.time() - start_time) * 1000
                    self._update_statistics(result, processing_time)
                    
                    return FilterContext(
                        filter_name=self.name,
                        result=result,
                        confidence=confidence,
                        reason=reason,
                        metadata={
                            'matched_pattern': pattern.pattern,
                            'pattern_type': 'block',
                            'rule': rule_text
                        },
                        processing_time=processing_time,
                        timestamp=datetime.now()
                    )
            
            # 没有匹配任何模式
            result = FilterResult.PASS
            reason = "未匹配任何模式"
            confidence = 0.7
            
            processing_time = (time.time() - start_time) * 1000
            self._update_statistics(result, processing_time)
            
            return FilterContext(
                filter_name=self.name,
                result=result,
                confidence=confidence,
                reason=reason,
                metadata={
                    'rule': rule_text,
                    'patterns_checked': len(self._block_patterns) + len(self._allow_patterns)
                },
                processing_time=processing_time,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            self._logger.error(f"规则模式过滤失败: {e}")
            processing_time = (time.time() - start_time) * 1000
            return FilterContext(
                filter_name=self.name,
                result=FilterResult.PASS,
                confidence=0.0,
                reason=f"过滤器异常: {str(e)}",
                metadata={'error': True},
                processing_time=processing_time,
                timestamp=datetime.now()
            )
    
    async def configure(self, config: Dict[str, Any]) -> None:
        """配置过滤器"""
        if 'block_patterns' in config:
            self._block_patterns.clear()
            self._compile_patterns(config['block_patterns'], self._block_patterns)
            self._logger.info(f"阻止模式已更新，包含 {len(self._block_patterns)} 个模式")
        
        if 'allow_patterns' in config:
            self._allow_patterns.clear()
            self._compile_patterns(config['allow_patterns'], self._allow_patterns)
            self._logger.info(f"允许模式已更新，包含 {len(self._allow_patterns)} 个模式")


class WhitelistManager:
    """白名单管理器实现
    
    管理动态白名单规则，支持多种匹配条件
    """
    
    def __init__(self, whitelist_file: Optional[str] = None):
        self._whitelist_rules: Dict[str, Dict[str, Any]] = {}
        self._whitelist_file = whitelist_file
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        if whitelist_file and Path(whitelist_file).exists():
            self._load_whitelist_from_file()
    
    def _load_whitelist_from_file(self):
        """从文件加载白名单规则"""
        try:
            with open(self._whitelist_file, 'r', encoding='utf-8') as f:
                rules = json.load(f)
                self._whitelist_rules = rules
                self._logger.info(f"从文件加载了 {len(rules)} 个白名单规则")
        except Exception as e:
            self._logger.error(f"加载白名单文件失败: {e}")
    
    def _save_whitelist_to_file(self):
        """保存白名单规则到文件"""
        if not self._whitelist_file:
            return
        
        try:
            with open(self._whitelist_file, 'w', encoding='utf-8') as f:
                json.dump(self._whitelist_rules, f, indent=2, ensure_ascii=False, default=str)
                self._logger.info(f"白名单规则已保存到文件")
        except Exception as e:
            self._logger.error(f"保存白名单文件失败: {e}")
    
    async def is_whitelisted(self, event: StandardizedEvent) -> bool:
        """检查事件是否在白名单中"""
        for rule_id, rule in self._whitelist_rules.items():
            try:
                if self._match_rule(event, rule):
                    self._logger.debug(f"事件匹配白名单规则: {rule_id}")
                    return True
            except Exception as e:
                self._logger.error(f"白名单规则 {rule_id} 匹配失败: {e}")
        
        return False
    
    def _match_rule(self, event: StandardizedEvent, rule: Dict[str, Any]) -> bool:
        """检查事件是否匹配白名单规则"""
        # 检查规则名称
        if 'rule_name' in rule:
            if rule['rule_name'] != event.rule_name:
                return False
        
        # 检查优先级
        if 'priority' in rule:
            if rule['priority'] != event.priority.name:
                return False
        
        # 检查源IP
        if 'source_ip' in rule:
            source_ip = event.triple.subject if hasattr(event.triple, 'subject') else ''
            if not self._match_ip(source_ip, rule['source_ip']):
                return False
        
        # 检查目标IP
        if 'target_ip' in rule:
            target_ip = event.triple.object if hasattr(event.triple, 'object') else ''
            if not self._match_ip(target_ip, rule['target_ip']):
                return False
        
        # 检查输出模式
        if 'output_pattern' in rule:
            pattern = re.compile(rule['output_pattern'], re.IGNORECASE)
            if not pattern.search(event.message):
                return False
        
        # 检查时间范围
        if 'time_range' in rule:
            if not self._match_time_range(event.timestamp, rule['time_range']):
                return False
        
        return True
    
    def _match_ip(self, ip_str: str, rule_ip: str) -> bool:
        """检查IP是否匹配规则"""
        if not ip_str:
            return False
        
        try:
            if '/' in rule_ip:
                # CIDR格式
                network = ipaddress.ip_network(rule_ip, strict=False)
                ip = ipaddress.ip_address(ip_str)
                return ip in network
            else:
                # 单个IP或通配符
                if rule_ip == '*':
                    return True
                return ip_str == rule_ip
        except ValueError:
            return False
    
    def _match_time_range(self, event_time: datetime, time_range: Dict[str, str]) -> bool:
        """检查时间是否在范围内"""
        try:
            start_time = datetime.fromisoformat(time_range.get('start', '1970-01-01T00:00:00'))
            end_time = datetime.fromisoformat(time_range.get('end', '2099-12-31T23:59:59'))
            return start_time <= event_time <= end_time
        except ValueError:
            return True  # 时间格式错误时默认匹配
    
    async def add_whitelist_rule(self, rule: Dict[str, Any]) -> None:
        """添加白名单规则"""
        rule_id = rule.get('id', f"rule_{len(self._whitelist_rules)}_{int(time.time())}")
        rule['id'] = rule_id
        rule['created_at'] = datetime.now().isoformat()
        
        self._whitelist_rules[rule_id] = rule
        self._save_whitelist_to_file()
        
        self._logger.info(f"已添加白名单规则: {rule_id}")
    
    async def remove_whitelist_rule(self, rule_id: str) -> None:
        """移除白名单规则"""
        if rule_id in self._whitelist_rules:
            del self._whitelist_rules[rule_id]
            self._save_whitelist_to_file()
            self._logger.info(f"已移除白名单规则: {rule_id}")
        else:
            self._logger.warning(f"白名单规则不存在: {rule_id}")
    
    async def get_whitelist_rules(self) -> List[Dict[str, Any]]:
        """获取所有白名单规则"""
        return list(self._whitelist_rules.values())
    
    async def update_whitelist_rule(self, rule_id: str, updates: Dict[str, Any]) -> None:
        """更新白名单规则"""
        if rule_id in self._whitelist_rules:
            self._whitelist_rules[rule_id].update(updates)
            self._whitelist_rules[rule_id]['updated_at'] = datetime.now().isoformat()
            self._save_whitelist_to_file()
            self._logger.info(f"已更新白名单规则: {rule_id}")
        else:
            self._logger.warning(f"白名单规则不存在: {rule_id}")
    
    async def get_statistics(self) -> Dict[str, Any]:
        """获取白名单统计信息"""
        return {
            'total_rules': len(self._whitelist_rules),
            'rules_by_type': self._get_rules_by_type(),
            'file_path': self._whitelist_file
        }
    
    def _get_rules_by_type(self) -> Dict[str, int]:
        """按类型统计规则数量"""
        type_counts = defaultdict(int)
        for rule in self._whitelist_rules.values():
            if 'source_ip' in rule:
                type_counts['ip_based'] += 1
            if 'rule_name' in rule:
                type_counts['rule_based'] += 1
            if 'output_pattern' in rule:
                type_counts['pattern_based'] += 1
            if 'time_range' in rule:
                type_counts['time_based'] += 1
        return dict(type_counts)


class AdaptiveFilter(AbstractEventFilter):
    """自适应过滤器
    
    基于历史数据和机器学习的自适应过滤
    """
    
    def __init__(self, learning_window: int = 1000):
        super().__init__("adaptive_filter", priority=50)
        self._learning_window = learning_window
        self._event_history: deque = deque(maxlen=learning_window)
        self._rule_scores: Dict[str, float] = defaultdict(float)
        self._adaptation_threshold = 0.1
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def filter(self, event: StandardizedEvent) -> FilterContext:
        """自适应过滤事件"""
        start_time = time.time()
        
        try:
            # 添加事件到历史记录
            self._event_history.append(event)
            
            # 计算事件的异常分数
            anomaly_score = self._calculate_anomaly_score(event)
            
            # 根据分数决定过滤结果
            if anomaly_score > 0.8:
                result = FilterResult.BLOCK
                reason = f"自适应检测到高异常分数: {anomaly_score:.3f}"
                confidence = anomaly_score
            elif anomaly_score > 0.6:
                result = FilterResult.SUSPICIOUS
                reason = f"自适应检测到中等异常分数: {anomaly_score:.3f}"
                confidence = anomaly_score * 0.8
            else:
                result = FilterResult.PASS
                reason = f"自适应检测正常: {anomaly_score:.3f}"
                confidence = 1.0 - anomaly_score
            
            # 更新规则分数
            self._update_rule_scores(event, anomaly_score)
            
            processing_time = (time.time() - start_time) * 1000
            self._update_statistics(result, processing_time)
            
            return FilterContext(
                filter_name=self.name,
                result=result,
                confidence=confidence,
                reason=reason,
                metadata={
                    'anomaly_score': anomaly_score,
                    'rule': event.rule_name,
                    'rule_score': self._rule_scores[event.rule_name],
                    'history_size': len(self._event_history)
                },
                processing_time=processing_time,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            self._logger.error(f"自适应过滤失败: {e}")
            processing_time = (time.time() - start_time) * 1000
            return FilterContext(
                filter_name=self.name,
                result=FilterResult.PASS,
                confidence=0.0,
                reason=f"过滤器异常: {str(e)}",
                metadata={'error': True},
                processing_time=processing_time,
                timestamp=datetime.now()
            )
    
    def _calculate_anomaly_score(self, event: StandardizedEvent) -> float:
        """计算事件异常分数"""
        if len(self._event_history) < 10:
            return 0.1  # 历史数据不足时返回低分
        
        score = 0.0
        
        # 基于规则频率的异常检测
        rule_frequency = sum(1 for e in self._event_history if e.rule_name == event.rule_name)
        total_events = len(self._event_history)
        expected_frequency = rule_frequency / total_events
        
        if expected_frequency < 0.01:  # 非常罕见的规则
            score += 0.4
        elif expected_frequency < 0.05:  # 罕见规则
            score += 0.2
        
        # 基于优先级的异常检测
        if event.priority in [EventPriority.CRITICAL, EventPriority.HIGH]:
            score += 0.3
        
        # 基于时间模式的异常检测
        recent_events = [
            e for e in self._event_history 
            if (event.timestamp - e.timestamp).total_seconds() < 300  # 5分钟内
        ]
        
        if len(recent_events) > 20:  # 短时间内大量事件
            score += 0.3
        
        return min(score, 1.0)
    
    def _update_rule_scores(self, event: StandardizedEvent, anomaly_score: float):
        """更新规则分数"""
        current_score = self._rule_scores[event.rule_name]
        # 使用指数移动平均更新分数
        alpha = 0.1  # 学习率
        self._rule_scores[event.rule_name] = (1 - alpha) * current_score + alpha * anomaly_score
    
    async def configure(self, config: Dict[str, Any]) -> None:
        """配置过滤器"""
        if 'learning_window' in config:
            self._learning_window = int(config['learning_window'])
            self._event_history = deque(self._event_history, maxlen=self._learning_window)
            self._logger.info(f"学习窗口已更新为: {self._learning_window}")
        
        if 'adaptation_threshold' in config:
            self._adaptation_threshold = float(config['adaptation_threshold'])
            self._logger.info(f"适应阈值已更新为: {self._adaptation_threshold}")