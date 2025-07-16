#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
图查询优化器配置模块
定义查询模板配置、性能参数和优化策略
"""

from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum


class QueryOptimizationLevel(Enum):
    """查询优化级别"""
    BASIC = "basic"          # 基础优化
    STANDARD = "standard"    # 标准优化
    AGGRESSIVE = "aggressive" # 激进优化


class CacheStrategy(Enum):
    """缓存策略"""
    NO_CACHE = "no_cache"           # 不使用缓存
    TIME_BASED = "time_based"       # 基于时间的缓存
    RESULT_BASED = "result_based"   # 基于结果的缓存
    ADAPTIVE = "adaptive"           # 自适应缓存


@dataclass
class QueryPerformanceConfig:
    """查询性能配置"""
    # 执行时间限制
    max_execution_time_seconds: float = 30.0
    slow_query_threshold_seconds: float = 5.0
    
    # 结果集限制
    default_max_results: int = 1000
    absolute_max_results: int = 10000
    
    # 路径查询限制
    max_path_depth: int = 5
    max_path_results: int = 100
    
    # 并发控制
    max_concurrent_queries: int = 10
    query_timeout_seconds: float = 60.0
    
    # 内存控制
    max_memory_usage_mb: int = 512
    result_streaming_threshold: int = 5000


@dataclass
class CacheConfig:
    """缓存配置"""
    # 缓存策略
    strategy: CacheStrategy = CacheStrategy.TIME_BASED
    
    # 缓存时间设置(秒)
    default_ttl: int = 300
    short_ttl: int = 60
    medium_ttl: int = 300
    long_ttl: int = 1800
    
    # 缓存大小限制
    max_cache_entries: int = 1000
    max_cache_memory_mb: int = 256
    
    # 缓存清理策略
    cleanup_interval_seconds: int = 300
    cleanup_threshold_ratio: float = 0.8
    
    # 缓存键配置
    include_timestamp_in_key: bool = False
    hash_large_parameters: bool = True


@dataclass
class QueryTemplateConfig:
    """查询模板配置"""
    # 模板性能配置
    performance_hints: List[str]
    cache_ttl: int
    max_results: int
    optimization_level: QueryOptimizationLevel
    
    # 查询特定配置
    enable_result_streaming: bool = False
    enable_parallel_execution: bool = False
    priority: int = 1  # 1-10, 10为最高优先级


class QueryOptimizerConfig:
    """图查询优化器配置类"""
    
    def __init__(self):
        self.performance = QueryPerformanceConfig()
        self.cache = CacheConfig()
        self.optimization_level = QueryOptimizationLevel.STANDARD
        
        # 查询模板配置
        self.template_configs = self._initialize_template_configs()
        
        # 索引优化建议
        self.index_recommendations = self._get_index_recommendations()
        
        # 查询重写规则
        self.rewrite_rules = self._get_rewrite_rules()
    
    def _initialize_template_configs(self) -> Dict[str, QueryTemplateConfig]:
        """初始化查询模板配置"""
        configs = {}
        
        # 攻击路径查询配置
        configs["attack_path_basic"] = QueryTemplateConfig(
            performance_hints=[
                "使用时间索引过滤减少扫描范围",
                "限制路径深度避免指数级增长",
                "优先查询高优先级事件",
                "使用LIMIT子句控制结果集大小"
            ],
            cache_ttl=600,  # 10分钟缓存
            max_results=100,
            optimization_level=QueryOptimizationLevel.STANDARD,
            enable_result_streaming=True,
            priority=8
        )
        
        # 横向移动检测配置
        configs["lateral_movement"] = QueryTemplateConfig(
            performance_hints=[
                "使用主机索引优化跨主机查询",
                "通过网络关系减少笛卡尔积",
                "使用EXISTS子查询优化存在性检查"
            ],
            cache_ttl=300,  # 5分钟缓存
            max_results=50,
            optimization_level=QueryOptimizationLevel.AGGRESSIVE,
            enable_parallel_execution=True,
            priority=9
        )
        
        # 权限提升检测配置
        configs["privilege_escalation"] = QueryTemplateConfig(
            performance_hints=[
                "使用用户ID索引优化权限比较",
                "通过进程关系减少扫描",
                "使用数值比较优化UID检查"
            ],
            cache_ttl=300,
            max_results=50,
            optimization_level=QueryOptimizationLevel.STANDARD,
            priority=9
        )
        
        # 数据泄露检测配置
        configs["data_exfiltration"] = QueryTemplateConfig(
            performance_hints=[
                "使用文件路径正则表达式索引",
                "通过IP地址范围过滤减少网络节点扫描",
                "使用聚合函数优化文件计数"
            ],
            cache_ttl=600,
            max_results=30,
            optimization_level=QueryOptimizationLevel.AGGRESSIVE,
            enable_result_streaming=True,
            priority=8
        )
        
        # 异常检测配置
        configs["anomaly_detection"] = QueryTemplateConfig(
            performance_hints=[
                "使用时间分区优化聚合查询",
                "通过规则名称索引加速分组",
                "使用HAVING子句过滤聚合结果"
            ],
            cache_ttl=180,  # 3分钟缓存
            max_results=50,
            optimization_level=QueryOptimizationLevel.STANDARD,
            priority=7
        )
        
        # 时间线分析配置
        configs["timeline_analysis"] = QueryTemplateConfig(
            performance_hints=[
                "使用时间戳索引优化范围查询",
                "通过主机过滤减少结果集",
                "使用ORDER BY优化时间排序"
            ],
            cache_ttl=120,  # 2分钟缓存
            max_results=500,
            optimization_level=QueryOptimizationLevel.BASIC,
            enable_result_streaming=True,
            priority=6
        )
        
        # 关联分析配置
        configs["correlation_analysis"] = QueryTemplateConfig(
            performance_hints=[
                "使用事件ID索引定位中心事件",
                "通过时间窗口限制关联范围",
                "使用shortestPath优化路径查找"
            ],
            cache_ttl=300,
            max_results=100,
            optimization_level=QueryOptimizationLevel.STANDARD,
            priority=7
        )
        
        return configs
    
    def _get_index_recommendations(self) -> List[Dict[str, Any]]:
        """获取索引优化建议"""
        return [
            {
                "index_name": "event_timestamp_idx",
                "node_label": "Event",
                "properties": ["timestamp"],
                "type": "range",
                "description": "优化时间范围查询性能",
                "priority": 10
            },
            {
                "index_name": "event_priority_idx",
                "node_label": "Event",
                "properties": ["priority"],
                "type": "lookup",
                "description": "优化优先级过滤查询",
                "priority": 9
            },
            {
                "index_name": "event_rule_name_idx",
                "node_label": "Event",
                "properties": ["rule_name"],
                "type": "lookup",
                "description": "优化规则名称分组和过滤",
                "priority": 8
            },
            {
                "index_name": "process_host_idx",
                "node_label": "Process",
                "properties": ["host"],
                "type": "lookup",
                "description": "优化主机相关查询",
                "priority": 8
            },
            {
                "index_name": "user_uid_idx",
                "node_label": "User",
                "properties": ["uid"],
                "type": "range",
                "description": "优化用户ID比较查询",
                "priority": 7
            },
            {
                "index_name": "file_path_idx",
                "node_label": "File",
                "properties": ["path"],
                "type": "text",
                "description": "优化文件路径模式匹配",
                "priority": 7
            },
            {
                "index_name": "network_remote_ip_idx",
                "node_label": "Network",
                "properties": ["remote_ip"],
                "type": "lookup",
                "description": "优化网络IP地址查询",
                "priority": 6
            },
            {
                "index_name": "event_composite_idx",
                "node_label": "Event",
                "properties": ["timestamp", "priority"],
                "type": "composite",
                "description": "优化时间和优先级组合查询",
                "priority": 9
            }
        ]
    
    def _get_rewrite_rules(self) -> List[Dict[str, Any]]:
        """获取查询重写规则"""
        return [
            {
                "rule_name": "time_range_optimization",
                "description": "优化时间范围查询",
                "pattern": "WHERE.*timestamp.*>=.*AND.*timestamp.*<=",
                "suggestion": "使用时间索引，考虑分区查询",
                "priority": 10
            },
            {
                "rule_name": "path_length_limitation",
                "description": "限制路径查询长度",
                "pattern": "MATCH.*\\[\\*\\]",
                "suggestion": "使用具体的路径长度范围，如[*1..5]",
                "priority": 9
            },
            {
                "rule_name": "exists_vs_optional_match",
                "description": "使用EXISTS替代OPTIONAL MATCH",
                "pattern": "OPTIONAL MATCH.*WHERE.*IS NOT NULL",
                "suggestion": "考虑使用EXISTS()函数替代",
                "priority": 8
            },
            {
                "rule_name": "limit_early_filtering",
                "description": "早期过滤优化",
                "pattern": "MATCH.*WHERE.*LIMIT",
                "suggestion": "将过滤条件尽可能前置",
                "priority": 7
            },
            {
                "rule_name": "aggregation_optimization",
                "description": "聚合查询优化",
                "pattern": "WITH.*count\\(.*\\).*WHERE.*count",
                "suggestion": "使用HAVING子句替代WHERE过滤聚合结果",
                "priority": 8
            }
        ]
    
    def get_template_config(self, template_name: str) -> QueryTemplateConfig:
        """获取查询模板配置"""
        return self.template_configs.get(template_name, QueryTemplateConfig(
            performance_hints=[],
            cache_ttl=self.cache.default_ttl,
            max_results=self.performance.default_max_results,
            optimization_level=self.optimization_level
        ))
    
    def update_template_config(self, template_name: str, config: QueryTemplateConfig):
        """更新查询模板配置"""
        self.template_configs[template_name] = config
    
    def get_cache_ttl_for_query_type(self, query_type: str) -> int:
        """根据查询类型获取缓存TTL"""
        # 实时性要求高的查询使用较短的缓存时间
        real_time_queries = ["anomaly_detection", "timeline_analysis"]
        if query_type in real_time_queries:
            return self.cache.short_ttl
        
        # 分析类查询可以使用较长的缓存时间
        analytical_queries = ["attack_path_basic", "data_exfiltration"]
        if query_type in analytical_queries:
            return self.cache.long_ttl
        
        return self.cache.default_ttl
    
    def should_use_cache(self, template_name: str, result_count: int) -> bool:
        """判断是否应该使用缓存"""
        if self.cache.strategy == CacheStrategy.NO_CACHE:
            return False
        
        template_config = self.get_template_config(template_name)
        
        # 高优先级查询总是缓存
        if template_config.priority >= 8:
            return True
        
        # 大结果集查询缓存
        if result_count > 100:
            return True
        
        # 基于策略决定
        if self.cache.strategy == CacheStrategy.ADAPTIVE:
            # 自适应策略：根据查询频率和结果大小决定
            return result_count > 10 or template_config.priority >= 6
        
        return True
    
    def get_optimization_hints(self, template_name: str) -> List[str]:
        """获取查询优化提示"""
        template_config = self.get_template_config(template_name)
        hints = template_config.performance_hints.copy()
        
        # 添加通用优化提示
        general_hints = [
            "使用参数化查询避免查询计划缓存失效",
            "考虑使用EXPLAIN分析查询执行计划",
            "监控查询执行时间和资源使用"
        ]
        
        if template_config.optimization_level == QueryOptimizationLevel.AGGRESSIVE:
            hints.extend(general_hints)
        
        return hints
    
    def validate_query_parameters(self, template_name: str, parameters: Dict[str, Any]) -> List[str]:
        """验证查询参数"""
        warnings = []
        template_config = self.get_template_config(template_name)
        
        # 检查结果集大小限制
        max_results = parameters.get("max_results", template_config.max_results)
        if max_results > self.performance.absolute_max_results:
            warnings.append(f"max_results ({max_results}) 超过绝对限制 ({self.performance.absolute_max_results})")
        
        # 检查时间范围
        start_time = parameters.get("start_time")
        end_time = parameters.get("end_time")
        if start_time and end_time:
            try:
                from datetime import datetime
                start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                time_diff = (end_dt - start_dt).total_seconds()
                
                # 警告过长的时间范围
                if time_diff > 7 * 24 * 3600:  # 超过7天
                    warnings.append("时间范围过长可能影响查询性能")
                    
            except Exception:
                warnings.append("时间格式无效")
        
        # 检查路径深度
        if "max_depth" in parameters:
            max_depth = parameters["max_depth"]
            if max_depth > self.performance.max_path_depth:
                warnings.append(f"路径深度 ({max_depth}) 超过建议值 ({self.performance.max_path_depth})")
        
        return warnings


# 全局配置实例
query_optimizer_config = QueryOptimizerConfig()


# 配置更新函数
def update_performance_config(**kwargs):
    """更新性能配置"""
    for key, value in kwargs.items():
        if hasattr(query_optimizer_config.performance, key):
            setattr(query_optimizer_config.performance, key, value)


def update_cache_config(**kwargs):
    """更新缓存配置"""
    for key, value in kwargs.items():
        if hasattr(query_optimizer_config.cache, key):
            setattr(query_optimizer_config.cache, key, value)


def get_config_summary() -> Dict[str, Any]:
    """获取配置摘要"""
    return {
        "optimization_level": query_optimizer_config.optimization_level.value,
        "performance": {
            "max_execution_time": query_optimizer_config.performance.max_execution_time_seconds,
            "slow_query_threshold": query_optimizer_config.performance.slow_query_threshold_seconds,
            "default_max_results": query_optimizer_config.performance.default_max_results,
            "max_path_depth": query_optimizer_config.performance.max_path_depth
        },
        "cache": {
            "strategy": query_optimizer_config.cache.strategy.value,
            "default_ttl": query_optimizer_config.cache.default_ttl,
            "max_entries": query_optimizer_config.cache.max_cache_entries
        },
        "templates_count": len(query_optimizer_config.template_configs),
        "index_recommendations_count": len(query_optimizer_config.index_recommendations)
    }


if __name__ == "__main__":
    # 测试配置
    import json
    
    print("Query Optimizer Configuration Summary:")
    print(json.dumps(get_config_summary(), indent=2))
    
    print("\nAvailable Templates:")
    for name, config in query_optimizer_config.template_configs.items():
        print(f"  {name}: {config.optimization_level.value} (TTL: {config.cache_ttl}s)")
    
    print("\nIndex Recommendations:")
    for idx in query_optimizer_config.index_recommendations:
        print(f"  {idx['index_name']}: {idx['description']} (Priority: {idx['priority']})")