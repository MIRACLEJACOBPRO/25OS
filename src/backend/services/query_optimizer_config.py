#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
图查询优化器配置模块
提供查询优化器的配置管理功能
"""

from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass


class QueryOptimizationLevel(Enum):
    """查询优化级别"""
    BASIC = "basic"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


class CacheStrategy(Enum):
    """缓存策略"""
    NO_CACHE = "no_cache"
    SHORT_TERM = "short_term"
    LONG_TERM = "long_term"
    ADAPTIVE = "adaptive"


@dataclass
class QueryPerformanceConfig:
    """查询性能配置"""
    slow_query_threshold: float = 5.0  # 慢查询阈值（秒）
    max_execution_time: float = 30.0   # 最大执行时间（秒）
    max_result_size: int = 10000        # 最大结果集大小
    enable_query_logging: bool = True   # 启用查询日志


@dataclass
class CacheConfig:
    """缓存配置"""
    enable_cache: bool = True
    default_ttl: int = 300              # 默认TTL（秒）
    short_ttl: int = 60                 # 短期TTL（秒）
    long_ttl: int = 3600                # 长期TTL（秒）
    max_cache_size: int = 1000          # 最大缓存条目数
    cleanup_interval: int = 300         # 清理间隔（秒）


@dataclass
class QueryTemplateConfig:
    """查询模板配置"""
    optimization_level: QueryOptimizationLevel
    cache_strategy: CacheStrategy
    cache_ttl: int
    max_results: int
    timeout: float


# 预定义查询模板
QUERY_TEMPLATES = {
    "attack_path_basic": {
        "query": """
        MATCH path = (start:Event)-[*1..{max_depth}]->(end:Event)
        WHERE start.event_id = $start_event_id
        AND ($end_event_id IS NULL OR end.event_id = $end_event_id)
        AND start.timestamp >= datetime($start_time)
        AND start.timestamp <= datetime($end_time)
        RETURN path,
               length(path) as path_length,
               [n in nodes(path) | n.event_id] as event_sequence,
               [r in relationships(path) | type(r)] as relationship_types
        ORDER BY path_length ASC
        LIMIT {max_results}
        """,
        "description": "基础攻击路径查询",
        "parameters": {
            "start_event_id": {"type": "string", "required": True},
            "end_event_id": {"type": "string", "required": False},
            "start_time": {"type": "datetime", "required": True},
            "end_time": {"type": "datetime", "required": True},
            "max_depth": {"type": "integer", "default": 5},
            "max_results": {"type": "integer", "default": 100}
        },
        "query_type": "ATTACK_PATH",
        "optimization_level": "standard",
        "cache_strategy": "short_term"
    },
    
    "lateral_movement": {
        "query": """
        MATCH (source:Event)-[:TRIGGERED]->(process:Process)-[:EXECUTED_BY]->(user:User),
              (process)-[:ACCESSED]->(target:Host)
        WHERE source.timestamp >= datetime($start_time)
        AND source.timestamp <= datetime($end_time)
        AND source.priority IN ['HIGH', 'CRITICAL']
        AND user.name <> 'root'
        RETURN source.event_id as source_event,
               process.name as process_name,
               user.name as user_name,
               target.hostname as target_host,
               source.timestamp as event_time,
               source.priority as priority
        ORDER BY source.timestamp DESC
        LIMIT {max_results}
        """,
        "description": "横向移动检测查询",
        "parameters": {
            "start_time": {"type": "datetime", "required": True},
            "end_time": {"type": "datetime", "required": True},
            "max_results": {"type": "integer", "default": 50}
        },
        "query_type": "LATERAL_MOVEMENT",
        "optimization_level": "standard",
        "cache_strategy": "short_term"
    },
    
    "privilege_escalation": {
        "query": """
        MATCH (event:Event)-[:TRIGGERED]->(process:Process)-[:EXECUTED_BY]->(user:User)
        WHERE event.timestamp >= datetime($start_time)
        AND event.timestamp <= datetime($end_time)
        AND (
            event.rule_name CONTAINS 'privilege' OR
            event.rule_name CONTAINS 'escalation' OR
            event.rule_name CONTAINS 'sudo' OR
            process.name IN ['sudo', 'su', 'pkexec']
        )
        RETURN event.event_id as event_id,
               event.rule_name as rule_name,
               process.name as process_name,
               user.name as original_user,
               event.timestamp as event_time,
               event.priority as priority
        ORDER BY event.timestamp DESC
        LIMIT {max_results}
        """,
        "description": "权限提升检测查询",
        "parameters": {
            "start_time": {"type": "datetime", "required": True},
            "end_time": {"type": "datetime", "required": True},
            "max_results": {"type": "integer", "default": 50}
        },
        "query_type": "PRIVILEGE_ESCALATION",
        "optimization_level": "standard",
        "cache_strategy": "short_term"
    },
    
    "data_exfiltration": {
        "query": """
        MATCH (event:Event)-[:TRIGGERED]->(process:Process)-[:ACCESSED]->(file:File),
              (process)-[:CONNECTED_TO]->(network:Network)
        WHERE event.timestamp >= datetime($start_time)
        AND event.timestamp <= datetime($end_time)
        AND (
            file.path CONTAINS '/etc/' OR
            file.path CONTAINS '/var/log/' OR
            file.path CONTAINS 'sensitive'
        )
        AND network.direction = 'outbound'
        RETURN event.event_id as event_id,
               file.path as file_path,
               network.destination_ip as dest_ip,
               network.destination_port as dest_port,
               process.name as process_name,
               event.timestamp as event_time
        ORDER BY event.timestamp DESC
        LIMIT {max_results}
        """,
        "description": "数据泄露检测查询",
        "parameters": {
            "start_time": {"type": "datetime", "required": True},
            "end_time": {"type": "datetime", "required": True},
            "max_results": {"type": "integer", "default": 50}
        },
        "query_type": "DATA_EXFILTRATION",
        "optimization_level": "standard",
        "cache_strategy": "long_term"
    },
    
    "anomaly_detection": {
        "query": """
        MATCH (event:Event)
        WHERE event.timestamp >= datetime($start_time)
        AND event.timestamp <= datetime($end_time)
        WITH event.rule_name as rule, count(*) as event_count,
             collect(DISTINCT event.priority) as priorities
        WHERE event_count > $threshold
        RETURN rule,
               event_count,
               priorities
        ORDER BY event_count DESC
        LIMIT {max_results}
        """,
        "description": "异常检测查询",
        "parameters": {
            "start_time": {"type": "datetime", "required": True},
            "end_time": {"type": "datetime", "required": True},
            "threshold": {"type": "integer", "default": 10},
            "max_results": {"type": "integer", "default": 20}
        },
        "query_type": "ANOMALY_DETECTION",
        "optimization_level": "aggressive",
        "cache_strategy": "adaptive"
    },
    
    "timeline_analysis": {
        "query": """
        MATCH (event:Event)
        WHERE event.timestamp >= datetime($start_time)
        AND event.timestamp <= datetime($end_time)
        AND ($event_types IS NULL OR event.event_type IN $event_types)
        RETURN event.event_id as event_id,
               event.timestamp as timestamp,
               event.priority as priority,
               event.rule_name as rule_name,
               event.event_type as event_type
        ORDER BY event.timestamp ASC
        LIMIT {max_results}
        """,
        "description": "时间线分析查询",
        "parameters": {
            "start_time": {"type": "datetime", "required": True},
            "end_time": {"type": "datetime", "required": True},
            "event_types": {"type": "list", "required": False},
            "max_results": {"type": "integer", "default": 1000}
        },
        "query_type": "TIMELINE_ANALYSIS",
        "optimization_level": "basic",
        "cache_strategy": "short_term"
    },
    
    "correlation_analysis": {
        "query": """
        MATCH (center:Event)
        WHERE center.event_id = $event_id
        
        MATCH (related:Event)
        WHERE related.timestamp >= center.timestamp - duration({seconds: $correlation_window_seconds})
        AND related.timestamp <= center.timestamp + duration({seconds: $correlation_window_seconds})
        AND related.event_id <> center.event_id
        
        OPTIONAL MATCH path = shortestPath((center)-[*1..3]-(related))
        
        RETURN related.event_id as event_id,
               related.timestamp as timestamp,
               related.priority as priority,
               related.rule_name as rule_name,
               duration.inSeconds(related.timestamp, center.timestamp) as time_diff,
               CASE WHEN path IS NOT NULL THEN length(path) ELSE null END as relationship_distance
        ORDER BY abs(duration.inSeconds(related.timestamp, center.timestamp)) ASC
        LIMIT {max_results}
        """,
        "description": "关联分析查询",
        "parameters": {
            "event_id": {"type": "string", "required": True},
            "correlation_window_seconds": {"type": "integer", "default": 3600},
            "max_results": {"type": "integer", "default": 100}
        },
        "query_type": "CORRELATION_ANALYSIS",
        "optimization_level": "standard",
        "cache_strategy": "short_term"
    }
}

# 索引优化建议
INDEX_RECOMMENDATIONS = [
    "CREATE INDEX event_timestamp_idx IF NOT EXISTS FOR (e:Event) ON (e.timestamp)",
    "CREATE INDEX event_priority_idx IF NOT EXISTS FOR (e:Event) ON (e.priority)",
    "CREATE INDEX event_rule_idx IF NOT EXISTS FOR (e:Event) ON (e.rule_name)",
    "CREATE INDEX process_name_idx IF NOT EXISTS FOR (p:Process) ON (p.name)",
    "CREATE INDEX user_name_idx IF NOT EXISTS FOR (u:User) ON (u.name)",
    "CREATE INDEX file_path_idx IF NOT EXISTS FOR (f:File) ON (f.path)",
    "CREATE INDEX host_name_idx IF NOT EXISTS FOR (h:Host) ON (h.hostname)"
]

# 查询重写规则
QUERY_REWRITE_RULES = {
    "add_time_bounds": {
        "description": "为查询添加时间边界以提高性能",
        "pattern": r"MATCH \(event:Event\)",
        "replacement": "MATCH (event:Event) WHERE event.timestamp >= datetime($start_time) AND event.timestamp <= datetime($end_time)"
    },
    "limit_results": {
        "description": "为查询添加结果限制",
        "pattern": r"RETURN (.+)(?!.*LIMIT)",
        "replacement": r"RETURN \1 LIMIT {max_results}"
    }
}


def get_query_optimizer_config() -> Dict[str, Any]:
    """获取查询优化器配置"""
    return {
        "query_templates": QUERY_TEMPLATES,
        "cache_config": {
            "enable_cache": True,
            "default_ttl": 300,
            "short_ttl": 60,
            "long_ttl": 3600,
            "max_cache_size": 1000,
            "cleanup_interval": 300
        },
        "performance_config": {
            "slow_query_threshold": 5.0,
            "max_execution_time": 30.0,
            "max_result_size": 10000,
            "enable_query_logging": True
        },
        "optimization_levels": {
            "basic": {
                "enable_query_rewrite": False,
                "enable_result_caching": True,
                "enable_execution_plan_caching": False
            },
            "standard": {
                "enable_query_rewrite": True,
                "enable_result_caching": True,
                "enable_execution_plan_caching": True
            },
            "aggressive": {
                "enable_query_rewrite": True,
                "enable_result_caching": True,
                "enable_execution_plan_caching": True,
                "enable_query_parallelization": True
            }
        },
        "index_recommendations": INDEX_RECOMMENDATIONS,
        "query_rewrite_rules": QUERY_REWRITE_RULES
    }


def get_template_config(template_name: str) -> Optional[QueryTemplateConfig]:
    """获取指定模板的配置"""
    if template_name not in QUERY_TEMPLATES:
        return None
    
    template = QUERY_TEMPLATES[template_name]
    return QueryTemplateConfig(
        optimization_level=QueryOptimizationLevel(template.get("optimization_level", "standard")),
        cache_strategy=CacheStrategy(template.get("cache_strategy", "short_term")),
        cache_ttl=300,  # 默认TTL
        max_results=template["parameters"].get("max_results", {}).get("default", 100),
        timeout=30.0
    )


def get_cache_ttl_for_query_type(query_type: str) -> int:
    """根据查询类型获取缓存TTL"""
    cache_config = CacheConfig()
    
    # 根据查询类型返回不同的TTL
    if query_type in ["anomaly_detection", "timeline_analysis"]:
        return cache_config.short_ttl
    elif query_type in ["data_exfiltration", "privilege_escalation"]:
        return cache_config.long_ttl
    else:
        return cache_config.default_ttl


def validate_query_parameters(template_name: str, parameters: Dict[str, Any]) -> List[str]:
    """验证查询参数"""
    warnings = []
    
    if template_name not in QUERY_TEMPLATES:
        warnings.append(f"Unknown template: {template_name}")
        return warnings
    
    template = QUERY_TEMPLATES[template_name]
    param_defs = template["parameters"]
    
    # 检查必需参数
    for param_name, param_def in param_defs.items():
        if param_def.get("required", False) and param_name not in parameters:
            warnings.append(f"Missing required parameter: {param_name}")
    
    # 检查参数值范围
    if "max_results" in parameters:
        max_results = parameters["max_results"]
        if max_results > 10000:
            warnings.append("max_results exceeds recommended limit (10000)")
    
    if "max_depth" in parameters:
        max_depth = parameters["max_depth"]
        if max_depth > 6:
            warnings.append("路径深度过大可能影响查询性能")
    
    return warnings


def update_config(new_config: Dict[str, Any]) -> None:
    """更新配置"""
    global QUERY_TEMPLATES
    
    if "query_templates" in new_config:
        QUERY_TEMPLATES.update(new_config["query_templates"])