#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenAI配置模块
管理OpenAI API集成的配置参数、模板设置和性能优化配置
"""

import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import json


class ModelType(Enum):
    """支持的模型类型"""
    GPT_4 = "gpt-4"
    GPT_4_TURBO = "gpt-4-turbo-preview"
    GPT_4_32K = "gpt-4-32k"
    GPT_4O_MINI = "gpt-4o-mini"  # 新增o4-mini模型
    GPT_3_5_TURBO = "gpt-3.5-turbo"
    GPT_3_5_TURBO_16K = "gpt-3.5-turbo-16k"


class AnalysisComplexity(Enum):
    """分析复杂度级别"""
    SIMPLE = "simple"      # 简单分析，快速响应
    STANDARD = "standard"  # 标准分析，平衡质量和速度
    DETAILED = "detailed"  # 详细分析，高质量输出
    COMPREHENSIVE = "comprehensive"  # 全面分析，最高质量


@dataclass
class ModelConfig:
    """模型配置"""
    model_type: ModelType = ModelType.GPT_4O_MINI  # 默认使用o4-mini模型
    max_tokens: int = 2000
    temperature: float = 0.1
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    timeout: float = 60.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model_type.value,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "frequency_penalty": self.frequency_penalty,
            "presence_penalty": self.presence_penalty,
            "timeout": self.timeout
        }


@dataclass
class RetryConfig:
    """重试配置"""
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    retry_on_timeout: bool = True
    retry_on_rate_limit: bool = True
    retry_on_server_error: bool = True


@dataclass
class CacheConfig:
    """缓存配置"""
    enabled: bool = True
    ttl_seconds: int = 300  # 5分钟
    max_size: int = 1000
    cleanup_interval: int = 60  # 1分钟
    cache_by_content: bool = True
    cache_by_analysis_type: bool = True


@dataclass
class RateLimitConfig:
    """速率限制配置"""
    requests_per_minute: int = 60
    tokens_per_minute: int = 90000
    concurrent_requests: int = 10
    burst_allowance: int = 5


@dataclass
class SecurityConfig:
    """安全配置"""
    api_key_rotation_days: int = 90
    log_requests: bool = True
    log_responses: bool = False  # 不记录响应内容以保护隐私
    mask_sensitive_data: bool = True
    allowed_analysis_types: List[str] = field(default_factory=lambda: [
        "security_analysis",
        "threat_assessment", 
        "incident_response",
        "remediation_advice",
        "pattern_analysis",
        "risk_evaluation"
    ])


@dataclass
class PerformanceConfig:
    """性能配置"""
    batch_size: int = 5
    max_concurrent_requests: int = 10
    request_timeout: float = 60.0
    connection_timeout: float = 10.0
    read_timeout: float = 60.0
    enable_streaming: bool = False
    chunk_size: int = 1024


@dataclass
class MonitoringConfig:
    """监控配置"""
    enable_metrics: bool = True
    metrics_interval: int = 60  # 秒
    alert_on_high_error_rate: bool = True
    error_rate_threshold: float = 0.1  # 10%
    alert_on_high_latency: bool = True
    latency_threshold: float = 30.0  # 秒
    alert_on_quota_usage: bool = True
    quota_usage_threshold: float = 0.8  # 80%


@dataclass
class OpenAIConfig:
    """OpenAI完整配置"""
    api_key: Optional[str] = None
    organization: Optional[str] = None
    base_url: Optional[str] = None
    
    # 模型配置
    default_model: ModelConfig = field(default_factory=ModelConfig)
    model_configs: Dict[str, ModelConfig] = field(default_factory=dict)
    
    # 功能配置
    retry: RetryConfig = field(default_factory=RetryConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    
    def __post_init__(self):
        """初始化后处理"""
        # 设置默认模型配置
        if not self.model_configs:
            self.model_configs = {
                "simple": ModelConfig(
                    model_type=ModelType.GPT_4O_MINI,  # 使用o4-mini进行简单分析
                    max_tokens=1000,
                    temperature=0.1
                ),
                "standard": ModelConfig(
                    model_type=ModelType.GPT_4O_MINI,  # 使用o4-mini进行标准分析
                    max_tokens=2000,
                    temperature=0.1
                ),
                "detailed": ModelConfig(
                    model_type=ModelType.GPT_4,  # 详细分析仍使用GPT-4
                    max_tokens=3000,
                    temperature=0.05
                ),
                "comprehensive": ModelConfig(
                    model_type=ModelType.GPT_4_32K,  # 全面分析使用GPT-4-32K
                    max_tokens=4000,
                    temperature=0.05
                )
            }
    
    def get_model_config(self, complexity: AnalysisComplexity) -> ModelConfig:
        """根据复杂度获取模型配置"""
        return self.model_configs.get(complexity.value, self.default_model)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "api_key": "***" if self.api_key else None,  # 隐藏API密钥
            "organization": self.organization,
            "base_url": self.base_url,
            "default_model": self.default_model.to_dict(),
            "model_configs": {k: v.to_dict() for k, v in self.model_configs.items()},
            "retry": self.retry.__dict__,
            "cache": self.cache.__dict__,
            "rate_limit": self.rate_limit.__dict__,
            "security": self.security.__dict__,
            "performance": self.performance.__dict__,
            "monitoring": self.monitoring.__dict__
        }


# 提示词模板配置
PROMPT_TEMPLATES = {
    "security_analysis": {
        "name": "安全分析模板",
        "description": "用于分析安全事件的详细模板",
        "system_prompt": "你是一个专业的网络安全分析师，专门分析Falco安全事件。请提供准确、详细和可操作的安全分析。",
        "user_prompt_template": """
请分析以下安全事件数据：

事件数据：
{events}

上下文信息：
{context}

请提供以下分析：
1. 事件摘要：简要描述发生了什么
2. 详细分析：深入分析事件的技术细节和潜在影响
3. 风险评估：评估风险等级(0-100分)和置信度(0-1)
4. 受影响系统：列出可能受影响的系统和组件
5. 攻击向量：识别可能的攻击路径和方法
6. 修复建议：提供具体的修复和缓解措施

请以JSON格式返回分析结果。
""",
        "expected_fields": [
            "summary", "detailed_analysis", "risk_score", "confidence",
            "affected_systems", "attack_vectors", "recommendations", "mitigation_steps"
        ],
        "complexity": "standard"
    },
    
    "threat_assessment": {
        "name": "威胁评估模板",
        "description": "用于评估安全威胁的模板",
        "system_prompt": "你是一个威胁情报分析专家，专门评估安全威胁的严重程度和影响范围。",
        "user_prompt_template": """
请对以下安全事件进行威胁评估：

事件数据：
{events}

上下文信息：
{context}

请重点分析：
1. 威胁类型和严重程度
2. 攻击者可能的意图和能力
3. 攻击的复杂度和持续性
4. 对业务的潜在影响
5. 类似攻击的历史模式
6. 预防和检测建议

请以JSON格式返回评估结果。
""",
        "expected_fields": [
            "threat_type", "severity", "attacker_profile", "business_impact",
            "attack_complexity", "persistence", "historical_patterns", "prevention_advice"
        ],
        "complexity": "detailed"
    },
    
    "incident_response": {
        "name": "事件响应模板",
        "description": "用于制定事件响应计划的模板",
        "system_prompt": "你是一个事件响应专家，专门制定和执行安全事件响应计划。",
        "user_prompt_template": """
请为以下安全事件制定响应计划：

事件数据：
{events}

上下文信息：
{context}

请提供：
1. 立即响应措施
2. 调查步骤
3. 遏制策略
4. 恢复计划
5. 后续监控
6. 经验教训

请以JSON格式返回响应计划。
""",
        "expected_fields": [
            "immediate_actions", "investigation_steps", "containment_strategy",
            "recovery_plan", "monitoring_requirements", "lessons_learned"
        ],
        "complexity": "comprehensive"
    },
    
    "remediation_advice": {
        "name": "修复建议模板",
        "description": "用于提供系统修复建议的模板",
        "system_prompt": "你是一个系统安全专家，专门提供详细的安全修复建议和最佳实践。",
        "user_prompt_template": """
请为以下安全事件提供详细的修复建议：

事件数据：
{events}

上下文信息：
{context}

请提供：
1. 紧急修复措施
2. 长期安全改进
3. 配置建议
4. 监控增强
5. 用户培训需求
6. 合规性考虑

请以JSON格式返回修复建议，包含具体的命令和配置。
""",
        "expected_fields": [
            "emergency_fixes", "long_term_improvements", "configuration_changes",
            "monitoring_enhancements", "training_requirements", "compliance_considerations"
        ],
        "complexity": "detailed"
    },
    
    "pattern_analysis": {
        "name": "模式分析模板",
        "description": "用于分析安全事件模式和趋势的模板",
        "system_prompt": "你是一个安全模式分析专家，专门识别和分析安全事件中的模式、趋势和异常。",
        "user_prompt_template": """
请分析以下事件中的模式和趋势：

事件数据：
{events}

上下文信息：
{context}

请分析：
1. 事件模式和趋势
2. 异常行为识别
3. 关联性分析
4. 预测性洞察
5. 基线偏差
6. 改进建议

请以JSON格式返回分析结果。
""",
        "expected_fields": [
            "patterns", "trends", "anomalies", "correlations",
            "predictions", "baseline_deviations", "improvement_suggestions"
        ],
        "complexity": "comprehensive"
    },
    
    "risk_evaluation": {
        "name": "风险评估模板",
        "description": "用于全面风险评估的模板",
        "system_prompt": "你是一个风险评估专家，专门进行全面的安全风险评估和影响分析。",
        "user_prompt_template": """
请对以下安全事件进行全面的风险评估：

事件数据：
{events}

上下文信息：
{context}

请评估：
1. 技术风险
2. 业务风险
3. 合规风险
4. 声誉风险
5. 财务影响
6. 风险缓解优先级

请以JSON格式返回风险评估结果。
""",
        "expected_fields": [
            "technical_risks", "business_risks", "compliance_risks",
            "reputation_risks", "financial_impact", "mitigation_priorities"
        ],
        "complexity": "comprehensive"
    }
}


# 分析类型配置
ANALYSIS_TYPE_CONFIG = {
    "security_analysis": {
        "priority": "high",
        "timeout": 60,
        "cache_ttl": 300,
        "max_events": 50,
        "complexity": "standard"
    },
    "threat_assessment": {
        "priority": "critical",
        "timeout": 90,
        "cache_ttl": 600,
        "max_events": 30,
        "complexity": "detailed"
    },
    "incident_response": {
        "priority": "critical",
        "timeout": 120,
        "cache_ttl": 180,
        "max_events": 20,
        "complexity": "comprehensive"
    },
    "remediation_advice": {
        "priority": "high",
        "timeout": 90,
        "cache_ttl": 900,
        "max_events": 40,
        "complexity": "detailed"
    },
    "pattern_analysis": {
        "priority": "medium",
        "timeout": 120,
        "cache_ttl": 1800,
        "max_events": 100,
        "complexity": "comprehensive"
    },
    "risk_evaluation": {
        "priority": "high",
        "timeout": 90,
        "cache_ttl": 600,
        "max_events": 50,
        "complexity": "comprehensive"
    }
}


# 成本配置（基于OpenAI定价）
COST_CONFIG = {
    "gpt-4": {
        "input_cost_per_1k_tokens": 0.03,
        "output_cost_per_1k_tokens": 0.06
    },
    "gpt-4-turbo-preview": {
        "input_cost_per_1k_tokens": 0.01,
        "output_cost_per_1k_tokens": 0.03
    },
    "gpt-4-32k": {
        "input_cost_per_1k_tokens": 0.06,
        "output_cost_per_1k_tokens": 0.12
    },
    "gpt-3.5-turbo": {
        "input_cost_per_1k_tokens": 0.0015,
        "output_cost_per_1k_tokens": 0.002
    },
    "gpt-3.5-turbo-16k": {
        "input_cost_per_1k_tokens": 0.003,
        "output_cost_per_1k_tokens": 0.004
    }
}


def load_config_from_env() -> OpenAIConfig:
    """从环境变量加载配置"""
    config = OpenAIConfig()
    
    # 基础配置
    config.api_key = os.getenv("OPENAI_API_KEY")
    config.organization = os.getenv("OPENAI_ORGANIZATION")
    config.base_url = os.getenv("OPENAI_BASE_URL")
    
    # 模型配置
    model_name = os.getenv("OPENAI_MODEL", "gpt-4")
    max_tokens = int(os.getenv("OPENAI_MAX_TOKENS", "2000"))
    temperature = float(os.getenv("OPENAI_TEMPERATURE", "0.1"))
    
    config.default_model = ModelConfig(
        model_type=ModelType(model_name),
        max_tokens=max_tokens,
        temperature=temperature
    )
    
    # 重试配置
    config.retry.max_retries = int(os.getenv("OPENAI_MAX_RETRIES", "3"))
    config.retry.base_delay = float(os.getenv("OPENAI_BASE_DELAY", "1.0"))
    config.retry.max_delay = float(os.getenv("OPENAI_MAX_DELAY", "60.0"))
    
    # 缓存配置
    config.cache.enabled = os.getenv("OPENAI_CACHE_ENABLED", "true").lower() == "true"
    config.cache.ttl_seconds = int(os.getenv("OPENAI_CACHE_TTL", "300"))
    config.cache.max_size = int(os.getenv("OPENAI_CACHE_MAX_SIZE", "1000"))
    
    # 性能配置
    config.performance.max_concurrent_requests = int(os.getenv("OPENAI_MAX_CONCURRENT", "10"))
    config.performance.request_timeout = float(os.getenv("OPENAI_REQUEST_TIMEOUT", "60.0"))
    
    return config


def load_config_from_file(file_path: str) -> OpenAIConfig:
    """从文件加载配置"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 这里可以添加更复杂的配置解析逻辑
        config = OpenAIConfig()
        
        # 基础配置
        if 'api_key' in data:
            config.api_key = data['api_key']
        if 'organization' in data:
            config.organization = data['organization']
        
        # 模型配置
        if 'default_model' in data:
            model_data = data['default_model']
            config.default_model = ModelConfig(
                model_type=ModelType(model_data.get('model_type', 'gpt-4')),
                max_tokens=model_data.get('max_tokens', 2000),
                temperature=model_data.get('temperature', 0.1)
            )
        
        return config
        
    except Exception as e:
        raise ValueError(f"Failed to load config from file {file_path}: {e}")


def get_template_config(analysis_type: str) -> Dict[str, Any]:
    """获取模板配置"""
    return PROMPT_TEMPLATES.get(analysis_type, PROMPT_TEMPLATES["security_analysis"])


def get_analysis_config(analysis_type: str) -> Dict[str, Any]:
    """获取分析类型配置"""
    return ANALYSIS_TYPE_CONFIG.get(analysis_type, ANALYSIS_TYPE_CONFIG["security_analysis"])


def calculate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """计算API调用成本"""
    if model not in COST_CONFIG:
        return 0.0
    
    config = COST_CONFIG[model]
    input_cost = (prompt_tokens / 1000) * config["input_cost_per_1k_tokens"]
    output_cost = (completion_tokens / 1000) * config["output_cost_per_1k_tokens"]
    
    return input_cost + output_cost


# 创建默认配置实例
default_config = load_config_from_env()