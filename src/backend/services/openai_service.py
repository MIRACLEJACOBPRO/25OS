#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS OpenAI API集成服务模块

实现1.4.1 OpenAI API集成的核心功能:
1. OpenAI客户端管理
2. 提示词模板系统
3. API调用重试机制
4. 响应解析逻辑
5. 安全事件分析
6. 修复建议生成

设计原则:
- 异步处理: 支持高并发API调用
- 重试机制: 处理网络异常和API限制
- 模板化: 标准化提示词管理
- 缓存优化: 减少重复API调用
- 错误处理: 完善的异常处理机制
"""

import asyncio
import json
import time
from typing import Dict, List, Any, Optional, Union, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
from functools import wraps

import openai
from openai import AsyncOpenAI
from loguru import logger

from core.config import settings


class AnalysisType(Enum):
    """分析类型枚举"""
    SECURITY_ANALYSIS = "security_analysis"          # 安全分析
    THREAT_ASSESSMENT = "threat_assessment"          # 威胁评估
    INCIDENT_RESPONSE = "incident_response"          # 事件响应
    REMEDIATION_ADVICE = "remediation_advice"        # 修复建议
    PATTERN_ANALYSIS = "pattern_analysis"            # 模式分析
    RISK_EVALUATION = "risk_evaluation"              # 风险评估


class Priority(Enum):
    """优先级枚举"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AnalysisRequest:
    """分析请求数据结构"""
    analysis_type: AnalysisType
    events: List[Dict[str, Any]]
    context: Optional[Dict[str, Any]] = None
    priority: Priority = Priority.MEDIUM
    max_tokens: int = 2000
    temperature: float = 0.1
    request_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.request_id is None:
            # 生成基于内容的请求ID，使用微秒级时间戳确保唯一性
            content_hash = hashlib.md5(
                json.dumps(self.events, sort_keys=True).encode()
            ).hexdigest()[:8]
            timestamp_us = int(time.time() * 1000000)  # 微秒级时间戳
            self.request_id = f"{self.analysis_type.value}_{content_hash}_{timestamp_us}"


@dataclass
class AnalysisResponse:
    """分析响应数据结构"""
    request_id: str
    analysis_type: AnalysisType
    summary: str
    detailed_analysis: str
    recommendations: List[str]
    risk_score: float  # 0-100
    confidence: float  # 0-1
    priority: Priority
    affected_systems: List[str]
    attack_vectors: List[str]
    mitigation_steps: List[str]
    timestamp: datetime
    processing_time: float
    token_usage: Dict[str, int]
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = asdict(self)
        result['analysis_type'] = self.analysis_type.value
        result['priority'] = self.priority.value
        result['timestamp'] = self.timestamp.isoformat()
        return result


class PromptTemplate:
    """提示词模板类"""
    
    # 安全分析模板
    SECURITY_ANALYSIS = """
你是一个专业的网络安全分析师，专门分析Falco安全事件。请分析以下安全事件数据：

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

请以JSON格式返回分析结果，包含以下字段：
- summary: 事件摘要
- detailed_analysis: 详细分析
- risk_score: 风险分数(0-100)
- confidence: 置信度(0-1)
- affected_systems: 受影响系统列表
- attack_vectors: 攻击向量列表
- recommendations: 修复建议列表
- mitigation_steps: 缓解步骤列表
"""
    
    # 威胁评估模板
    THREAT_ASSESSMENT = """
你是一个威胁情报分析专家，请对以下安全事件进行威胁评估：

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
"""
    
    # 事件响应模板
    INCIDENT_RESPONSE = """
你是一个事件响应专家，请为以下安全事件制定响应计划：

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
"""
    
    # 修复建议模板
    REMEDIATION_ADVICE = """
你是一个系统安全专家，请为以下安全事件提供详细的修复建议：

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
"""
    
    # 模式分析模板
    PATTERN_ANALYSIS = """
你是一个安全模式分析专家，请分析以下事件中的模式和趋势：

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
"""
    
    # 风险评估模板
    RISK_EVALUATION = """
你是一个风险评估专家，请对以下安全事件进行全面的风险评估：

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
"""
    
    @classmethod
    def get_template(cls, analysis_type: AnalysisType) -> str:
        """获取指定类型的模板"""
        template_map = {
            AnalysisType.SECURITY_ANALYSIS: cls.SECURITY_ANALYSIS,
            AnalysisType.THREAT_ASSESSMENT: cls.THREAT_ASSESSMENT,
            AnalysisType.INCIDENT_RESPONSE: cls.INCIDENT_RESPONSE,
            AnalysisType.REMEDIATION_ADVICE: cls.REMEDIATION_ADVICE,
            AnalysisType.PATTERN_ANALYSIS: cls.PATTERN_ANALYSIS,
            AnalysisType.RISK_EVALUATION: cls.RISK_EVALUATION,
        }
        return template_map.get(analysis_type, cls.SECURITY_ANALYSIS)
    
    @classmethod
    def format_template(cls, analysis_type: AnalysisType, events: List[Dict], context: Dict = None) -> str:
        """格式化模板"""
        template = cls.get_template(analysis_type)
        events_str = json.dumps(events, indent=2, ensure_ascii=False)
        context_str = json.dumps(context or {}, indent=2, ensure_ascii=False)
        
        return template.format(
            events=events_str,
            context=context_str
        )


class RetryConfig:
    """重试配置"""
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter


def retry_with_exponential_backoff(retry_config: RetryConfig = None):
    """指数退避重试装饰器"""
    if retry_config is None:
        retry_config = RetryConfig()
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(retry_config.max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # 如果是最后一次尝试，直接抛出异常
                    if attempt == retry_config.max_retries:
                        logger.error(f"Function {func.__name__} failed after {retry_config.max_retries} retries: {e}")
                        raise e
                    
                    # 计算延迟时间
                    delay = min(
                        retry_config.base_delay * (retry_config.exponential_base ** attempt),
                        retry_config.max_delay
                    )
                    
                    # 添加随机抖动
                    if retry_config.jitter:
                        import random
                        delay *= (0.5 + random.random() * 0.5)
                    
                    logger.warning(
                        f"Function {func.__name__} failed on attempt {attempt + 1}/{retry_config.max_retries + 1}: {e}. "
                        f"Retrying in {delay:.2f} seconds..."
                    )
                    
                    await asyncio.sleep(delay)
            
            # 这行代码理论上不会执行到
            raise last_exception
        
        return wrapper
    return decorator


class OpenAIService:
    """OpenAI API服务类"""
    
    def __init__(self):
        """初始化OpenAI服务"""
        self.client = None
        self.retry_config = RetryConfig(
            max_retries=3,
            base_delay=1.0,
            max_delay=30.0
        )
        self.cache = {}  # 简单的内存缓存
        self.cache_ttl = 300  # 缓存5分钟
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'cache_hits': 0,
            'total_tokens': 0,
            'total_cost': 0.0
        }
        
        self._initialize_client()
    
    def _initialize_client(self):
        """初始化OpenAI客户端"""
        try:
            if not settings.openai_api_key:
                raise ValueError("OpenAI API key not configured")
            
            self.client = AsyncOpenAI(
                api_key=settings.openai_api_key,
                timeout=60.0,
                max_retries=0  # 我们使用自己的重试机制
            )
            
            logger.info("OpenAI client initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            raise
    
    def _get_cache_key(self, request: AnalysisRequest) -> str:
        """生成缓存键"""
        # 基于事件内容和分析类型生成缓存键
        content = {
            'analysis_type': request.analysis_type.value,
            'events': request.events,
            'context': request.context
        }
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.md5(content_str.encode()).hexdigest()
    
    def _is_cache_valid(self, cache_entry: Dict) -> bool:
        """检查缓存是否有效"""
        return time.time() - cache_entry['timestamp'] < self.cache_ttl
    
    def _parse_response(self, response_text: str, request: AnalysisRequest) -> Dict[str, Any]:
        """解析OpenAI响应"""
        try:
            # 尝试解析JSON响应
            if response_text.strip().startswith('{'):
                parsed = json.loads(response_text)
            else:
                # 如果不是JSON格式，尝试提取JSON部分
                import re
                json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group())
                else:
                    # 如果无法解析JSON，创建默认结构
                    parsed = {
                        'summary': response_text[:200] + '...' if len(response_text) > 200 else response_text,
                        'detailed_analysis': response_text,
                        'risk_score': 50.0,
                        'confidence': 0.7,
                        'affected_systems': [],
                        'attack_vectors': [],
                        'recommendations': [],
                        'mitigation_steps': []
                    }
            
            # 确保必要字段存在
            required_fields = {
                'summary': 'Analysis completed',
                'detailed_analysis': response_text,
                'risk_score': 50.0,
                'confidence': 0.7,
                'affected_systems': [],
                'attack_vectors': [],
                'recommendations': [],
                'mitigation_steps': []
            }
            
            for field, default_value in required_fields.items():
                if field not in parsed:
                    parsed[field] = default_value
            
            # 验证数据类型
            if not isinstance(parsed['risk_score'], (int, float)):
                parsed['risk_score'] = 50.0
            if not isinstance(parsed['confidence'], (int, float)):
                parsed['confidence'] = 0.7
            
            # 确保分数在有效范围内
            parsed['risk_score'] = max(0, min(100, float(parsed['risk_score'])))
            parsed['confidence'] = max(0, min(1, float(parsed['confidence'])))
            
            return parsed
            
        except Exception as e:
            logger.error(f"Failed to parse OpenAI response: {e}")
            logger.debug(f"Response text: {response_text}")
            
            # 返回默认解析结果
            return {
                'summary': 'Failed to parse analysis result',
                'detailed_analysis': response_text,
                'risk_score': 50.0,
                'confidence': 0.5,
                'affected_systems': [],
                'attack_vectors': [],
                'recommendations': ['Please review the raw analysis output'],
                'mitigation_steps': []
            }
    
    @retry_with_exponential_backoff()
    async def _call_openai_api(
        self,
        prompt: str,
        max_tokens: int = 2000,
        temperature: float = 0.1
    ) -> Tuple[str, Dict[str, int]]:
        """调用OpenAI API"""
        try:
            response = await self.client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": "你是一个专业的网络安全分析师，专门分析和响应安全事件。请提供准确、详细和可操作的安全分析。"
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=max_tokens,
                temperature=temperature,
                response_format={"type": "text"}
            )
            
            content = response.choices[0].message.content
            token_usage = {
                'prompt_tokens': response.usage.prompt_tokens,
                'completion_tokens': response.usage.completion_tokens,
                'total_tokens': response.usage.total_tokens
            }
            
            return content, token_usage
            
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            raise
    
    async def analyze_security_events(
        self,
        request: AnalysisRequest
    ) -> AnalysisResponse:
        """分析安全事件"""
        start_time = time.time()
        
        try:
            # 更新统计
            self.stats['total_requests'] += 1
            
            # 检查缓存
            cache_key = self._get_cache_key(request)
            if cache_key in self.cache and self._is_cache_valid(self.cache[cache_key]):
                logger.info(f"Cache hit for request {request.request_id}")
                self.stats['cache_hits'] += 1
                cached_response = self.cache[cache_key]['response']
                
                # 更新处理时间
                cached_response.processing_time = time.time() - start_time
                return cached_response
            
            # 生成提示词
            prompt = PromptTemplate.format_template(
                request.analysis_type,
                request.events,
                request.context
            )
            
            logger.info(f"Analyzing {len(request.events)} events with type {request.analysis_type.value}")
            
            # 调用OpenAI API
            response_text, token_usage = await self._call_openai_api(
                prompt,
                request.max_tokens,
                request.temperature
            )
            
            # 解析响应
            parsed_response = self._parse_response(response_text, request)
            
            # 创建响应对象
            analysis_response = AnalysisResponse(
                request_id=request.request_id,
                analysis_type=request.analysis_type,
                summary=parsed_response['summary'],
                detailed_analysis=parsed_response['detailed_analysis'],
                recommendations=parsed_response['recommendations'],
                risk_score=parsed_response['risk_score'],
                confidence=parsed_response['confidence'],
                priority=request.priority,
                affected_systems=parsed_response['affected_systems'],
                attack_vectors=parsed_response['attack_vectors'],
                mitigation_steps=parsed_response['mitigation_steps'],
                timestamp=datetime.now(),
                processing_time=time.time() - start_time,
                token_usage=token_usage
            )
            
            # 缓存响应
            self.cache[cache_key] = {
                'response': analysis_response,
                'timestamp': time.time()
            }
            
            # 更新统计
            self.stats['successful_requests'] += 1
            self.stats['total_tokens'] += token_usage['total_tokens']
            
            logger.info(
                f"Analysis completed for request {request.request_id} in {analysis_response.processing_time:.2f}s. "
                f"Risk score: {analysis_response.risk_score}, Confidence: {analysis_response.confidence}"
            )
            
            return analysis_response
            
        except Exception as e:
            self.stats['failed_requests'] += 1
            logger.error(f"Failed to analyze security events for request {request.request_id}: {e}")
            raise
    
    async def batch_analyze(
        self,
        requests: List[AnalysisRequest],
        max_concurrent: int = 5
    ) -> List[AnalysisResponse]:
        """批量分析安全事件"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def analyze_with_semaphore(request):
            async with semaphore:
                return await self.analyze_security_events(request)
        
        tasks = [analyze_with_semaphore(request) for request in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常结果
        responses = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Batch analysis failed for request {i}: {result}")
                # 创建错误响应
                error_response = AnalysisResponse(
                    request_id=requests[i].request_id,
                    analysis_type=requests[i].analysis_type,
                    summary=f"Analysis failed: {str(result)}",
                    detailed_analysis=f"Error occurred during analysis: {str(result)}",
                    recommendations=["Please retry the analysis or contact support"],
                    risk_score=0.0,
                    confidence=0.0,
                    priority=requests[i].priority,
                    affected_systems=[],
                    attack_vectors=[],
                    mitigation_steps=[],
                    timestamp=datetime.now(),
                    processing_time=0.0,
                    token_usage={'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0}
                )
                responses.append(error_response)
            else:
                responses.append(result)
        
        return responses
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取服务统计信息"""
        return {
            **self.stats,
            'cache_size': len(self.cache),
            'success_rate': (
                self.stats['successful_requests'] / max(self.stats['total_requests'], 1)
            ) * 100,
            'cache_hit_rate': (
                self.stats['cache_hits'] / max(self.stats['total_requests'], 1)
            ) * 100
        }
    
    def clear_cache(self):
        """清空缓存"""
        self.cache.clear()
        logger.info("OpenAI service cache cleared")
    
    def cleanup_expired_cache(self):
        """清理过期缓存"""
        current_time = time.time()
        expired_keys = [
            key for key, entry in self.cache.items()
            if current_time - entry['timestamp'] > self.cache_ttl
        ]
        
        for key in expired_keys:
            del self.cache[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")


# 创建全局OpenAI服务实例
openai_service = OpenAIService()


# 便捷函数
async def analyze_events(
    events: List[Dict[str, Any]],
    analysis_type: AnalysisType = AnalysisType.SECURITY_ANALYSIS,
    context: Optional[Dict[str, Any]] = None,
    priority: Priority = Priority.MEDIUM
) -> AnalysisResponse:
    """便捷的事件分析函数"""
    request = AnalysisRequest(
        analysis_type=analysis_type,
        events=events,
        context=context,
        priority=priority
    )
    
    return await openai_service.analyze_security_events(request)


async def get_remediation_advice(
    events: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None
) -> AnalysisResponse:
    """获取修复建议"""
    return await analyze_events(
        events,
        AnalysisType.REMEDIATION_ADVICE,
        context,
        Priority.HIGH
    )


async def assess_threat(
    events: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None
) -> AnalysisResponse:
    """威胁评估"""
    return await analyze_events(
        events,
        AnalysisType.THREAT_ASSESSMENT,
        context,
        Priority.HIGH
    )