#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1.4.1 OpenAI API集成功能测试
测试OpenAI客户端、提示词模板、API调用重试机制和响应解析逻辑
"""

import pytest
import asyncio
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, List, Any, Optional

# 添加项目路径
import sys
sys.path.append('/home/xzj/01_Project/B_25OS/src/backend')

from services.openai_service import (
    OpenAIService,
    AnalysisRequest,
    AnalysisResponse,
    AnalysisType,
    Priority,
    PromptTemplate,
    RetryConfig,
    retry_with_exponential_backoff,
    analyze_events,
    get_remediation_advice,
    assess_threat
)

from config.openai_config import (
    OpenAIConfig,
    ModelConfig,
    ModelType,
    AnalysisComplexity,
    load_config_from_env,
    get_template_config,
    get_analysis_config,
    calculate_cost,
    PROMPT_TEMPLATES,
    ANALYSIS_TYPE_CONFIG
)

from core.config import settings


class TestOpenAIConfig:
    """测试OpenAI配置模块"""
    
    def test_model_config_creation(self):
        """测试模型配置创建"""
        config = ModelConfig(
            model_type=ModelType.GPT_4,
            max_tokens=2000,
            temperature=0.1
        )
        
        assert config.model_type == ModelType.GPT_4
        assert config.max_tokens == 2000
        assert config.temperature == 0.1
        
        config_dict = config.to_dict()
        assert config_dict["model"] == "gpt-4"
        assert config_dict["max_tokens"] == 2000
    
    def test_openai_config_initialization(self):
        """测试OpenAI配置初始化"""
        config = OpenAIConfig()
        
        # 检查默认值
        assert config.default_model.model_type == ModelType.GPT_4O_MINI  # 更新为o4-mini
        assert config.retry.max_retries == 3
        assert config.cache.enabled == True
        assert len(config.model_configs) == 4  # simple, standard, detailed, comprehensive
        
        # 检查模型配置
        simple_config = config.get_model_config(AnalysisComplexity.SIMPLE)
        assert simple_config.model_type == ModelType.GPT_4O_MINI  # 更新为o4-mini
        
        standard_config = config.get_model_config(AnalysisComplexity.STANDARD)
        assert standard_config.model_type == ModelType.GPT_4O_MINI  # 更新为o4-mini
        
        comprehensive_config = config.get_model_config(AnalysisComplexity.COMPREHENSIVE)
        assert comprehensive_config.model_type == ModelType.GPT_4_32K
    
    def test_config_to_dict(self):
        """测试配置转换为字典"""
        config = OpenAIConfig(api_key="test-key")
        config_dict = config.to_dict()
        
        assert config_dict["api_key"] == "***"  # 应该被隐藏
        assert "default_model" in config_dict
        assert "retry" in config_dict
        assert "cache" in config_dict
    
    def test_template_config(self):
        """测试模板配置"""
        # 测试获取模板配置
        security_config = get_template_config("security_analysis")
        assert "name" in security_config
        assert "system_prompt" in security_config
        assert "user_prompt_template" in security_config
        assert "expected_fields" in security_config
        
        # 测试所有模板都存在
        for analysis_type in ["security_analysis", "threat_assessment", "incident_response",
                             "remediation_advice", "pattern_analysis", "risk_evaluation"]:
            config = get_template_config(analysis_type)
            assert config is not None
            assert len(config["expected_fields"]) > 0
    
    def test_analysis_config(self):
        """测试分析配置"""
        # 测试获取分析配置
        security_config = get_analysis_config("security_analysis")
        assert "priority" in security_config
        assert "timeout" in security_config
        assert "cache_ttl" in security_config
        assert "max_events" in security_config
        
        # 测试威胁评估配置
        threat_config = get_analysis_config("threat_assessment")
        assert threat_config["priority"] == "critical"
        assert threat_config["timeout"] == 90
    
    def test_cost_calculation(self):
        """测试成本计算"""
        # 测试GPT-4成本计算
        cost = calculate_cost("gpt-4", 1000, 500)
        expected_cost = (1000 / 1000) * 0.03 + (500 / 1000) * 0.06
        assert abs(cost - expected_cost) < 0.001
        
        # 测试GPT-3.5成本计算
        cost = calculate_cost("gpt-3.5-turbo", 2000, 1000)
        expected_cost = (2000 / 1000) * 0.0015 + (1000 / 1000) * 0.002
        assert abs(cost - expected_cost) < 0.001
        
        # 测试未知模型
        cost = calculate_cost("unknown-model", 1000, 500)
        assert cost == 0.0


class TestPromptTemplate:
    """测试提示词模板"""
    
    def test_get_template(self):
        """测试获取模板"""
        # 测试安全分析模板
        template = PromptTemplate.get_template(AnalysisType.SECURITY_ANALYSIS)
        assert "安全分析师" in template
        assert "事件数据" in template
        assert "JSON格式" in template
        
        # 测试威胁评估模板
        template = PromptTemplate.get_template(AnalysisType.THREAT_ASSESSMENT)
        assert "威胁情报" in template
        assert "威胁类型" in template
    
    def test_format_template(self):
        """测试模板格式化"""
        events = [
            {
                "event_id": "test_001",
                "rule": "Test Rule",
                "message": "Test message"
            }
        ]
        
        context = {
            "system": "test system",
            "environment": "production"
        }
        
        formatted = PromptTemplate.format_template(
            AnalysisType.SECURITY_ANALYSIS,
            events,
            context
        )
        
        assert "test_001" in formatted
        assert "Test Rule" in formatted
        assert "test system" in formatted
        assert "production" in formatted
    
    def test_all_analysis_types_have_templates(self):
        """测试所有分析类型都有对应模板"""
        for analysis_type in AnalysisType:
            template = PromptTemplate.get_template(analysis_type)
            assert template is not None
            assert len(template) > 0
            assert "事件数据" in template or "events" in template.lower()


class TestRetryMechanism:
    """测试重试机制"""
    
    @pytest.mark.asyncio
    async def test_retry_decorator_success(self):
        """测试重试装饰器成功情况"""
        call_count = 0
        
        @retry_with_exponential_backoff(RetryConfig(max_retries=3))
        async def test_function():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = await test_function()
        assert result == "success"
        assert call_count == 1
    
    @pytest.mark.asyncio
    async def test_retry_decorator_with_retries(self):
        """测试重试装饰器重试情况"""
        call_count = 0
        
        @retry_with_exponential_backoff(RetryConfig(max_retries=3, base_delay=0.01))
        async def test_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Temporary failure")
            return "success"
        
        result = await test_function()
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_retry_decorator_max_retries_exceeded(self):
        """测试重试装饰器超过最大重试次数"""
        call_count = 0
        
        @retry_with_exponential_backoff(RetryConfig(max_retries=2, base_delay=0.01))
        async def test_function():
            nonlocal call_count
            call_count += 1
            raise Exception("Persistent failure")
        
        with pytest.raises(Exception, match="Persistent failure"):
            await test_function()
        
        assert call_count == 3  # 1 initial + 2 retries


class TestAnalysisRequest:
    """测试分析请求"""
    
    def test_analysis_request_creation(self):
        """测试分析请求创建"""
        events = [
            {
                "event_id": "test_001",
                "rule": "Test Rule",
                "message": "Test message"
            }
        ]
        
        request = AnalysisRequest(
            analysis_type=AnalysisType.SECURITY_ANALYSIS,
            events=events,
            priority=Priority.HIGH
        )
        
        assert request.analysis_type == AnalysisType.SECURITY_ANALYSIS
        assert request.events == events
        assert request.priority == Priority.HIGH
        assert request.request_id is not None
        assert request.timestamp is not None
    
    def test_analysis_request_id_generation(self):
        """测试分析请求ID生成"""
        import time
        events = [{"test": "data"}]
        
        request1 = AnalysisRequest(
            analysis_type=AnalysisType.SECURITY_ANALYSIS,
            events=events
        )
        
        # 等待一小段时间确保时间戳不同
        time.sleep(0.001)
        
        request2 = AnalysisRequest(
            analysis_type=AnalysisType.SECURITY_ANALYSIS,
            events=events
        )
        
        # 相同内容应该生成不同的ID（因为时间戳不同）
        assert request1.request_id != request2.request_id
        assert "security_analysis" in request1.request_id


class TestAnalysisResponse:
    """测试分析响应"""
    
    def test_analysis_response_creation(self):
        """测试分析响应创建"""
        response = AnalysisResponse(
            request_id="test_request_001",
            analysis_type=AnalysisType.SECURITY_ANALYSIS,
            summary="Test summary",
            detailed_analysis="Test detailed analysis",
            recommendations=["Recommendation 1", "Recommendation 2"],
            risk_score=75.0,
            confidence=0.85,
            priority=Priority.HIGH,
            affected_systems=["system1", "system2"],
            attack_vectors=["vector1", "vector2"],
            mitigation_steps=["step1", "step2"],
            timestamp=datetime.now(),
            processing_time=3.5,
            token_usage={"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500}
        )
        
        assert response.request_id == "test_request_001"
        assert response.risk_score == 75.0
        assert response.confidence == 0.85
        assert len(response.recommendations) == 2
        assert len(response.affected_systems) == 2
    
    def test_analysis_response_to_dict(self):
        """测试分析响应转换为字典"""
        response = AnalysisResponse(
            request_id="test_request_001",
            analysis_type=AnalysisType.SECURITY_ANALYSIS,
            summary="Test summary",
            detailed_analysis="Test detailed analysis",
            recommendations=["Recommendation 1"],
            risk_score=75.0,
            confidence=0.85,
            priority=Priority.HIGH,
            affected_systems=["system1"],
            attack_vectors=["vector1"],
            mitigation_steps=["step1"],
            timestamp=datetime.now(),
            processing_time=3.5,
            token_usage={"total_tokens": 1500}
        )
        
        response_dict = response.to_dict()
        
        assert response_dict["request_id"] == "test_request_001"
        assert response_dict["analysis_type"] == "security_analysis"
        assert response_dict["priority"] == "HIGH"
        assert "timestamp" in response_dict
        assert isinstance(response_dict["timestamp"], str)


class TestOpenAIService:
    """测试OpenAI服务"""
    
    def test_service_initialization(self):
        """测试服务初始化"""
        with patch('services.openai_service.settings') as mock_settings:
            mock_settings.openai_api_key = "test-api-key"
            
            with patch('services.openai_service.AsyncOpenAI') as mock_openai:
                service = OpenAIService()
                
                assert service.client is not None
                assert service.retry_config.max_retries == 3
                assert service.cache == {}
                assert service.stats["total_requests"] == 0
                
                # 验证OpenAI客户端初始化
                mock_openai.assert_called_once()
    
    def test_cache_key_generation(self):
        """测试缓存键生成"""
        with patch('services.openai_service.settings') as mock_settings:
            mock_settings.openai_api_key = "test-api-key"
            
            with patch('services.openai_service.AsyncOpenAI'):
                service = OpenAIService()
                
                request = AnalysisRequest(
                    analysis_type=AnalysisType.SECURITY_ANALYSIS,
                    events=[{"test": "data"}],
                    context={"env": "test"}
                )
                
                cache_key1 = service._get_cache_key(request)
                cache_key2 = service._get_cache_key(request)
                
                # 相同请求应该生成相同的缓存键
                assert cache_key1 == cache_key2
                assert len(cache_key1) == 32  # MD5 hash length
    
    def test_response_parsing_json(self):
        """测试JSON响应解析"""
        with patch('services.openai_service.settings') as mock_settings:
            mock_settings.openai_api_key = "test-api-key"
            
            with patch('services.openai_service.AsyncOpenAI'):
                service = OpenAIService()
                
                request = AnalysisRequest(
                    analysis_type=AnalysisType.SECURITY_ANALYSIS,
                    events=[{"test": "data"}]
                )
                
                # 测试有效JSON响应
                json_response = json.dumps({
                    "summary": "Test summary",
                    "detailed_analysis": "Test analysis",
                    "risk_score": 80,
                    "confidence": 0.9,
                    "affected_systems": ["system1"],
                    "attack_vectors": ["vector1"],
                    "recommendations": ["rec1"],
                    "mitigation_steps": ["step1"]
                })
                
                parsed = service._parse_response(json_response, request)
                
                assert parsed["summary"] == "Test summary"
                assert parsed["risk_score"] == 80
                assert parsed["confidence"] == 0.9
                assert len(parsed["affected_systems"]) == 1
    
    def test_response_parsing_invalid_json(self):
        """测试无效JSON响应解析"""
        with patch('services.openai_service.settings') as mock_settings:
            mock_settings.openai_api_key = "test-api-key"
            
            with patch('services.openai_service.AsyncOpenAI'):
                service = OpenAIService()
                
                request = AnalysisRequest(
                    analysis_type=AnalysisType.SECURITY_ANALYSIS,
                    events=[{"test": "data"}]
                )
                
                # 测试无效JSON响应
                invalid_response = "This is not a JSON response"
                
                parsed = service._parse_response(invalid_response, request)
                
                # 应该返回默认结构
                assert "summary" in parsed
                assert "detailed_analysis" in parsed
                assert parsed["risk_score"] == 50.0
                assert parsed["confidence"] == 0.7
    
    @pytest.mark.asyncio
    async def test_analyze_security_events_with_cache(self):
        """测试带缓存的安全事件分析"""
        with patch('services.openai_service.settings') as mock_settings:
            mock_settings.openai_api_key = "test-api-key"
            mock_settings.openai_model = "gpt-4"
            
            with patch('services.openai_service.AsyncOpenAI'):
                service = OpenAIService()
                
                # 模拟缓存响应
                cached_response = AnalysisResponse(
                    request_id="cached_request",
                    analysis_type=AnalysisType.SECURITY_ANALYSIS,
                    summary="Cached summary",
                    detailed_analysis="Cached analysis",
                    recommendations=["Cached rec"],
                    risk_score=60.0,
                    confidence=0.8,
                    priority=Priority.MEDIUM,
                    affected_systems=[],
                    attack_vectors=[],
                    mitigation_steps=[],
                    timestamp=datetime.now(),
                    processing_time=0.1,
                    token_usage={"total_tokens": 100}
                )
                
                request = AnalysisRequest(
                    analysis_type=AnalysisType.SECURITY_ANALYSIS,
                    events=[{"test": "data"}]
                )
                
                # 添加到缓存
                cache_key = service._get_cache_key(request)
                service.cache[cache_key] = {
                    "response": cached_response,
                    "timestamp": time.time()
                }
                
                # 执行分析（应该命中缓存）
                result = await service.analyze_security_events(request)
                
                assert result.summary == "Cached summary"
                assert service.stats["cache_hits"] == 1
    
    def test_statistics(self):
        """测试统计信息"""
        with patch('services.openai_service.settings') as mock_settings:
            mock_settings.openai_api_key = "test-api-key"
            
            with patch('services.openai_service.AsyncOpenAI'):
                service = OpenAIService()
                
                # 更新统计
                service.stats["total_requests"] = 100
                service.stats["successful_requests"] = 95
                service.stats["failed_requests"] = 5
                service.stats["cache_hits"] = 20
                
                stats = service.get_statistics()
                
                assert stats["total_requests"] == 100
                assert stats["successful_requests"] == 95
                assert stats["success_rate"] == 95.0
                assert stats["cache_hit_rate"] == 20.0
    
    def test_cache_management(self):
        """测试缓存管理"""
        with patch('services.openai_service.settings') as mock_settings:
            mock_settings.openai_api_key = "test-api-key"
            
            with patch('services.openai_service.AsyncOpenAI'):
                service = OpenAIService()
                
                # 添加缓存项
                service.cache["key1"] = {"data": "value1", "timestamp": time.time()}
                service.cache["key2"] = {"data": "value2", "timestamp": time.time() - 400}  # 过期
                
                assert len(service.cache) == 2
                
                # 清理过期缓存
                service.cleanup_expired_cache()
                
                assert len(service.cache) == 1
                assert "key1" in service.cache
                assert "key2" not in service.cache
                
                # 清空所有缓存
                service.clear_cache()
                assert len(service.cache) == 0


class TestConvenienceFunctions:
    """测试便捷函数"""
    
    @pytest.mark.asyncio
    async def test_analyze_events_function(self):
        """测试analyze_events便捷函数"""
        with patch('services.openai_service.openai_service') as mock_service:
            mock_response = AnalysisResponse(
                request_id="test_request",
                analysis_type=AnalysisType.SECURITY_ANALYSIS,
                summary="Test summary",
                detailed_analysis="Test analysis",
                recommendations=["Test rec"],
                risk_score=70.0,
                confidence=0.8,
                priority=Priority.MEDIUM,
                affected_systems=[],
                attack_vectors=[],
                mitigation_steps=[],
                timestamp=datetime.now(),
                processing_time=2.0,
                token_usage={"total_tokens": 1000}
            )
            
            mock_service.analyze_security_events = AsyncMock(return_value=mock_response)
            
            events = [{"test": "event"}]
            result = await analyze_events(events, AnalysisType.SECURITY_ANALYSIS)
            
            assert result.summary == "Test summary"
            mock_service.analyze_security_events.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_remediation_advice_function(self):
        """测试get_remediation_advice便捷函数"""
        with patch('services.openai_service.openai_service') as mock_service:
            mock_response = AnalysisResponse(
                request_id="remediation_request",
                analysis_type=AnalysisType.REMEDIATION_ADVICE,
                summary="Remediation summary",
                detailed_analysis="Remediation analysis",
                recommendations=["Fix 1", "Fix 2"],
                risk_score=80.0,
                confidence=0.9,
                priority=Priority.HIGH,
                affected_systems=[],
                attack_vectors=[],
                mitigation_steps=["Step 1", "Step 2"],
                timestamp=datetime.now(),
                processing_time=3.0,
                token_usage={"total_tokens": 1500}
            )
            
            mock_service.analyze_security_events = AsyncMock(return_value=mock_response)
            
            events = [{"security": "incident"}]
            result = await get_remediation_advice(events)
            
            assert result.analysis_type == AnalysisType.REMEDIATION_ADVICE
            assert len(result.recommendations) == 2
            assert len(result.mitigation_steps) == 2
    
    @pytest.mark.asyncio
    async def test_assess_threat_function(self):
        """测试assess_threat便捷函数"""
        with patch('services.openai_service.openai_service') as mock_service:
            mock_response = AnalysisResponse(
                request_id="threat_request",
                analysis_type=AnalysisType.THREAT_ASSESSMENT,
                summary="Threat summary",
                detailed_analysis="Threat analysis",
                recommendations=["Threat rec"],
                risk_score=90.0,
                confidence=0.95,
                priority=Priority.HIGH,
                affected_systems=["critical_system"],
                attack_vectors=["advanced_threat"],
                mitigation_steps=["Immediate action"],
                timestamp=datetime.now(),
                processing_time=4.0,
                token_usage={"total_tokens": 2000}
            )
            
            mock_service.analyze_security_events = AsyncMock(return_value=mock_response)
            
            events = [{"threat": "detected"}]
            result = await assess_threat(events)
            
            assert result.analysis_type == AnalysisType.THREAT_ASSESSMENT
            assert result.risk_score == 90.0
            assert result.confidence == 0.95


class TestIntegration:
    """集成测试"""
    
    def test_prompt_template_integration(self):
        """测试提示词模板集成"""
        # 验证所有分析类型都有对应的配置
        for analysis_type in AnalysisType:
            # 检查模板
            template = PromptTemplate.get_template(analysis_type)
            assert template is not None
            
            # 检查配置
            config = get_analysis_config(analysis_type.value)
            assert config is not None
            
            # 检查模板配置
            template_config = get_template_config(analysis_type.value)
            assert template_config is not None
    
    def test_config_consistency(self):
        """测试配置一致性"""
        # 验证所有分析类型在各个配置中都存在
        analysis_types = [t.value for t in AnalysisType]
        
        for analysis_type in analysis_types:
            assert analysis_type in PROMPT_TEMPLATES
            assert analysis_type in ANALYSIS_TYPE_CONFIG
    
    def test_model_type_consistency(self):
        """测试模型类型一致性"""
        # 验证所有模型类型都有成本配置
        from config.openai_config import COST_CONFIG
        
        for model_type in ModelType:
            # 某些模型可能没有成本配置，这是正常的
            if model_type.value in COST_CONFIG:
                cost_config = COST_CONFIG[model_type.value]
                assert "input_cost_per_1k_tokens" in cost_config
                assert "output_cost_per_1k_tokens" in cost_config


if __name__ == "__main__":
    # 运行测试
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--disable-warnings"
    ])