#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
o4-mini模型配置演示脚本
展示如何使用配置的o4-mini模型进行安全分析
"""

import sys
from pathlib import Path

# 添加项目路径
sys.path.append(str(Path(__file__).parent.parent / "src" / "backend"))

from config.openai_config import (
    OpenAIConfig,
    ModelType,
    AnalysisComplexity,
    ModelConfig
)

def print_separator(title: str):
    """打印分隔符"""
    print("\n" + "=" * 60)
    print(f" {title} ")
    print("=" * 60)

def demo_o4_mini_configuration():
    """演示o4-mini模型配置"""
    print_separator("o4-mini模型配置演示")
    
    # 创建OpenAI配置实例
    config = OpenAIConfig()
    
    print("📋 当前模型配置:")
    print(f"默认模型: {config.default_model.model_type.value}")
    print(f"最大Token数: {config.default_model.max_tokens}")
    print(f"温度参数: {config.default_model.temperature}")
    
    print("\n🎯 各复杂度级别的模型配置:")
    for complexity in AnalysisComplexity:
        model_config = config.get_model_config(complexity)
        print(f"  {complexity.value:12}: {model_config.model_type.value:15} (max_tokens: {model_config.max_tokens:4}, temp: {model_config.temperature})")
    
    print("\n✨ o4-mini模型的优势:")
    print("  • 更快的响应速度")
    print("  • 更低的使用成本")
    print("  • 优秀的推理能力")
    print("  • 适合简单和标准分析任务")
    
    print("\n🔧 模型选择策略:")
    print("  • 简单分析 (simple): o4-mini - 快速基础分析")
    print("  • 标准分析 (standard): o4-mini - 日常安全分析")
    print("  • 详细分析 (detailed): GPT-4 - 复杂威胁分析")
    print("  • 全面分析 (comprehensive): GPT-4-32K - 大规模事件分析")

def demo_model_type_enum():
    """演示模型类型枚举"""
    print_separator("支持的模型类型")
    
    print("🤖 当前支持的模型:")
    for model_type in ModelType:
        print(f"  • {model_type.name:15}: {model_type.value}")
    
    print("\n🆕 新增的o4-mini模型:")
    print(f"  模型名称: {ModelType.GPT_4O_MINI.name}")
    print(f"  模型值: {ModelType.GPT_4O_MINI.value}")
    print(f"  用途: 高效的聊天和分析模型")

def demo_custom_model_config():
    """演示自定义模型配置"""
    print_separator("自定义模型配置")
    
    # 创建自定义o4-mini配置
    custom_config = ModelConfig(
        model_type=ModelType.GPT_4O_MINI,
        max_tokens=1500,
        temperature=0.2,
        top_p=0.9,
        frequency_penalty=0.1,
        presence_penalty=0.1,
        timeout=45.0
    )
    
    print("🛠️ 自定义o4-mini配置:")
    config_dict = custom_config.to_dict()
    for key, value in config_dict.items():
        print(f"  {key:18}: {value}")
    
    print("\n💡 配置说明:")
    print("  • max_tokens: 控制输出长度")
    print("  • temperature: 控制创造性 (0.0-2.0)")
    print("  • top_p: 核采样参数 (0.0-1.0)")
    print("  • frequency_penalty: 频率惩罚 (-2.0-2.0)")
    print("  • presence_penalty: 存在惩罚 (-2.0-2.0)")
    print("  • timeout: API调用超时时间")

def demo_cost_comparison():
    """演示成本对比"""
    print_separator("模型成本对比")
    
    # 模拟成本计算 (实际价格可能有变化)
    models_cost = {
        "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},  # 每1K tokens
        "gpt-3.5-turbo": {"input": 0.0015, "output": 0.002},
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-4-32k": {"input": 0.06, "output": 0.12}
    }
    
    print("💰 模型成本对比 (每1K tokens):")
    print(f"{'模型':15} {'输入成本':>10} {'输出成本':>10} {'总成本(1K+1K)':>15}")
    print("-" * 55)
    
    for model, costs in models_cost.items():
        total_cost = costs["input"] + costs["output"]
        print(f"{model:15} ${costs['input']:>9.5f} ${costs['output']:>9.4f} ${total_cost:>14.5f}")
    
    print("\n📊 o4-mini的成本优势:")
    gpt4_cost = models_cost["gpt-4"]["input"] + models_cost["gpt-4"]["output"]
    o4mini_cost = models_cost["gpt-4o-mini"]["input"] + models_cost["gpt-4o-mini"]["output"]
    savings = ((gpt4_cost - o4mini_cost) / gpt4_cost) * 100
    print(f"  相比GPT-4节省成本: {savings:.1f}%")
    print(f"  成本比例: 1:{gpt4_cost/o4mini_cost:.1f}")

def main():
    """主函数"""
    print("🚀 NeuronOS o4-mini模型配置演示")
    print("=" * 60)
    print("本演示展示了如何配置和使用o4-mini模型进行安全分析")
    
    demos = [
        ("o4-mini模型配置", demo_o4_mini_configuration),
        ("模型类型枚举", demo_model_type_enum),
        ("自定义模型配置", demo_custom_model_config),
        ("模型成本对比", demo_cost_comparison)
    ]
    
    for name, demo_func in demos:
        try:
            demo_func()
            print(f"\n✅ {name} 演示完成")
        except Exception as e:
            print(f"\n❌ {name} 演示失败: {e}")
        
        input("\n按回车键继续下一个演示...")
    
    print_separator("演示完成")
    print("🎉 o4-mini模型已成功配置为项目的默认聊天模型!")
    print("\n📝 配置总结:")
    print("  • 默认模型: gpt-4o-mini")
    print("  • 简单分析: gpt-4o-mini")
    print("  • 标准分析: gpt-4o-mini")
    print("  • 详细分析: gpt-4")
    print("  • 全面分析: gpt-4-32k")
    print("\n🔗 相关文件:")
    print("  • 配置文件: /src/backend/config/openai_config.py")
    print("  • 服务文件: /src/backend/services/openai_service.py")
    print("  • 测试文件: /tests/test_1_4_1_openai_integration.py")
    print("  • 演示文件: /examples/openai_integration_demo.py")

if __name__ == "__main__":
    main()