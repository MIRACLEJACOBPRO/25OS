#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenAI配置检查和修复工具
帮助诊断和解决OpenAI API密钥配置问题
"""

import os
import sys
from pathlib import Path

# 添加项目路径
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root / "src" / "backend"))

def check_environment_variable():
    """检查环境变量中的API密钥"""
    env_key = os.getenv('OPENAI_API_KEY')
    print("\n=== 环境变量检查 ===")
    if env_key:
        print(f"✓ 环境变量 OPENAI_API_KEY 已设置")
        if env_key.startswith('sk-test-') or 'demo' in env_key.lower():
            print(f"⚠️  警告: 检测到测试密钥: {env_key[:15]}...")
            print("   这可能会覆盖.env文件中的真实密钥")
            return False
        elif env_key.startswith('sk-placeholder-'):
            print(f"⚠️  警告: 检测到占位符密钥: {env_key[:20]}...")
            return False
        else:
            print(f"✓ 环境变量密钥格式正确: {env_key[:15]}...")
            return True
    else:
        print("✓ 环境变量 OPENAI_API_KEY 未设置 (将从.env文件读取)")
        return None

def check_env_files():
    """检查.env文件"""
    print("\n=== .env文件检查 ===")
    
    env_files = [
        project_root / ".env",
        project_root / "src" / "backend" / ".env"
    ]
    
    results = {}
    
    for env_file in env_files:
        print(f"\n检查文件: {env_file}")
        if env_file.exists():
            print("✓ 文件存在")
            try:
                with open(env_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # 查找OPENAI_API_KEY行
                for line_num, line in enumerate(content.split('\n'), 1):
                    if line.strip().startswith('OPENAI_API_KEY='):
                        key_value = line.split('=', 1)[1].strip()
                        print(f"✓ 第{line_num}行找到API密钥配置")
                        
                        if key_value.startswith('sk-test-') or 'demo' in key_value.lower():
                            print(f"⚠️  警告: 测试密钥 {key_value[:15]}...")
                            results[str(env_file)] = 'test'
                        elif key_value.startswith('sk-placeholder-'):
                            print(f"⚠️  警告: 占位符密钥 {key_value[:20]}...")
                            results[str(env_file)] = 'placeholder'
                        elif key_value.startswith('sk-proj-') or key_value.startswith('sk-'):
                            print(f"✓ 真实密钥 {key_value[:15]}...")
                            results[str(env_file)] = 'real'
                        else:
                            print(f"❌ 无效密钥格式: {key_value[:20]}...")
                            results[str(env_file)] = 'invalid'
                        break
                else:
                    print("❌ 未找到OPENAI_API_KEY配置")
                    results[str(env_file)] = 'missing'
                    
            except Exception as e:
                print(f"❌ 读取文件失败: {e}")
                results[str(env_file)] = 'error'
        else:
            print("❌ 文件不存在")
            results[str(env_file)] = 'not_found'
    
    return results

def check_config_loading():
    """检查配置加载"""
    print("\n=== 配置加载检查 ===")
    try:
        from core.config import settings
        
        api_key = settings.openai_api_key
        if api_key:
            print(f"✓ 配置加载成功")
            print(f"✓ 加载的API密钥: {api_key[:15]}...")
            print(f"✓ 使用的模型: {settings.openai_model}")
            
            if api_key.startswith('sk-test-') or 'demo' in api_key.lower():
                print("⚠️  警告: 加载了测试密钥")
                return False
            elif api_key.startswith('sk-placeholder-'):
                print("⚠️  警告: 加载了占位符密钥")
                return False
            else:
                print("✓ 密钥格式正确")
                return True
        else:
            print("❌ 未加载到API密钥")
            return False
            
    except Exception as e:
        print(f"❌ 配置加载失败: {e}")
        return False

def test_openai_connection():
    """测试OpenAI连接"""
    print("\n=== OpenAI连接测试 ===")
    try:
        from services.openai_service import OpenAIService
        
        service = OpenAIService()
        print("✓ OpenAI服务初始化成功")
        return True
        
    except Exception as e:
        print(f"❌ OpenAI服务初始化失败: {e}")
        return False

def provide_solutions(env_check, config_check, connection_check):
    """提供解决方案"""
    print("\n=== 解决方案建议 ===")
    
    if env_check is False:  # 环境变量有问题
        print("\n🔧 解决方案1: 清除环境变量")
        print("   unset OPENAI_API_KEY")
        print("   # 然后重新运行脚本")
        
        print("\n🔧 解决方案2: 更新环境变量")
        print("   export OPENAI_API_KEY='your-real-api-key'")
        
    if not config_check:
        print("\n🔧 解决方案3: 检查.env文件")
        print("   确保根目录的.env文件包含正确的API密钥")
        print("   OPENAI_API_KEY=sk-proj-your-real-key")
        
    if not connection_check:
        print("\n🔧 解决方案4: 验证API密钥")
        print("   1. 登录 https://platform.openai.com/account/api-keys")
        print("   2. 检查API密钥是否有效")
        print("   3. 确保账户有足够的余额")
        
    print("\n📖 详细文档: docs/troubleshooting/openai_api_key_issue.md")

def main():
    """主函数"""
    print("OpenAI配置检查和修复工具")
    print("=" * 50)
    
    # 检查环境变量
    env_check = check_environment_variable()
    
    # 检查.env文件
    env_files_check = check_env_files()
    
    # 检查配置加载
    config_check = check_config_loading()
    
    # 测试连接
    connection_check = test_openai_connection()
    
    # 总结
    print("\n=== 检查总结 ===")
    print(f"环境变量: {'✓' if env_check else '⚠️' if env_check is False else '○'}")
    print(f"配置加载: {'✓' if config_check else '❌'}")
    print(f"服务连接: {'✓' if connection_check else '❌'}")
    
    # 提供解决方案
    if not all([config_check, connection_check]):
        provide_solutions(env_check, config_check, connection_check)
    else:
        print("\n🎉 所有检查通过！OpenAI配置正常。")
        print("\n可以运行演示脚本:")
        print("   cd /home/xzj/01_Project/B_25OS")
        print("   python examples/openai_integration_demo.py")

if __name__ == "__main__":
    main()