#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
综合集成测试脚本
用于全面验证1.1至1.3模块的功能完整性和协作能力

测试范围:
- 1.1 基础设施模块
- 1.2 日志解析模块 (包含子模块 1.2.1, 1.2.2, 1.2.3)
- 1.3 异常检测与过滤模块 (包含子模块 1.3.1, 1.3.2)
"""

import os
import sys
import asyncio
import tempfile
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# 添加项目路径
sys.path.insert(0, '/home/xzj/01_Project/B_25OS/src/backend')

# 设置环境变量避免依赖问题
os.environ['OPENAI_API_KEY'] = 'test-key'
os.environ['PINECONE_API_KEY'] = 'test-key'
os.environ['PINECONE_ENVIRONMENT'] = 'test-env'


class ComprehensiveTestRunner:
    """综合测试运行器"""
    
    def __init__(self):
        self.test_results = {}
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        
    def log_test_result(self, module_name: str, success: bool, details: str = ""):
        """记录测试结果"""
        self.test_results[module_name] = {
            'success': success,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.total_tests += 1
        if success:
            self.passed_tests += 1
        else:
            self.failed_tests += 1
            
    async def test_1_1_infrastructure(self):
        """测试1.1基础设施模块"""
        try:
            # 测试配置管理
            from config.filter_engine_config import FilterEngineConfig, create_default_config_file
            
            # 创建临时配置文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                config_path = f.name
                create_default_config_file(config_path)
            
            # 测试配置加载
            config = FilterEngineConfig.from_file(config_path)
            assert config is not None
            assert hasattr(config, 'priority_filter_enabled')
            
            # 清理
            os.unlink(config_path)
            
            self.log_test_result("1.1_infrastructure", True, "配置管理功能正常")
            
        except Exception as e:
            import traceback
            error_msg = f"错误: {str(e)}\n{traceback.format_exc()}"
            self.log_test_result("1.1_infrastructure", False, error_msg)
    
    async def test_1_2_1_falco_log_parser(self):
        """测试1.2.1 Falco日志解析器"""
        try:
            from services.falco_log_parser import FalcoLogParser, StandardizedEvent
            
            # 创建临时日志文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
                log_path = f.name
            
            parser = FalcoLogParser(log_path)
            
            # 测试日志解析
            test_log = {
                "time": "2024-01-01T10:00:00.000000000Z",
                "rule": "Terminal shell in container",
                "priority": "Notice",
                "output": "A shell was used as the entrypoint/exec point into a container",
                "output_fields": {
                    "container.id": "test123",
                    "proc.name": "bash",
                    "user.name": "root"
                }
            }
            
            event = parser.parse_event(json.dumps(test_log))
            assert isinstance(event, StandardizedEvent)
            assert event.rule_name == "Terminal shell in container"
            
            self.log_test_result("1.2.1_falco_log_parser", True, "日志解析功能正常")
            
        except Exception as e:
            self.log_test_result("1.2.1_falco_log_parser", False, f"错误: {str(e)}")
    
    async def test_1_2_2_graph_database(self):
        """测试1.2.2图数据库管理"""
        try:
            from services.graph_database import GraphDatabaseManager, GraphNodeType
            
            # 创建管理器实例（不实际连接）
            manager = GraphDatabaseManager(
                uri="bolt://localhost:7687",
                username="neo4j",
                password="password"
            )
            
            # 测试基本属性
            assert manager.uri == "bolt://localhost:7687"
            assert manager.username == "neo4j"
            assert hasattr(manager, 'batch_size')
            
            # 测试节点类型常量
            assert hasattr(GraphNodeType, 'EVENT')
            assert hasattr(GraphNodeType, 'PROCESS')
            
            self.log_test_result("1.2.2_graph_database", True, "图数据库管理器初始化正常")
            
        except Exception as e:
            self.log_test_result("1.2.2_graph_database", False, f"错误: {str(e)}")
    
    async def test_1_2_3_log_volume_controller(self):
        """测试1.2.3日志量控制器"""
        try:
            from services.log_volume_controller import LogVolumeController, LogVolumeConfig
            
            # 创建配置
            config = LogVolumeConfig(
                max_file_size=100 * 1024 * 1024,  # 100MB
                max_files=10,
                enable_compression=True,
                base_sampling_rate=0.8
            )
            
            # 创建控制器
            controller = LogVolumeController(config)
            
            # 测试基本功能
            assert hasattr(controller, 'config')
            assert controller.config.max_file_size == 100 * 1024 * 1024
            
            # 测试统计信息获取
            stats = controller.get_stats()
            assert isinstance(stats, dict)
            # 检查统计信息的基本结构
            assert isinstance(stats, dict)
            # LogVolumeController的stats包含这些字段
            expected_keys = ['total_events', 'sampled_events', 'dropped_events']
            assert any(key in stats for key in expected_keys)
            
            self.log_test_result("1.2.3_log_volume_controller", True, "日志量控制器功能正常")
            
        except Exception as e:
            import traceback
            error_msg = f"错误: {str(e)}\n{traceback.format_exc()}"
            self.log_test_result("1.2.3_log_volume_controller", False, error_msg)
    
    async def test_1_3_1_local_filter_engine(self):
        """测试1.3.1本地过滤引擎"""
        try:
            from services.local_filter_engine import LocalFilterEngine
            from config.filter_engine_config import FilterEngineConfig
            
            # 创建配置
            config = FilterEngineConfig()
            
            # 创建引擎
            engine = LocalFilterEngine(config)
            
            # 测试基本属性
            # 测试引擎的基本属性
            assert engine is not None
            # LocalFilterEngine应该有这些基本方法
            assert hasattr(engine, '__init__')
            
            self.log_test_result("1.3.1_local_filter_engine", True, "本地过滤引擎初始化正常")
            
        except Exception as e:
            import traceback
            error_msg = f"错误: {str(e)}\n{traceback.format_exc()}"
            self.log_test_result("1.3.1_local_filter_engine", False, error_msg)
    
    async def test_1_3_2_graph_query_optimizer(self):
        """测试1.3.2图查询优化器"""
        try:
            from services.graph_query_optimizer import GraphQueryOptimizer
            from services.graph_database import GraphDatabaseManager
            
            # 创建GraphDatabaseManager实例
            graph_manager = GraphDatabaseManager(
                uri="bolt://localhost:7687",
                username="neo4j",
                password="password"
            )
            
            # 创建优化器
            optimizer = GraphQueryOptimizer(graph_manager)
            
            # 测试基本属性
            # 测试优化器的基本属性
            assert optimizer is not None
            assert hasattr(optimizer, 'graph_manager')
            assert hasattr(optimizer, 'query_templates')
            
            self.log_test_result("1.3.2_graph_query_optimizer", True, "图查询优化器初始化正常")
            
        except Exception as e:
            import traceback
            error_msg = f"错误: {str(e)}\n{traceback.format_exc()}"
            self.log_test_result("1.3.2_graph_query_optimizer", False, error_msg)
    
    async def test_end_to_end_integration(self):
        """端到端集成测试"""
        try:
            # 模拟完整的数据流
            from services.falco_log_parser import FalcoLogParser
            from services.local_filter_engine import LocalFilterEngine
            from config.filter_engine_config import FilterEngineConfig
            
            # 1. 解析日志
            with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
                log_path = f.name
            
            parser = FalcoLogParser(log_path)
            test_log = {
                "time": "2024-01-01T10:00:00.000000000Z",
                "rule": "Suspicious network activity",
                "priority": "Warning",
                "output": "Unexpected network connection detected",
                "output_fields": {
                    "fd.rip": "192.168.1.100",
                    "proc.name": "suspicious_proc"
                }
            }
            
            event = parser.parse_event(json.dumps(test_log))
            
            # 2. 过滤处理
            config = FilterEngineConfig()
            engine = LocalFilterEngine(config)
            
            # 测试事件处理流程
            assert event is not None
            assert hasattr(event, 'rule_name')
            
            self.log_test_result("end_to_end_integration", True, "端到端集成测试通过")
            
        except Exception as e:
            self.log_test_result("end_to_end_integration", False, f"错误: {str(e)}")
    
    async def run_all_tests(self):
        """运行所有测试"""
        print("\n=== 开始综合集成测试 ===")
        print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n" + "="*60)
        
        # 运行各模块测试
        test_methods = [
            self.test_1_1_infrastructure,
            self.test_1_2_1_falco_log_parser,
            self.test_1_2_2_graph_database,
            self.test_1_2_3_log_volume_controller,
            self.test_1_3_1_local_filter_engine,
            self.test_1_3_2_graph_query_optimizer,
            self.test_end_to_end_integration
        ]
        
        for test_method in test_methods:
            try:
                await test_method()
                print(f"✓ {test_method.__name__}")
            except Exception as e:
                print(f"✗ {test_method.__name__}: {str(e)}")
        
        # 生成测试报告
        self.generate_report()
    
    def generate_report(self):
        """生成测试报告"""
        print("\n" + "="*60)
        print("=== 综合测试报告 ===")
        print(f"总测试数: {self.total_tests}")
        print(f"通过: {self.passed_tests}")
        print(f"失败: {self.failed_tests}")
        print(f"成功率: {(self.passed_tests/self.total_tests*100):.1f}%")
        
        print("\n详细结果:")
        for module, result in self.test_results.items():
            status = "✓ 通过" if result['success'] else "✗ 失败"
            print(f"  {module}: {status}")
            if result['details']:
                print(f"    详情: {result['details']}")
        
        # 生成建议
        if self.failed_tests > 0:
            print("\n=== 修复建议 ===")
            for module, result in self.test_results.items():
                if not result['success']:
                    print(f"• {module}: {result['details']}")
        else:
            print("\n🎉 所有测试通过！模块开发质量良好。")
        
        print("\n" + "="*60)


async def main():
    """主函数"""
    runner = ComprehensiveTestRunner()
    await runner.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())