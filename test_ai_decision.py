#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS AI决策代理测试脚本

该脚本用于测试AI决策代理的各个组件和集成功能。
测试内容包括：
1. OpenAI分析服务集成
2. AI决策代理决策逻辑
3. 命令执行器功能
4. 效果验证器功能
5. 完整工作流集成测试

作者: NeuronOS Team
创建时间: 2024-12-19
"""

import asyncio
import json
import logging
import sys
import os
from datetime import datetime
from typing import Dict, List, Any

# 添加项目路径
sys.path.append('/home/xzj/01_Project/B_25OS')
sys.path.append('/home/xzj/01_Project/B_25OS/src')
sys.path.append('/home/xzj/01_Project/B_25OS/src/backend')

# 导入测试模块
try:
    from src.backend.services.ai_decision_integration import AIDecisionIntegration
    from src.backend.services.ai_decision_agent import ExecutionMode
    from src.backend.services.openai_service import AnalysisRequest, AnalysisType
except ImportError as e:
    print(f"导入模块失败: {e}")
    print("请确保项目路径正确且所有依赖已安装")
    # 尝试直接导入
    try:
        import services.ai_decision_integration as ai_integration
        import services.ai_decision_agent as ai_agent
        import services.openai_service as openai_svc
        AIDecisionIntegration = ai_integration.AIDecisionIntegration
        ExecutionMode = ai_agent.ExecutionMode
        AnalysisRequest = openai_svc.AnalysisRequest
        AnalysisType = openai_svc.AnalysisType
        print("使用备用导入方式成功")
    except ImportError as e2:
        print(f"备用导入也失败: {e2}")
        sys.exit(1)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AIDecisionTester:
    """AI决策代理测试器"""
    
    def __init__(self):
        """初始化测试器"""
        self.config_path = "/home/xzj/01_Project/B_25OS/config/ai_decision_config.yaml"
        self.integration = None
        self.test_results = []
    
    async def setup(self):
        """设置测试环境"""
        try:
            logger.info("初始化AI决策代理集成服务...")
            self.integration = AIDecisionIntegration(self.config_path)
            logger.info("测试环境设置完成")
            return True
        except Exception as e:
            logger.error(f"设置测试环境失败: {e}")
            return False
    
    def create_test_security_events(self) -> List[Dict[str, Any]]:
        """创建测试用的安全事件"""
        return [
            {
                'event_type': 'suspicious_process',
                'process_name': 'malware.exe',
                'pid': 1234,
                'severity': 'high',
                'timestamp': datetime.now().isoformat(),
                'source': 'endpoint_detection',
                'description': '检测到可疑进程执行',
                'metadata': {
                    'file_path': '/tmp/malware.exe',
                    'parent_process': 'explorer.exe',
                    'command_line': 'malware.exe --stealth',
                    'network_connections': ['192.168.1.100:4444']
                }
            },
            {
                'event_type': 'network_anomaly',
                'severity': 'medium',
                'timestamp': datetime.now().isoformat(),
                'source': 'network_monitor',
                'description': '检测到异常网络流量',
                'metadata': {
                    'source_ip': '10.0.0.50',
                    'destination_ip': '192.168.1.100',
                    'port': 4444,
                    'protocol': 'TCP',
                    'bytes_transferred': 1048576
                }
            },
            {
                'event_type': 'file_modification',
                'severity': 'low',
                'timestamp': datetime.now().isoformat(),
                'source': 'file_monitor',
                'description': '系统文件被修改',
                'metadata': {
                    'file_path': '/etc/hosts',
                    'modification_type': 'content_change',
                    'user': 'root',
                    'process': 'vim'
                }
            }
        ]
    
    async def test_openai_integration(self) -> bool:
        """测试OpenAI集成"""
        logger.info("开始测试OpenAI集成...")
        
        try:
            # 创建测试事件
            test_events = self.create_test_security_events()[:1]  # 只用第一个事件
            
            # 测试OpenAI服务
            openai_service = self.integration.openai_service
            
            # 创建分析请求
            analysis_request = AnalysisRequest(
                events=test_events,
                analysis_type=AnalysisType.SECURITY_ANALYSIS,
                priority="high",
                context={"test_mode": True}
            )
            
            # 执行分析
            analysis_result = await openai_service.analyze_security_events(analysis_request)
            
            # 验证结果
            if analysis_result and hasattr(analysis_result, 'risk_score'):
                logger.info(f"OpenAI分析成功，风险评分: {analysis_result.risk_score}")
                self.test_results.append({
                    'test': 'openai_integration',
                    'status': 'passed',
                    'details': f'风险评分: {analysis_result.risk_score}'
                })
                return True
            else:
                logger.error("OpenAI分析结果无效")
                self.test_results.append({
                    'test': 'openai_integration',
                    'status': 'failed',
                    'details': '分析结果无效'
                })
                return False
                
        except Exception as e:
            logger.error(f"OpenAI集成测试失败: {e}")
            self.test_results.append({
                'test': 'openai_integration',
                'status': 'failed',
                'details': str(e)
            })
            return False
    
    async def test_decision_agent(self) -> bool:
        """测试决策代理"""
        logger.info("开始测试决策代理...")
        
        try:
            # 创建模拟分析结果
            from src.backend.services.openai_service import AnalysisResponse
            
            from src.backend.services.openai_service import AnalysisType, Priority
            
            mock_analysis = AnalysisResponse(
                request_id="test_request_001",
                analysis_type=AnalysisType.SECURITY_ANALYSIS,
                summary="检测到高风险恶意进程",
                detailed_analysis="进程malware.exe表现出典型的恶意软件行为",
                recommendations=["立即终止进程", "隔离受影响系统", "扫描相关文件"],
                risk_score=85,
                confidence=0.9,
                priority=Priority.HIGH,
                affected_systems=["endpoint-001"],
                attack_vectors=["process_injection", "network_communication"],
                mitigation_steps=["kill_process", "block_ip", "scan_file"],
                timestamp=datetime.now(),
                processing_time=1.5,
                token_usage={'prompt_tokens': 100, 'completion_tokens': 50, 'total_tokens': 150}
            )
            
            # 创建决策上下文
            from src.backend.services.ai_decision_agent import DecisionContext
            
            decision_context = DecisionContext(
                analysis_response=mock_analysis,
                system_state={"test_mode": True},
                execution_mode=ExecutionMode.DRY_RUN,
                user_id="test_user",
                session_id="test_session"
            )
            
            # 执行决策
            decision_agent = self.integration.decision_agent
            decision_result = await decision_agent.make_decision(decision_context)
            
            # 验证结果
            if decision_result and decision_result.execution_plan and hasattr(decision_result.execution_plan, 'decision_type'):
                logger.info(f"决策代理成功，决策类型: {decision_result.execution_plan.decision_type.value}")
                self.test_results.append({
                    'test': 'decision_agent',
                    'status': 'passed',
                    'details': f'决策类型: {decision_result.execution_plan.decision_type.value}'
                })
                return True
            elif decision_result:
                logger.info(f"决策代理成功，但无执行计划")
                self.test_results.append({
                    'test': 'decision_agent',
                    'status': 'passed',
                    'details': '决策完成但无执行计划'
                })
                return True
            else:
                logger.error("决策代理结果无效")
                self.test_results.append({
                    'test': 'decision_agent',
                    'status': 'failed',
                    'details': '决策结果无效'
                })
                return False
                
        except Exception as e:
            logger.error(f"决策代理测试失败: {e}")
            self.test_results.append({
                'test': 'decision_agent',
                'status': 'failed',
                'details': str(e)
            })
            return False
    
    async def test_command_executor(self) -> bool:
        """测试命令执行器"""
        logger.info("开始测试命令执行器...")
        
        try:
            # 创建测试执行计划
            from src.backend.services.ai_decision_agent import ExecutionPlan, DecisionType, RiskLevel
            from src.backend.services.command_executor import CommandType
            
            test_plan = ExecutionPlan(
                plan_id="test_plan",
                decision_type=DecisionType.IMMEDIATE_ACTION,
                risk_level=RiskLevel.LOW,
                commands=[
                    {
                        "action": "check_system_status",
                        "parameters": {"target": "localhost"},
                        "description": "检查系统状态"
                    }
                ],
                execution_order=[0],
                estimated_duration=10.0,
                rollback_plan=[],
                approval_required=False,
                created_at=datetime.now(),
                created_by="test_user"
            )
            
            # 执行命令（干运行模式）
            decision_agent = self.integration.decision_agent
            execution_results = await decision_agent.execute_plan(test_plan)
            
            # 验证结果
            if execution_results and len(execution_results) > 0:
                logger.info(f"命令执行器成功，执行结果数量: {len(execution_results)}")
                self.test_results.append({
                    'test': 'command_executor',
                    'status': 'passed',
                    'details': f'执行结果数量: {len(execution_results)}'
                })
                return True
            else:
                logger.error("命令执行器结果无效")
                self.test_results.append({
                    'test': 'command_executor',
                    'status': 'failed',
                    'details': '执行结果无效'
                })
                return False
                
        except Exception as e:
            logger.error(f"命令执行器测试失败: {e}")
            self.test_results.append({
                'test': 'command_executor',
                'status': 'failed',
                'details': str(e)
            })
            return False
    
    async def test_effect_validator(self) -> bool:
        """测试效果验证器"""
        logger.info("开始测试效果验证器...")
        
        try:
            # 创建模拟执行结果
            from src.backend.services.command_executor import ExecutionResult, ExecutionStatus, CommandType
            
            mock_execution = ExecutionResult(
                command_id="test_execution",
                command={
                    "action": "check_system_status",
                    "parameters": {"target": "localhost"}
                },
                status=ExecutionStatus.SUCCESS,
                return_code=0,
                stdout="System status: OK",
                stderr="",
                execution_time=1.5,
                start_time=datetime.now(),
                end_time=datetime.now(),
                error_message=None,
                metadata={"test_mode": True}
            )
            
            # 执行效果验证
            effect_validator = self.integration.effect_validator
            validation_result = await effect_validator.validate_effect(
                command_info={"action": "check_system_status", "parameters": {"target": "localhost"}},
                execution_result=mock_execution
            )
            
            # 验证结果
            if validation_result and hasattr(validation_result, 'is_valid'):
                logger.info(f"效果验证器成功，验证结果: {validation_result.is_valid}")
                self.test_results.append({
                    'test': 'effect_validator',
                    'status': 'passed',
                    'details': f'验证结果: {validation_result.is_valid}'
                })
                return True
            else:
                logger.error("效果验证器结果无效")
                self.test_results.append({
                    'test': 'effect_validator',
                    'status': 'failed',
                    'details': '验证结果无效'
                })
                return False
                
        except Exception as e:
            logger.error(f"效果验证器测试失败: {e}")
            self.test_results.append({
                'test': 'effect_validator',
                'status': 'failed',
                'details': str(e)
            })
            return False
    
    async def test_full_workflow(self) -> bool:
        """测试完整工作流"""
        logger.info("开始测试完整工作流...")
        
        try:
            # 创建测试事件
            test_events = self.create_test_security_events()
            
            # 执行完整工作流（干运行模式）
            context = await self.integration.process_security_events(
                security_events=test_events,
                user_id="test_user",
                session_id="test_session",
                execution_mode=ExecutionMode.DRY_RUN
            )
            
            # 验证结果
            if context and context.workflow_id:
                logger.info(f"完整工作流成功，工作流ID: {context.workflow_id}")
                logger.info(f"最终状态: {context.status.value}")
                
                self.test_results.append({
                    'test': 'full_workflow',
                    'status': 'passed',
                    'details': f'工作流ID: {context.workflow_id}, 状态: {context.status.value}'
                })
                return True
            else:
                logger.error("完整工作流结果无效")
                self.test_results.append({
                    'test': 'full_workflow',
                    'status': 'failed',
                    'details': '工作流结果无效'
                })
                return False
                
        except Exception as e:
            logger.error(f"完整工作流测试失败: {e}")
            self.test_results.append({
                'test': 'full_workflow',
                'status': 'failed',
                'details': str(e)
            })
            return False
    
    async def test_statistics_and_monitoring(self) -> bool:
        """测试统计和监控功能"""
        logger.info("开始测试统计和监控功能...")
        
        try:
            # 获取统计信息
            stats = self.integration.get_statistics()
            
            # 获取活跃工作流
            active_workflows = self.integration.get_active_workflows()
            
            # 获取工作流历史
            workflow_history = self.integration.get_workflow_history(limit=10)
            
            # 执行健康检查
            health_status = await self.integration.health_check()
            
            # 验证结果
            if stats and health_status:
                logger.info("统计和监控功能正常")
                logger.info(f"统计信息: {stats}")
                logger.info(f"健康状态: {health_status['status']}")
                
                self.test_results.append({
                    'test': 'statistics_monitoring',
                    'status': 'passed',
                    'details': f'健康状态: {health_status["status"]}'
                })
                return True
            else:
                logger.error("统计和监控功能异常")
                self.test_results.append({
                    'test': 'statistics_monitoring',
                    'status': 'failed',
                    'details': '功能异常'
                })
                return False
                
        except Exception as e:
            logger.error(f"统计和监控功能测试失败: {e}")
            self.test_results.append({
                'test': 'statistics_monitoring',
                'status': 'failed',
                'details': str(e)
            })
            return False
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """运行所有测试"""
        logger.info("开始运行AI决策代理完整测试套件...")
        
        # 设置测试环境
        if not await self.setup():
            return {
                'success': False,
                'error': '测试环境设置失败',
                'results': []
            }
        
        # 定义测试用例
        test_cases = [
            ('OpenAI集成测试', self.test_openai_integration),
            ('决策代理测试', self.test_decision_agent),
            ('命令执行器测试', self.test_command_executor),
            ('效果验证器测试', self.test_effect_validator),
            ('完整工作流测试', self.test_full_workflow),
            ('统计监控测试', self.test_statistics_and_monitoring)
        ]
        
        # 执行测试
        passed_tests = 0
        total_tests = len(test_cases)
        
        for test_name, test_func in test_cases:
            logger.info(f"\n{'='*50}")
            logger.info(f"执行测试: {test_name}")
            logger.info(f"{'='*50}")
            
            try:
                result = await test_func()
                if result:
                    passed_tests += 1
                    logger.info(f"✅ {test_name} - 通过")
                else:
                    logger.error(f"❌ {test_name} - 失败")
            except Exception as e:
                logger.error(f"❌ {test_name} - 异常: {e}")
        
        # 生成测试报告
        success_rate = passed_tests / total_tests
        test_summary = {
            'success': success_rate == 1.0,
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': total_tests - passed_tests,
            'success_rate': success_rate,
            'test_time': datetime.now().isoformat(),
            'results': self.test_results
        }
        
        logger.info(f"\n{'='*60}")
        logger.info("测试总结")
        logger.info(f"{'='*60}")
        logger.info(f"总测试数: {total_tests}")
        logger.info(f"通过测试: {passed_tests}")
        logger.info(f"失败测试: {total_tests - passed_tests}")
        logger.info(f"成功率: {success_rate:.2%}")
        
        if success_rate == 1.0:
            logger.info("🎉 所有测试通过！AI决策代理功能正常")
        else:
            logger.warning("⚠️ 部分测试失败，请检查相关组件")
        
        return test_summary
    
    def save_test_report(self, test_summary: Dict[str, Any], filename: str = None):
        """保存测试报告"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"/home/xzj/01_Project/B_25OS/ai_decision_test_report_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(test_summary, f, indent=2, ensure_ascii=False)
            logger.info(f"测试报告已保存到: {filename}")
        except Exception as e:
            logger.error(f"保存测试报告失败: {e}")

async def main():
    """主函数"""
    print("NeuronOS AI决策代理测试脚本")
    print("=" * 50)
    
    # 创建测试器
    tester = AIDecisionTester()
    
    try:
        # 运行所有测试
        test_summary = await tester.run_all_tests()
        
        # 保存测试报告
        tester.save_test_report(test_summary)
        
        # 返回结果
        if test_summary['success']:
            print("\n🎉 测试完成！所有功能正常")
            return 0
        else:
            print("\n⚠️ 测试完成！部分功能异常")
            return 1
            
    except KeyboardInterrupt:
        print("\n用户中断测试")
        return 130
    except Exception as e:
        print(f"\n测试执行失败: {e}")
        return 1

if __name__ == "__main__":
    # 运行测试
    exit_code = asyncio.run(main())
    sys.exit(exit_code)