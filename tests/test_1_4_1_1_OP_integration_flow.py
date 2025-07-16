#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1.4.1.1 集成流程测试 - 从图查询优化到OpenAI分析
展示项目从1.3.2图查询优化到1.4.1 OpenAI分析的完整数据流程

测试流程:
1. 连接Neo4j数据库
2. 使用1.3.2图查询优化器分析当前数据库内容
3. 将查询结果输入到1.4.1 OpenAI服务进行智能分析
4. 输出分析结果
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from loguru import logger

# 添加项目路径
import sys
sys.path.append('/home/xzj/01_Project/B_25OS/src/backend')

# 导入1.3.2图查询优化模块
from services.graph_query_optimizer import (
    GraphQueryOptimizer,
    QueryOptimizerConfig,
    create_query_optimizer
)
from services.graph_database import GraphDatabaseManager
from services.interfaces import QueryType, OptimizationLevel

# 导入1.4.1 OpenAI分析模块
from services.openai_service import (
    OpenAIService,
    AnalysisRequest,
    AnalysisResponse,
    AnalysisType,
    Priority,
    analyze_events
)
from config.openai_config import OpenAIConfig

# 导入核心配置
from core.config import settings
from core.database import neo4j_driver


class TestIntegrationFlow:
    """集成流程测试类"""
    
    def __init__(self):
        self.db_manager = None
        self.query_optimizer = None
        self.openai_service = None
        self.test_results = {}
    
    async def setup_services(self):
        """初始化服务组件"""
        logger.info("=== 开始初始化服务组件 ===")
        
        try:
            # 1. 初始化Neo4j数据库连接
            logger.info("1. 初始化Neo4j数据库连接...")
            await neo4j_driver.connect()
            connection_status = await neo4j_driver.verify_connectivity()
            
            if not connection_status:
                raise Exception("Neo4j数据库连接失败")
            
            logger.info("✅ Neo4j数据库连接成功")
            
            # 2. 初始化图数据库管理器
            logger.info("2. 初始化图数据库管理器...")
            self.db_manager = GraphDatabaseManager(
                uri=settings.neo4j_uri,
                username=settings.neo4j_user,
                password=settings.neo4j_password,
                database=settings.neo4j_database
            )
            
            # 连接数据库管理器
            await self.db_manager.connect()
            logger.info("✅ 图数据库管理器初始化成功")
            
            # 3. 初始化1.3.2图查询优化器
            logger.info("3. 初始化图查询优化器...")
            optimizer_config = QueryOptimizerConfig(
                enabled=True,
                optimization_level=OptimizationLevel.BALANCED,
                cache_enabled=True,
                cache_size=1000,
                cache_ttl=3600,
                query_timeout=30
            )
            
            self.query_optimizer = GraphQueryOptimizer(
                config=optimizer_config,
                db_manager=self.db_manager
            )
            
            # 启动并验证查询优化器
            await self.query_optimizer.start_optimizer()
            if not hasattr(self.query_optimizer, 'config'):
                raise AssertionError("查询优化器配置缺失")
            
            logger.info("✅ 图查询优化器启动并验证通过")
            
            # 4. 初始化1.4.1 OpenAI服务
            logger.info("4. 初始化OpenAI服务...")
            self.openai_service = OpenAIService()
            
            # 验证OpenAI服务
            service_stats = self.openai_service.get_statistics()
            if self.openai_service.client is None:
                raise Exception("OpenAI客户端初始化失败")
            
            logger.info(f"OpenAI服务统计: {service_stats}")
            
            logger.info("✅ OpenAI服务初始化成功")
            logger.info("=== 所有服务组件初始化完成 ===")
            
        except Exception as e:
            logger.error(f"❌ 服务初始化失败: {e}")
            raise
    
    async def analyze_database_content(self) -> Dict[str, Any]:
        """步骤1: 使用1.3.2图查询优化器分析数据库内容"""
        logger.info("\n=== 步骤1: 分析Neo4j数据库内容 ===")
        
        try:
            # 1. 获取数据库统计信息
            logger.info("1.1 获取数据库统计信息...")
            db_stats = await self.db_manager.get_graph_stats()
            logger.info(f"数据库统计: {json.dumps(db_stats, indent=2, ensure_ascii=False)}")
            
            # 2. 查询最近的安全事件
            logger.info("1.2 查询最近的安全事件...")
            recent_events_query = """
            MATCH (e:Event)
            WHERE e.timestamp >= datetime() - duration('P7D')
            RETURN e.event_id, e.rule, e.message, e.priority, e.timestamp, e.source
            ORDER BY e.timestamp DESC
            LIMIT 20
            """
            
            recent_events = await self.query_optimizer.execute_optimized_query(
                query=recent_events_query,
                params={}
            )
            
            logger.info(f"找到 {len(recent_events.get('data', []))} 个最近事件")
            
            # 3. 分析事件关联关系
            logger.info("1.3 分析事件关联关系...")
            correlation_query = """
            MATCH (e1:Event)-[r:TRIGGERS|FOLLOWS|CORRELATES_WITH]->(e2:Event)
            WHERE e1.timestamp >= datetime() - duration('P7D')
            RETURN e1.event_id, type(r) as relation_type, e2.event_id, 
                   e1.rule as source_rule, e2.rule as target_rule,
                   e1.priority as source_priority, e2.priority as target_priority
            ORDER BY e1.timestamp DESC
            LIMIT 15
            """
            
            correlations = await self.query_optimizer.execute_optimized_query(
                query=correlation_query,
                params={}
            )
            
            logger.info(f"找到 {len(correlations.get('data', []))} 个事件关联")
            
            # 4. 查询高优先级事件
            logger.info("1.4 查询高优先级事件...")
            high_priority_query = """
            MATCH (e:Event)
            WHERE e.priority IN ['Critical', 'High', 'critical', 'high']
              AND e.timestamp >= datetime() - duration('P3D')
            RETURN e.event_id, e.rule, e.message, e.priority, e.timestamp,
                   e.source, e.process_name, e.user_name, e.file_path
            ORDER BY e.timestamp DESC
            LIMIT 10
            """
            
            high_priority_events = await self.query_optimizer.execute_optimized_query(
                query=high_priority_query,
                params={}
            )
            
            logger.info(f"找到 {len(high_priority_events.get('data', []))} 个高优先级事件")
            
            # 5. 分析攻击路径
            logger.info("1.5 分析潜在攻击路径...")
            attack_path_query = """
            MATCH path = (start:Event)-[:TRIGGERS*1..3]->(end:Event)
            WHERE start.priority IN ['Critical', 'High'] 
              AND start.timestamp >= datetime() - duration('P1D')
            RETURN 
                [node in nodes(path) | {
                    event_id: node.event_id,
                    rule: node.rule,
                    timestamp: node.timestamp,
                    priority: node.priority
                }] as attack_sequence,
                length(path) as path_length
            ORDER BY path_length DESC, start.timestamp DESC
            LIMIT 5
            """
            
            attack_paths = await self.query_optimizer.execute_optimized_query(
                query=attack_path_query,
                params={}
            )
            
            logger.info(f"找到 {len(attack_paths.get('data', []))} 个潜在攻击路径")
            
            # 整合分析结果
            analysis_result = {
                'database_stats': db_stats,
                'recent_events': recent_events.get('data', []),
                'event_correlations': correlations.get('data', []),
                'high_priority_events': high_priority_events.get('data', []),
                'attack_paths': attack_paths.get('data', []),
                'query_performance': {
                    'recent_events_time': recent_events.get('execution_time', 0),
                    'correlations_time': correlations.get('execution_time', 0),
                    'high_priority_time': high_priority_events.get('execution_time', 0),
                    'attack_paths_time': attack_paths.get('execution_time', 0)
                },
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            self.test_results['graph_analysis'] = analysis_result
            logger.info("✅ 数据库内容分析完成")
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"❌ 数据库分析失败: {e}")
            raise
    
    async def analyze_with_openai(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """步骤2: 使用1.4.1 OpenAI服务分析图查询结果"""
        logger.info("\n=== 步骤2: OpenAI智能分析 ===")
        
        try:
            # 1. 准备分析数据
            logger.info("2.1 准备分析数据...")
            
            # 提取关键事件用于分析
            events_for_analysis = []
            
            # 添加高优先级事件
            for event in graph_data.get('high_priority_events', []):
                events_for_analysis.append({
                    'event_id': event.get('e.event_id'),
                    'rule': event.get('e.rule'),
                    'message': event.get('e.message'),
                    'priority': event.get('e.priority'),
                    'timestamp': event.get('e.timestamp'),
                    'source': event.get('e.source'),
                    'process_name': event.get('e.process_name'),
                    'user_name': event.get('e.user_name'),
                    'file_path': event.get('e.file_path')
                })
            
            # 添加最近事件（如果高优先级事件不足）
            if len(events_for_analysis) < 5:
                for event in graph_data.get('recent_events', [])[:10]:
                    event_data = {
                        'event_id': event.get('e.event_id'),
                        'rule': event.get('e.rule'),
                        'message': event.get('e.message'),
                        'priority': event.get('e.priority'),
                        'timestamp': event.get('e.timestamp'),
                        'source': event.get('e.source')
                    }
                    if event_data not in events_for_analysis:
                        events_for_analysis.append(event_data)
            
            logger.info(f"准备分析 {len(events_for_analysis)} 个事件")
            
            # 2. 创建分析请求
            logger.info("2.2 创建OpenAI分析请求...")
            
            analysis_request = AnalysisRequest(
                analysis_type=AnalysisType.SECURITY_ANALYSIS,
                events=events_for_analysis,
                context={
                    'database_stats': graph_data.get('database_stats', {}),
                    'correlations_count': len(graph_data.get('event_correlations', [])),
                    'attack_paths_count': len(graph_data.get('attack_paths', [])),
                    'analysis_timeframe': '7 days',
                    'system_info': 'NeuronOS Security Monitoring System'
                },
                priority=Priority.HIGH
            )
            
            # 3. 执行安全分析
            logger.info("2.3 执行安全分析...")
            security_analysis = await self.openai_service.analyze_security_events(analysis_request)
            
            logger.info("✅ 安全分析完成")
            logger.info(f"分析结果概要: {security_analysis.summary}")
            
            # 4. 执行威胁评估（如果有高优先级事件）
            threat_assessment = None
            if graph_data.get('high_priority_events'):
                logger.info("2.4 执行威胁评估...")
                
                threat_request = AnalysisRequest(
                    analysis_type=AnalysisType.THREAT_ASSESSMENT,
                    events=events_for_analysis[:5],  # 只分析前5个事件
                    context={
                        'high_priority_count': len(graph_data.get('high_priority_events', [])),
                        'attack_paths': graph_data.get('attack_paths', []),
                        'system_criticality': 'high'
                    },
                    priority=Priority.CRITICAL
                )
                
                threat_assessment = await self.openai_service.assess_threat(threat_request)
                logger.info("✅ 威胁评估完成")
                logger.info(f"威胁评估结果: {threat_assessment.summary}")
            
            # 5. 生成修复建议（如果发现威胁）
            remediation_advice = None
            if threat_assessment and threat_assessment.risk_score > 7.0:
                logger.info("2.5 生成修复建议...")
                
                remediation_request = AnalysisRequest(
                    analysis_type=AnalysisType.REMEDIATION_ADVICE,
                    events=events_for_analysis[:3],  # 只针对最关键的事件
                    context={
                        'threat_level': threat_assessment.risk_score,
                        'security_analysis': security_analysis.summary,
                        'system_type': 'Linux/OpenKylin',
                        'monitoring_tool': 'Falco'
                    },
                    priority=Priority.HIGH
                )
                
                remediation_advice = await self.openai_service.get_remediation_advice(remediation_request)
                logger.info("✅ 修复建议生成完成")
            
            # 整合OpenAI分析结果
            openai_result = {
                'security_analysis': {
                    'summary': security_analysis.summary,
                    'risk_score': security_analysis.risk_score,
                    'confidence': security_analysis.confidence,
                    'detailed_analysis': security_analysis.detailed_analysis,
                    'recommendations': security_analysis.recommendations,
                    'attack_vectors': security_analysis.attack_vectors,
                    'mitigation_steps': security_analysis.mitigation_steps,
                    'processing_time': security_analysis.processing_time,
                    'token_usage': security_analysis.token_usage
                },
                'threat_assessment': {
                    'summary': threat_assessment.summary if threat_assessment else None,
                    'risk_score': threat_assessment.risk_score if threat_assessment else None,
                    'confidence': threat_assessment.confidence if threat_assessment else None,
                    'attack_vectors': threat_assessment.attack_vectors if threat_assessment else [],
                    'mitigation_steps': threat_assessment.mitigation_steps if threat_assessment else [],
                    'processing_time': threat_assessment.processing_time if threat_assessment else None
                } if threat_assessment else None,
                'remediation_advice': {
                    'summary': remediation_advice.summary if remediation_advice else None,
                    'mitigation_steps': remediation_advice.mitigation_steps if remediation_advice else [],
                    'recommendations': remediation_advice.recommendations if remediation_advice else [],
                    'attack_vectors': remediation_advice.attack_vectors if remediation_advice else []
                } if remediation_advice else None,
                'analysis_metadata': {
                    'events_analyzed': len(events_for_analysis),
                    'analysis_timestamp': datetime.now().isoformat(),
                    'total_processing_time': (
                        security_analysis.processing_time +
                        (threat_assessment.processing_time if threat_assessment else 0) +
                        (remediation_advice.processing_time if remediation_advice else 0)
                    ),
                    'total_tokens_used': (
                        security_analysis.token_usage.get('total', 0) +
                        (threat_assessment.token_usage.get('total', 0) if threat_assessment else 0) +
                        (remediation_advice.token_usage.get('total', 0) if remediation_advice else 0)
                    )
                }
            }
            
            self.test_results['openai_analysis'] = openai_result
            logger.info("✅ OpenAI分析完成")
            
            return openai_result
            
        except Exception as e:
            logger.error(f"❌ OpenAI分析失败: {e}")
            raise
    
    async def generate_comprehensive_report(self, graph_data: Dict[str, Any], openai_data: Dict[str, Any]) -> Dict[str, Any]:
        """步骤3: 生成综合分析报告"""
        logger.info("\n=== 步骤3: 生成综合分析报告 ===")
        
        try:
            # 计算关键指标
            total_events = len(graph_data.get('recent_events', []))
            high_priority_events = len(graph_data.get('high_priority_events', []))
            correlations = len(graph_data.get('event_correlations', []))
            attack_paths = len(graph_data.get('attack_paths', []))
            
            # 获取OpenAI分析结果
            security_analysis = openai_data.get('security_analysis', {})
            threat_assessment = openai_data.get('threat_assessment')
            remediation_advice = openai_data.get('remediation_advice')
            
            # 生成综合报告
            comprehensive_report = {
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'analysis_period': '7 days',
                    'system': 'NeuronOS Security Monitoring',
                    'version': '1.4.1'
                },
                'executive_summary': {
                    'total_events_analyzed': total_events,
                    'high_priority_events': high_priority_events,
                    'event_correlations': correlations,
                    'attack_paths_detected': attack_paths,
                    'overall_risk_score': security_analysis.get('risk_score', 0),
                    'confidence_level': security_analysis.get('confidence', 0),
                    'threat_level': 'High' if threat_assessment and threat_assessment.get('risk_score', 0) > 7 else 'Medium' if security_analysis.get('risk_score', 0) > 5 else 'Low'
                },
                'graph_analysis_summary': {
                    'database_statistics': graph_data.get('database_stats', {}),
                    'query_performance': graph_data.get('query_performance', {}),
                    'key_findings': {
                        'recent_activity': f"发现 {total_events} 个最近事件",
                        'priority_events': f"识别 {high_priority_events} 个高优先级事件",
                        'correlations': f"检测到 {correlations} 个事件关联",
                        'attack_patterns': f"发现 {attack_paths} 个潜在攻击路径"
                    }
                },
                'ai_analysis_summary': {
                    'security_analysis': security_analysis,
                    'threat_assessment': threat_assessment,
                    'remediation_advice': remediation_advice,
                    'processing_metrics': openai_data.get('analysis_metadata', {})
                },
                'recommendations': {
                    'immediate_actions': [],
                    'monitoring_improvements': [],
                    'security_enhancements': []
                },
                'technical_details': {
                    'graph_queries_executed': 5,
                    'ai_analyses_performed': 1 + (1 if threat_assessment else 0) + (1 if remediation_advice else 0),
                    'total_processing_time': (
                        sum(graph_data.get('query_performance', {}).values()) +
                        openai_data.get('analysis_metadata', {}).get('total_processing_time', 0)
                    ),
                    'data_sources': ['Neo4j Graph Database', 'OpenAI GPT-4', 'Falco Security Events']
                }
            }
            
            # 添加具体建议
            if security_analysis.get('recommendations'):
                comprehensive_report['recommendations']['immediate_actions'].extend(
                    security_analysis['recommendations'][:3]
                )
            
            if threat_assessment:
                comprehensive_report['recommendations']['security_enhancements'].append(
                    f"威胁评估显示风险评分为 {threat_assessment.get('risk_score', 0):.1f}，建议加强监控"
                )
            
            if remediation_advice:
                if remediation_advice.get('mitigation_steps'):
                    comprehensive_report['recommendations']['immediate_actions'].extend(
                        remediation_advice['mitigation_steps'][:2]
                    )
            
            comprehensive_report['recommendations']['monitoring_improvements'] = [
                "优化图查询性能，当前平均查询时间较长",
                "增加实时事件关联分析",
                "扩展攻击路径检测算法"
            ]
            
            self.test_results['comprehensive_report'] = comprehensive_report
            logger.info("✅ 综合分析报告生成完成")
            
            return comprehensive_report
            
        except Exception as e:
            logger.error(f"❌ 报告生成失败: {e}")
            raise
    
    async def cleanup_services(self):
        """清理服务资源"""
        logger.info("\n=== 清理服务资源 ===")
        
        try:
            if self.query_optimizer:
                await self.query_optimizer.stop_optimizer()
                logger.info("✅ 图查询优化器已停止并清理")
            
            if self.db_manager:
                await self.db_manager.disconnect()
                logger.info("✅ 数据库管理器已关闭")
            
            if neo4j_driver._driver:
                await neo4j_driver.close()
                logger.info("✅ Neo4j连接已关闭")
            
            logger.info("✅ 所有服务资源清理完成")
            
        except Exception as e:
            logger.error(f"❌ 资源清理失败: {e}")
    
    async def run_integration_test(self) -> Dict[str, Any]:
        """运行完整的集成测试流程"""
        logger.info("\n" + "="*60)
        logger.info("开始执行1.3.2到1.4.1集成流程测试")
        logger.info("="*60)
        
        try:
            # 初始化服务
            await self.setup_services()
            
            # 步骤1: 图查询分析
            graph_analysis_result = await self.analyze_database_content()
            
            # 步骤2: OpenAI智能分析
            openai_analysis_result = await self.analyze_with_openai(graph_analysis_result)
            
            # 步骤3: 生成综合报告
            comprehensive_report = await self.generate_comprehensive_report(
                graph_analysis_result, 
                openai_analysis_result
            )
            
            # 输出最终结果
            logger.info("\n" + "="*60)
            logger.info("集成测试完成 - 最终结果")
            logger.info("="*60)
            
            logger.info("\n📊 执行摘要:")
            exec_summary = comprehensive_report['executive_summary']
            logger.info(f"  • 分析事件总数: {exec_summary['total_events_analyzed']}")
            logger.info(f"  • 高优先级事件: {exec_summary['high_priority_events']}")
            logger.info(f"  • 事件关联数: {exec_summary['event_correlations']}")
            logger.info(f"  • 攻击路径数: {exec_summary['attack_paths_detected']}")
            logger.info(f"  • 整体风险评分: {exec_summary['overall_risk_score']:.1f}/10")
            logger.info(f"  • 威胁等级: {exec_summary['threat_level']}")
            
            logger.info("\n🔍 AI分析结果:")
            ai_summary = comprehensive_report['ai_analysis_summary']
            if ai_summary['security_analysis']:
                logger.info(f"  • 安全分析: {ai_summary['security_analysis']['summary'][:100]}...")
            if ai_summary['threat_assessment']:
                logger.info(f"  • 威胁评估: {ai_summary['threat_assessment']['summary'][:100]}...")
            if ai_summary['remediation_advice']:
                logger.info(f"  • 修复建议: {ai_summary['remediation_advice']['summary'][:100]}...")
            
            logger.info("\n⚡ 性能指标:")
            tech_details = comprehensive_report['technical_details']
            logger.info(f"  • 图查询执行数: {tech_details['graph_queries_executed']}")
            logger.info(f"  • AI分析执行数: {tech_details['ai_analyses_performed']}")
            logger.info(f"  • 总处理时间: {tech_details['total_processing_time']:.2f}秒")
            
            logger.info("\n✅ 集成测试成功完成!")
            
            return {
                'status': 'success',
                'test_results': self.test_results,
                'comprehensive_report': comprehensive_report,
                'execution_time': tech_details['total_processing_time']
            }
            
        except Exception as e:
            logger.error(f"\n❌ 集成测试失败: {e}")
            return {
                'status': 'failed',
                'error': str(e),
                'partial_results': self.test_results
            }
        
        finally:
            # 清理资源
            await self.cleanup_services()


# 测试函数
@pytest.mark.asyncio
async def test_integration_flow():
    """测试1.3.2到1.4.1的完整集成流程"""
    test_runner = TestIntegrationFlow()
    result = await test_runner.run_integration_test()
    
    # 验证测试结果
    assert result['status'] == 'success', f"集成测试失败: {result.get('error')}"
    assert 'comprehensive_report' in result
    assert 'test_results' in result
    
    # 验证关键组件
    assert 'graph_analysis' in result['test_results']
    assert 'openai_analysis' in result['test_results']
    assert 'comprehensive_report' in result['test_results']
    
    print("\n🎉 集成流程测试通过!")
    return result


# 独立运行脚本
if __name__ == "__main__":
    async def main():
        """主函数"""
        test_runner = TestIntegrationFlow()
        result = await test_runner.run_integration_test()
        
        # 保存结果到文件
        import json
        with open('/tmp/integration_test_result.json', 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n📄 详细结果已保存到: /tmp/integration_test_result.json")
        return result
    
    # 运行测试
    asyncio.run(main())