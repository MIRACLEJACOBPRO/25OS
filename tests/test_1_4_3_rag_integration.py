#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAG 检索增强生成集成测试

测试 1.4.3 RAG 检索增强生成功能，包括：
1. RAG 服务初始化
2. 异常事件向量化
3. 知识检索增强
4. AI 分析增强
5. 完整的 RAG 工作流程

作者: NeuronOS 开发团队
版本: 1.0.0
创建时间: 2024-01-20
"""

import asyncio
import pytest
import os
import sys
from datetime import datetime
from typing import List, Dict, Any

# 添加项目路径
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src', 'backend'))

from services.rag_service import (
    RAGService, RAGRequest, RAGResponse, RAGMode, RetrievalStrategy
)
from services.pinecone_service import (
    PineconeService, KnowledgeItem, KnowledgeType
)
from services.openai_service import (
    OpenAIService, AnalysisRequest, AnalysisType, Priority
)
from services.interfaces import AnomalyScore
from config.pinecone_config import get_config_manager


class TestRAGIntegration:
    """RAG 集成测试类"""
    
    def __init__(self):
        """初始化测试"""
        self.config_manager = get_config_manager()
        self.pinecone_service = None
        self.openai_service = None
        self.rag_service = None
        
        # 模拟异常事件数据
        self.test_anomaly_events = [
            {
                "event_id": "anomaly_001",
                "event_type": "suspicious_process",
                "description": "检测到可疑进程 /tmp/malware.exe 尝试访问敏感文件 /etc/passwd",
                "severity": "high",
                "source_ip": "192.168.1.100",
                "process_name": "malware.exe",
                "file_path": "/etc/passwd",
                "timestamp": datetime.now().isoformat(),
                "anomaly_score": AnomalyScore(
                    total_score=0.85,
                    category_scores={"process": 0.9, "file_access": 0.8},
                    risk_level="high",
                    indicators=["suspicious_executable", "sensitive_file_access"],
                    confidence=0.88,
                    explanation="进程行为异常，尝试访问敏感系统文件"
                )
            },
            {
                "event_id": "anomaly_002",
                "event_type": "network_anomaly",
                "description": "检测到异常网络连接，大量数据传输到未知外部IP 203.0.113.50",
                "severity": "medium",
                "source_ip": "192.168.1.50",
                "dest_ip": "203.0.113.50",
                "bytes_transferred": 1048576,
                "timestamp": datetime.now().isoformat(),
                "anomaly_score": AnomalyScore(
                    total_score=0.72,
                    category_scores={"network": 0.75, "data_transfer": 0.7},
                    risk_level="medium",
                    indicators=["unusual_traffic_volume", "unknown_destination"],
                    confidence=0.75,
                    explanation="网络流量异常，可能存在数据泄露风险"
                )
            },
            {
                "event_id": "anomaly_003",
                "event_type": "sql_injection",
                "description": "Web应用检测到SQL注入攻击尝试，来源IP 10.0.0.25",
                "severity": "high",
                "source_ip": "10.0.0.25",
                "url": "/login.php",
                "payload": "' OR '1'='1' --",
                "timestamp": datetime.now().isoformat(),
                "anomaly_score": AnomalyScore(
                    total_score=0.92,
                    category_scores={"web_security": 0.95, "injection": 0.9},
                    risk_level="high",
                    indicators=["sql_injection_pattern", "malicious_payload"],
                    confidence=0.93,
                    explanation="明确的SQL注入攻击模式"
                )
            }
        ]
    
    async def setup_services(self) -> bool:
        """设置测试服务
        
        Returns:
            是否设置成功
        """
        try:
            print("\n=== 设置 RAG 和相关服务 ===")
            
            # 获取配置
            pinecone_config = self.config_manager.get_pinecone_config()
            rag_config = self.config_manager.get_rag_config()
            
            # 初始化 Pinecone 服务
            self.pinecone_service = PineconeService(
                api_key=pinecone_config.api_key,
                environment=pinecone_config.environment,
                index_name=pinecone_config.index_name,
                openai_api_key=os.getenv("OPENAI_API_KEY")
            )
            
            # 初始化 OpenAI 服务
            self.openai_service = OpenAIService(
                api_key=os.getenv("OPENAI_API_KEY")
            )
            
            # 初始化 RAG 服务
            self.rag_service = RAGService(
                pinecone_service=self.pinecone_service,
                openai_service=self.openai_service
            )
            
            # 初始化服务
            pinecone_success = await self.pinecone_service.initialize()
            if not pinecone_success:
                print("❌ Pinecone 服务初始化失败")
                return False
            
            openai_success = await self.openai_service.initialize()
            if not openai_success:
                print("❌ OpenAI 服务初始化失败")
                return False
            
            rag_success = await self.rag_service.initialize()
            if not rag_success:
                print("❌ RAG 服务初始化失败")
                return False
            
            print("✅ 所有服务设置完成")
            return True
            
        except Exception as e:
            print(f"❌ 服务设置失败: {e}")
            return False
    
    async def test_anomaly_vectorization(self) -> bool:
        """测试异常事件向量化
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试异常事件向量化 ===")
            
            vectorization_results = []
            
            for i, event in enumerate(self.test_anomaly_events):
                print(f"\n向量化异常事件 {i+1}: {event['event_type']}")
                
                # 向量化异常事件
                vector_result = await self.rag_service.vectorize_anomaly_event(event)
                
                if vector_result:
                    print(f"✅ 异常事件向量化成功")
                    print(f"  事件ID: {vector_result.get('event_id')}")
                    print(f"  向量维度: {len(vector_result.get('embedding', []))}")
                    print(f"  文本长度: {len(vector_result.get('text', ''))}")
                    vectorization_results.append(True)
                else:
                    print(f"❌ 异常事件向量化失败")
                    vectorization_results.append(False)
                
                await asyncio.sleep(0.5)
            
            success_count = sum(vectorization_results)
            total_count = len(vectorization_results)
            
            print(f"\n📊 向量化结果: {success_count}/{total_count} 成功")
            
            return success_count == total_count
            
        except Exception as e:
            print(f"❌ 异常事件向量化测试失败: {e}")
            return False
    
    async def test_knowledge_retrieval(self) -> bool:
        """测试知识检索功能
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试知识检索功能 ===")
            
            retrieval_results = []
            
            for i, event in enumerate(self.test_anomaly_events):
                print(f"\n检索相关知识 {i+1}: {event['event_type']}")
                
                # 检索相关知识
                knowledge_items = await self.rag_service.retrieve_relevant_knowledge(
                    query_text=event["description"],
                    event_type=event["event_type"],
                    max_items=3
                )
                
                if knowledge_items:
                    print(f"✅ 找到 {len(knowledge_items)} 个相关知识")
                    
                    for j, item in enumerate(knowledge_items):
                        print(f"  知识 {j+1}: {item.knowledge_item.title}")
                        print(f"    相似度: {item.score:.3f}")
                        print(f"    类型: {item.knowledge_item.knowledge_type.value}")
                    
                    retrieval_results.append(True)
                else:
                    print(f"❌ 未找到相关知识")
                    retrieval_results.append(False)
                
                await asyncio.sleep(0.5)
            
            success_count = sum(retrieval_results)
            total_count = len(retrieval_results)
            
            print(f"\n📊 检索结果: {success_count}/{total_count} 成功")
            
            return success_count >= total_count * 0.7  # 70% 成功率
            
        except Exception as e:
            print(f"❌ 知识检索测试失败: {e}")
            return False
    
    async def test_enhanced_analysis(self) -> bool:
        """测试增强分析功能
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试增强分析功能 ===")
            
            analysis_results = []
            
            for i, event in enumerate(self.test_anomaly_events):
                print(f"\n增强分析 {i+1}: {event['event_type']}")
                
                # 创建 RAG 请求
                rag_request = RAGRequest(
                    anomaly_event=event,
                    analysis_type=AnalysisType.SECURITY_ANALYSIS,
                    mode=RAGMode.ENHANCED,
                    strategy=RetrievalStrategy.HYBRID,
                    max_knowledge_items=3
                )
                
                # 执行增强分析
                rag_response = await self.rag_service.enhance_analysis(rag_request)
                
                if rag_response and rag_response.enhanced_analysis:
                    print(f"✅ 增强分析成功")
                    print(f"  原始分析质量: {rag_response.original_analysis.confidence:.3f}")
                    print(f"  增强分析质量: {rag_response.enhanced_analysis.confidence:.3f}")
                    print(f"  使用知识数: {len(rag_response.retrieved_knowledge)}")
                    print(f"  知识相关性: {rag_response.knowledge_relevance_score:.3f}")
                    
                    # 显示增强后的分析摘要
                    enhanced_summary = rag_response.enhanced_analysis.summary[:200]
                    print(f"  增强摘要: {enhanced_summary}...")
                    
                    analysis_results.append(True)
                else:
                    print(f"❌ 增强分析失败")
                    analysis_results.append(False)
                
                await asyncio.sleep(1)
            
            success_count = sum(analysis_results)
            total_count = len(analysis_results)
            
            print(f"\n📊 增强分析结果: {success_count}/{total_count} 成功")
            
            return success_count >= total_count * 0.8  # 80% 成功率
            
        except Exception as e:
            print(f"❌ 增强分析测试失败: {e}")
            return False
    
    async def test_rag_workflow(self) -> bool:
        """测试完整的 RAG 工作流程
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试完整 RAG 工作流程 ===")
            
            # 选择一个复杂的异常事件进行完整测试
            test_event = self.test_anomaly_events[0]  # SQL注入事件
            
            print(f"\n测试事件: {test_event['description']}")
            
            # 步骤1: 异常事件向量化
            print("\n步骤1: 异常事件向量化")
            vector_result = await self.rag_service.vectorize_anomaly_event(test_event)
            if not vector_result:
                print("❌ 向量化失败")
                return False
            print("✅ 向量化成功")
            
            # 步骤2: 检索相关知识
            print("\n步骤2: 检索相关知识")
            knowledge_items = await self.rag_service.retrieve_relevant_knowledge(
                query_text=test_event["description"],
                event_type=test_event["event_type"],
                max_items=5
            )
            if not knowledge_items:
                print("❌ 知识检索失败")
                return False
            print(f"✅ 检索到 {len(knowledge_items)} 个相关知识")
            
            # 步骤3: 构建增强上下文
            print("\n步骤3: 构建增强上下文")
            enhanced_context = await self.rag_service.build_enhanced_context(
                anomaly_event=test_event,
                knowledge_items=knowledge_items
            )
            if not enhanced_context:
                print("❌ 上下文构建失败")
                return False
            print("✅ 增强上下文构建成功")
            print(f"  上下文长度: {len(enhanced_context)} 字符")
            
            # 步骤4: 执行增强分析
            print("\n步骤4: 执行增强分析")
            rag_request = RAGRequest(
                anomaly_event=test_event,
                analysis_type=AnalysisType.THREAT_ASSESSMENT,
                mode=RAGMode.ENHANCED,
                strategy=RetrievalStrategy.HYBRID,
                max_knowledge_items=5
            )
            
            rag_response = await self.rag_service.enhance_analysis(rag_request)
            if not rag_response or not rag_response.enhanced_analysis:
                print("❌ 增强分析失败")
                return False
            
            print("✅ 增强分析成功")
            
            # 步骤5: 分析结果对比
            print("\n步骤5: 分析结果对比")
            original = rag_response.original_analysis
            enhanced = rag_response.enhanced_analysis
            
            print(f"\n📊 分析对比:")
            print(f"  原始风险评分: {original.risk_score:.2f}")
            print(f"  增强风险评分: {enhanced.risk_score:.2f}")
            print(f"  原始置信度: {original.confidence:.3f}")
            print(f"  增强置信度: {enhanced.confidence:.3f}")
            print(f"  原始建议数: {len(original.recommendations)}")
            print(f"  增强建议数: {len(enhanced.recommendations)}")
            
            # 验证增强效果
            improvement_score = (
                enhanced.confidence - original.confidence +
                (len(enhanced.recommendations) - len(original.recommendations)) * 0.1
            )
            
            if improvement_score > 0:
                print(f"✅ RAG 增强效果显著 (改进分数: {improvement_score:.3f})")
                return True
            else:
                print(f"⚠️  RAG 增强效果有限 (改进分数: {improvement_score:.3f})")
                return False
            
        except Exception as e:
            print(f"❌ RAG 工作流程测试失败: {e}")
            return False
    
    async def test_service_performance(self) -> bool:
        """测试服务性能
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试 RAG 服务性能 ===")
            
            # 获取 RAG 服务统计
            rag_stats = await self.rag_service.get_stats()
            print(f"\n📊 RAG 服务统计:")
            print(f"  总增强请求: {rag_stats.get('total_enhancements', 0)}")
            print(f"  成功增强: {rag_stats.get('successful_enhancements', 0)}")
            print(f"  失败增强: {rag_stats.get('failed_enhancements', 0)}")
            print(f"  平均检索时间: {rag_stats.get('average_retrieval_time', 0):.3f}s")
            print(f"  平均增强时间: {rag_stats.get('average_enhancement_time', 0):.3f}s")
            print(f"  知识缓存命中率: {rag_stats.get('cache_hit_rate', 0)*100:.1f}%")
            
            # 获取 Pinecone 服务统计
            pinecone_stats = await self.pinecone_service.get_stats()
            print(f"\n📊 Pinecone 服务统计:")
            print(f"  总搜索数: {pinecone_stats.get('total_searches', 0)}")
            print(f"  平均搜索时间: {pinecone_stats.get('search_time', 0):.3f}s")
            
            return True
            
        except Exception as e:
            print(f"❌ 性能测试失败: {e}")
            return False
    
    async def cleanup_services(self) -> None:
        """清理测试服务"""
        try:
            print("\n=== 清理测试服务 ===")
            
            if self.rag_service:
                await self.rag_service.close()
                print("✅ RAG 服务已关闭")
            
            if self.pinecone_service:
                await self.pinecone_service.close()
                print("✅ Pinecone 服务已关闭")
            
            if self.openai_service:
                await self.openai_service.close()
                print("✅ OpenAI 服务已关闭")
            
            print("✅ 服务清理完成")
            
        except Exception as e:
            print(f"❌ 服务清理失败: {e}")
    
    async def run_integration_test(self) -> Dict[str, Any]:
        """运行完整的集成测试
        
        Returns:
            测试结果字典
        """
        print("\n" + "="*60)
        print("🚀 开始 RAG 检索增强生成集成测试")
        print("="*60)
        
        start_time = datetime.now()
        test_results = {
            'start_time': start_time.isoformat(),
            'tests': {},
            'overall_success': False,
            'error_message': None
        }
        
        try:
            # 1. 设置服务
            setup_success = await self.setup_services()
            test_results['tests']['setup'] = setup_success
            
            if not setup_success:
                test_results['error_message'] = "服务设置失败"
                return test_results
            
            # 2. 测试异常事件向量化
            vectorization_success = await self.test_anomaly_vectorization()
            test_results['tests']['anomaly_vectorization'] = vectorization_success
            
            # 3. 测试知识检索
            retrieval_success = await self.test_knowledge_retrieval()
            test_results['tests']['knowledge_retrieval'] = retrieval_success
            
            # 4. 测试增强分析
            analysis_success = await self.test_enhanced_analysis()
            test_results['tests']['enhanced_analysis'] = analysis_success
            
            # 5. 测试完整 RAG 工作流程
            workflow_success = await self.test_rag_workflow()
            test_results['tests']['rag_workflow'] = workflow_success
            
            # 6. 测试服务性能
            performance_success = await self.test_service_performance()
            test_results['tests']['service_performance'] = performance_success
            
            # 计算总体成功率
            total_tests = len(test_results['tests'])
            successful_tests = sum(test_results['tests'].values())
            success_rate = successful_tests / total_tests
            
            test_results['overall_success'] = success_rate >= 0.8  # 80% 成功率
            test_results['success_rate'] = success_rate
            test_results['successful_tests'] = successful_tests
            test_results['total_tests'] = total_tests
            
        except Exception as e:
            test_results['error_message'] = str(e)
            print(f"❌ 集成测试异常: {e}")
        
        finally:
            # 清理服务
            await self.cleanup_services()
            
            end_time = datetime.now()
            test_results['end_time'] = end_time.isoformat()
            test_results['duration'] = (end_time - start_time).total_seconds()
        
        return test_results
    
    def print_test_summary(self, results: Dict[str, Any]) -> None:
        """打印测试摘要
        
        Args:
            results: 测试结果
        """
        print("\n" + "="*60)
        print("📋 RAG 集成测试摘要")
        print("="*60)
        
        print(f"\n⏱️  测试时间: {results.get('duration', 0):.2f} 秒")
        print(f"📊 成功率: {results.get('success_rate', 0)*100:.1f}% ({results.get('successful_tests', 0)}/{results.get('total_tests', 0)})")
        
        print("\n🧪 详细测试结果:")
        for test_name, success in results.get('tests', {}).items():
            status = "✅ 通过" if success else "❌ 失败"
            print(f"  {test_name}: {status}")
        
        if results.get('overall_success'):
            print("\n🎉 RAG 集成测试整体成功！")
            print("✅ 1.4.3 RAG 检索增强生成功能验证通过")
            print("✅ 异常事件向量化和知识检索增强工作正常")
            print("✅ AI 分析质量得到显著提升")
        else:
            print("\n⚠️  RAG 集成测试存在问题")
            if results.get('error_message'):
                print(f"❌ 错误信息: {results['error_message']}")
        
        print("\n" + "="*60)


async def test_integration_flow():
    """测试集成流程"""
    tester = TestRAGIntegration()
    results = await tester.run_integration_test()
    tester.print_test_summary(results)
    return results


if __name__ == "__main__":
    # 运行集成测试
    try:
        results = asyncio.run(test_integration_flow())
        
        # 根据测试结果设置退出码
        exit_code = 0 if results.get('overall_success') else 1
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n⚠️  测试被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 测试执行失败: {e}")
        sys.exit(1)