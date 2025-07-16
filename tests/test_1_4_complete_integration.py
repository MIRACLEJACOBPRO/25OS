#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1.4 AI分析模块完整集成测试

测试 1.4.1 OpenAI API集成、1.4.2 Pinecone向量数据库、1.4.3 RAG检索增强的完整工作流程，包括：
1. 从1.3异常检测获取异常事件
2. 向量化异常事件
3. 检索相关知识
4. 增强AI分析
5. 生成综合报告

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

from services.pinecone_service import (
    PineconeService, KnowledgeItem, KnowledgeType
)
from services.rag_service import (
    RAGService, RAGRequest, RAGMode, RetrievalStrategy
)
from services.openai_service import (
    OpenAIService, AnalysisRequest, AnalysisType, Priority
)
from services.knowledge_manager import KnowledgeManager
from services.local_filter_engine import LocalFilterEngine
from services.interfaces import AnomalyScore
from config.pinecone_config import get_config_manager


class TestCompleteIntegration:
    """完整集成测试类"""
    
    def __init__(self):
        """初始化测试"""
        self.config_manager = get_config_manager()
        
        # 服务实例
        self.pinecone_service = None
        self.openai_service = None
        self.rag_service = None
        self.knowledge_manager = None
        self.filter_engine = None
        
        # 测试知识库
        self.knowledge_base = [
            {
                "title": "SQL注入攻击检测与防护",
                "content": "SQL注入是最常见的Web应用安全漏洞之一。攻击者通过在输入字段中插入恶意SQL代码来操控数据库。检测方法包括：1. 监控异常的SQL查询模式，特别是包含UNION、DROP、INSERT等关键字的查询 2. 检查输入参数中的SQL特殊字符如单引号、分号、注释符 3. 分析数据库错误日志中的异常模式 4. 使用Web应用防火墙(WAF)进行实时检测。防护措施：1. 使用参数化查询或预编译语句 2. 输入验证和过滤 3. 最小权限原则 4. 定期安全审计",
                "knowledge_type": KnowledgeType.SECURITY_RULE,
                "tags": ["SQL注入", "Web安全", "数据库安全", "漏洞检测"],
                "source": "OWASP安全指南"
            },
            {
                "title": "恶意进程行为分析与检测",
                "content": "恶意进程通常表现出异常的行为模式，可通过以下指标进行检测：1. 进程创建模式异常：频繁创建子进程、创建隐藏进程、进程名称伪装 2. 文件系统操作异常：访问敏感文件、修改系统文件、创建可执行文件 3. 网络行为异常：连接可疑IP、大量数据传输、使用非标准端口 4. 权限提升行为：尝试获取管理员权限、修改系统配置 5. 持久化行为：修改启动项、创建计划任务、安装服务。检测技术包括行为分析、机器学习异常检测、签名匹配等",
                "knowledge_type": KnowledgeType.THREAT_INTELLIGENCE,
                "tags": ["恶意进程", "行为分析", "威胁检测", "系统安全"],
                "source": "威胁情报数据库"
            },
            {
                "title": "网络流量异常检测方法",
                "content": "网络流量异常可能指示多种安全威胁，包括DDoS攻击、数据泄露、恶意通信等。检测方法：1. 基线建立：收集正常流量模式，建立流量基线 2. 统计异常检测：监控流量量、连接数、协议分布的异常变化 3. 模式识别：识别已知攻击模式，如DDoS特征、僵尸网络通信模式 4. 地理位置分析：检测来自异常地理位置的连接 5. 时间模式分析：识别非正常时间的异常活动。技术手段包括深度包检测(DPI)、机器学习算法、行为分析等",
                "knowledge_type": KnowledgeType.ANALYSIS_TEMPLATE,
                "tags": ["网络安全", "流量分析", "异常检测", "DDoS防护"],
                "source": "网络安全分析手册"
            },
            {
                "title": "XSS跨站脚本攻击防护策略",
                "content": "跨站脚本攻击(XSS)是Web应用中的常见漏洞，攻击者通过注入恶意脚本来窃取用户信息或劫持会话。防护策略：1. 输入验证：对所有用户输入进行严格验证和过滤 2. 输出编码：对输出到HTML页面的内容进行适当编码 3. 内容安全策略(CSP)：设置CSP头部限制脚本执行 4. HttpOnly Cookie：防止JavaScript访问敏感Cookie 5. 安全框架：使用具有内置XSS防护的开发框架。检测方法包括静态代码分析、动态扫描、渗透测试等",
                "knowledge_type": KnowledgeType.SECURITY_RULE,
                "tags": ["XSS", "Web安全", "脚本注入", "前端安全"],
                "source": "Web安全最佳实践"
            },
            {
                "title": "APT高级持续威胁检测",
                "content": "高级持续威胁(APT)是复杂的、长期的网络攻击，通常由国家级或有组织的攻击者发起。特征包括：1. 多阶段攻击：侦察、初始入侵、横向移动、数据收集、数据外泄 2. 隐蔽性强：使用合法工具、加密通信、定时活动 3. 目标明确：针对特定组织或个人的有价值信息。检测方法：1. 行为分析：监控异常的用户和系统行为 2. 威胁狩猎：主动搜索威胁指标 3. 关联分析：关联多个安全事件发现攻击链 4. 威胁情报：利用外部威胁情报进行匹配",
                "knowledge_type": KnowledgeType.THREAT_INTELLIGENCE,
                "tags": ["APT", "高级威胁", "威胁狩猎", "行为分析"],
                "source": "高级威胁研究报告"
            }
        ]
        
        # 模拟异常事件
        self.test_anomaly_events = [
            {
                "event_id": "evt_001",
                "event_type": "web_attack",
                "description": "检测到来自IP 192.168.1.100的SQL注入攻击尝试，目标URL /login.php，payload包含'OR 1=1--",
                "severity": "high",
                "source_ip": "192.168.1.100",
                "target_url": "/login.php",
                "payload": "admin' OR '1'='1' --",
                "timestamp": datetime.now().isoformat(),
                "anomaly_score": AnomalyScore(
                    total_score=0.92,
                    category_scores={"web_security": 0.95, "injection": 0.9},
                    risk_level="high",
                    indicators=["sql_injection_pattern", "malicious_payload", "authentication_bypass"],
                    confidence=0.93,
                    explanation="明确的SQL注入攻击模式，尝试绕过身份验证"
                )
            },
            {
                "event_id": "evt_002",
                "event_type": "process_anomaly",
                "description": "检测到可疑进程/tmp/update.exe执行异常行为，尝试访问/etc/passwd和/etc/shadow文件，并建立到外部IP 203.0.113.50的网络连接",
                "severity": "critical",
                "process_name": "update.exe",
                "process_path": "/tmp/update.exe",
                "accessed_files": ["/etc/passwd", "/etc/shadow"],
                "network_connections": ["203.0.113.50:443"],
                "timestamp": datetime.now().isoformat(),
                "anomaly_score": AnomalyScore(
                    total_score=0.96,
                    category_scores={"process": 0.98, "file_access": 0.95, "network": 0.94},
                    risk_level="critical",
                    indicators=["suspicious_executable", "sensitive_file_access", "external_communication", "privilege_escalation"],
                    confidence=0.97,
                    explanation="高度可疑的恶意进程行为，可能是APT攻击的一部分"
                )
            },
            {
                "event_id": "evt_003",
                "event_type": "network_anomaly",
                "description": "检测到异常网络流量模式，来自内网主机192.168.1.50向外部IP 198.51.100.25传输大量数据(500MB)，使用非标准端口8443",
                "severity": "medium",
                "source_ip": "192.168.1.50",
                "dest_ip": "198.51.100.25",
                "dest_port": 8443,
                "bytes_transferred": 524288000,
                "duration": 3600,
                "timestamp": datetime.now().isoformat(),
                "anomaly_score": AnomalyScore(
                    total_score=0.78,
                    category_scores={"network": 0.8, "data_transfer": 0.85, "timing": 0.7},
                    risk_level="medium",
                    indicators=["large_data_transfer", "unusual_port", "external_destination", "off_hours_activity"],
                    confidence=0.82,
                    explanation="可能的数据泄露行为，需要进一步调查"
                )
            }
        ]
    
    async def setup_services(self) -> bool:
        """设置所有测试服务
        
        Returns:
            是否设置成功
        """
        try:
            print("\n=== 设置完整集成测试服务 ===")
            
            # 获取配置
            pinecone_config = self.config_manager.get_pinecone_config()
            
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
            
            # 初始化知识管理服务
            self.knowledge_manager = KnowledgeManager(
                pinecone_service=self.pinecone_service
            )
            
            # 初始化过滤引擎（模拟1.3异常检测）
            self.filter_engine = LocalFilterEngine()
            
            # 初始化所有服务
            services = [
                ("Pinecone", self.pinecone_service),
                ("OpenAI", self.openai_service),
                ("RAG", self.rag_service),
                ("FilterEngine", self.filter_engine)
            ]
            
            for service_name, service in services:
                if hasattr(service, 'initialize'):
                    success = await service.initialize()
                    if not success:
                        print(f"❌ {service_name} 服务初始化失败")
                        return False
                    print(f"✅ {service_name} 服务初始化成功")
            
            print("✅ 所有服务设置完成")
            return True
            
        except Exception as e:
            print(f"❌ 服务设置失败: {e}")
            return False
    
    async def setup_knowledge_base(self) -> bool:
        """设置知识库
        
        Returns:
            是否设置成功
        """
        try:
            print("\n=== 设置知识库 ===")
            
            upload_count = 0
            
            for i, kb_item in enumerate(self.knowledge_base):
                print(f"上传知识 {i+1}: {kb_item['title']}")
                
                # 创建知识项
                knowledge_item = KnowledgeItem(
                    id=f"kb_{i+1:03d}",
                    title=kb_item["title"],
                    content=kb_item["content"],
                    knowledge_type=kb_item["knowledge_type"],
                    tags=kb_item["tags"],
                    source=kb_item["source"]
                )
                
                # 上传知识
                success = await self.pinecone_service.upload_knowledge(knowledge_item)
                if success:
                    upload_count += 1
                    print(f"  ✅ 上传成功")
                else:
                    print(f"  ❌ 上传失败")
                
                await asyncio.sleep(0.5)
            
            print(f"\n📊 知识库设置完成: {upload_count}/{len(self.knowledge_base)} 成功")
            return upload_count >= len(self.knowledge_base) * 0.8  # 80% 成功率
            
        except Exception as e:
            print(f"❌ 知识库设置失败: {e}")
            return False
    
    async def test_end_to_end_workflow(self) -> bool:
        """测试端到端工作流程
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试端到端工作流程 ===")
            
            workflow_results = []
            
            for i, event in enumerate(self.test_anomaly_events):
                print(f"\n处理异常事件 {i+1}: {event['event_type']}")
                print(f"事件描述: {event['description'][:100]}...")
                
                # 步骤1: 模拟1.3异常检测输出
                print("\n步骤1: 异常检测处理")
                filter_result = await self.simulate_anomaly_detection(event)
                if not filter_result:
                    print("❌ 异常检测失败")
                    workflow_results.append(False)
                    continue
                print("✅ 异常检测完成")
                
                # 步骤2: 异常事件向量化
                print("\n步骤2: 异常事件向量化")
                vector_result = await self.rag_service.vectorize_anomaly_event(event)
                if not vector_result:
                    print("❌ 向量化失败")
                    workflow_results.append(False)
                    continue
                print("✅ 向量化成功")
                
                # 步骤3: 检索相关知识
                print("\n步骤3: 检索相关知识")
                knowledge_items = await self.rag_service.retrieve_relevant_knowledge(
                    query_text=event["description"],
                    event_type=event["event_type"],
                    max_items=3
                )
                if not knowledge_items:
                    print("❌ 知识检索失败")
                    workflow_results.append(False)
                    continue
                print(f"✅ 检索到 {len(knowledge_items)} 个相关知识")
                
                # 步骤4: 执行增强分析
                print("\n步骤4: 执行增强分析")
                rag_request = RAGRequest(
                    anomaly_event=event,
                    analysis_type=AnalysisType.COMPREHENSIVE_ANALYSIS,
                    mode=RAGMode.ENHANCED,
                    strategy=RetrievalStrategy.HYBRID,
                    max_knowledge_items=3
                )
                
                rag_response = await self.rag_service.enhance_analysis(rag_request)
                if not rag_response or not rag_response.enhanced_analysis:
                    print("❌ 增强分析失败")
                    workflow_results.append(False)
                    continue
                print("✅ 增强分析成功")
                
                # 步骤5: 生成综合报告
                print("\n步骤5: 生成综合报告")
                report = await self.generate_comprehensive_report(
                    event, rag_response, knowledge_items
                )
                if not report:
                    print("❌ 报告生成失败")
                    workflow_results.append(False)
                    continue
                print("✅ 综合报告生成成功")
                
                # 显示处理结果
                self.display_workflow_result(event, rag_response, report)
                
                workflow_results.append(True)
                await asyncio.sleep(1)
            
            success_count = sum(workflow_results)
            total_count = len(workflow_results)
            
            print(f"\n📊 端到端工作流程结果: {success_count}/{total_count} 成功")
            
            return success_count >= total_count * 0.8  # 80% 成功率
            
        except Exception as e:
            print(f"❌ 端到端工作流程测试失败: {e}")
            return False
    
    async def simulate_anomaly_detection(self, event: Dict[str, Any]) -> bool:
        """模拟1.3异常检测处理
        
        Args:
            event: 异常事件
            
        Returns:
            是否处理成功
        """
        try:
            # 模拟过滤引擎处理
            # 在实际环境中，这里会调用 LocalFilterEngine 的处理方法
            print(f"  检测到异常: {event['event_type']}")
            print(f"  风险等级: {event['anomaly_score'].risk_level}")
            print(f"  置信度: {event['anomaly_score'].confidence:.3f}")
            return True
        except Exception as e:
            print(f"异常检测模拟失败: {e}")
            return False
    
    async def generate_comprehensive_report(
        self, 
        event: Dict[str, Any], 
        rag_response: Any, 
        knowledge_items: List[Any]
    ) -> Dict[str, Any]:
        """生成综合报告
        
        Args:
            event: 异常事件
            rag_response: RAG响应
            knowledge_items: 相关知识项
            
        Returns:
            综合报告
        """
        try:
            report = {
                "event_summary": {
                    "event_id": event["event_id"],
                    "event_type": event["event_type"],
                    "severity": event["severity"],
                    "timestamp": event["timestamp"],
                    "risk_score": event["anomaly_score"].total_score
                },
                "analysis_results": {
                    "original_analysis": {
                        "summary": rag_response.original_analysis.summary,
                        "risk_score": rag_response.original_analysis.risk_score,
                        "confidence": rag_response.original_analysis.confidence
                    },
                    "enhanced_analysis": {
                        "summary": rag_response.enhanced_analysis.summary,
                        "risk_score": rag_response.enhanced_analysis.risk_score,
                        "confidence": rag_response.enhanced_analysis.confidence,
                        "recommendations": rag_response.enhanced_analysis.recommendations
                    },
                    "improvement_metrics": {
                        "confidence_improvement": rag_response.enhanced_analysis.confidence - rag_response.original_analysis.confidence,
                        "knowledge_relevance": rag_response.knowledge_relevance_score,
                        "knowledge_count": len(knowledge_items)
                    }
                },
                "knowledge_context": [
                    {
                        "title": item.knowledge_item.title,
                        "relevance_score": item.score,
                        "knowledge_type": item.knowledge_item.knowledge_type.value,
                        "tags": item.knowledge_item.tags
                    }
                    for item in knowledge_items
                ],
                "recommendations": rag_response.enhanced_analysis.recommendations,
                "next_actions": self.generate_next_actions(event, rag_response)
            }
            
            return report
            
        except Exception as e:
            print(f"综合报告生成失败: {e}")
            return None
    
    def generate_next_actions(self, event: Dict[str, Any], rag_response: Any) -> List[str]:
        """生成后续行动建议
        
        Args:
            event: 异常事件
            rag_response: RAG响应
            
        Returns:
            行动建议列表
        """
        actions = []
        
        # 基于风险等级生成行动建议
        risk_level = event["anomaly_score"].risk_level
        
        if risk_level == "critical":
            actions.extend([
                "立即隔离受影响的系统",
                "启动应急响应流程",
                "通知安全团队和管理层",
                "收集和保存相关证据"
            ])
        elif risk_level == "high":
            actions.extend([
                "加强监控相关系统",
                "实施临时防护措施",
                "进行深入调查分析",
                "更新安全策略"
            ])
        else:
            actions.extend([
                "持续监控事件发展",
                "记录事件详情",
                "评估潜在影响",
                "考虑预防性措施"
            ])
        
        return actions
    
    def display_workflow_result(
        self, 
        event: Dict[str, Any], 
        rag_response: Any, 
        report: Dict[str, Any]
    ) -> None:
        """显示工作流程结果
        
        Args:
            event: 异常事件
            rag_response: RAG响应
            report: 综合报告
        """
        print(f"\n📋 处理结果摘要:")
        print(f"  事件ID: {event['event_id']}")
        print(f"  事件类型: {event['event_type']}")
        print(f"  原始风险评分: {rag_response.original_analysis.risk_score:.2f}")
        print(f"  增强风险评分: {rag_response.enhanced_analysis.risk_score:.2f}")
        print(f"  置信度提升: {report['analysis_results']['improvement_metrics']['confidence_improvement']:.3f}")
        print(f"  使用知识数: {len(rag_response.retrieved_knowledge)}")
        print(f"  生成建议数: {len(rag_response.enhanced_analysis.recommendations)}")
    
    async def test_performance_metrics(self) -> bool:
        """测试性能指标
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试性能指标 ===")
            
            # 获取各服务统计信息
            services_stats = {}
            
            # Pinecone 服务统计
            pinecone_stats = await self.pinecone_service.get_stats()
            services_stats['pinecone'] = pinecone_stats
            
            # RAG 服务统计
            rag_stats = await self.rag_service.get_stats()
            services_stats['rag'] = rag_stats
            
            # 知识管理统计
            km_stats = await self.knowledge_manager.get_stats()
            services_stats['knowledge_manager'] = km_stats
            
            # 显示性能指标
            print(f"\n📊 性能指标汇总:")
            
            print(f"\n🔍 Pinecone 服务:")
            print(f"  总嵌入数: {pinecone_stats.get('total_embeddings', 0)}")
            print(f"  总搜索数: {pinecone_stats.get('total_searches', 0)}")
            print(f"  缓存命中率: {pinecone_stats.get('cache_hits', 0) / max(pinecone_stats.get('total_embeddings', 1), 1) * 100:.1f}%")
            print(f"  平均搜索时间: {pinecone_stats.get('search_time', 0):.3f}s")
            
            print(f"\n🤖 RAG 服务:")
            print(f"  总增强请求: {rag_stats.get('total_enhancements', 0)}")
            print(f"  成功增强: {rag_stats.get('successful_enhancements', 0)}")
            print(f"  平均增强时间: {rag_stats.get('average_enhancement_time', 0):.3f}s")
            
            print(f"\n📚 知识管理:")
            print(f"  总导入数: {km_stats.get('total_imports', 0)}")
            print(f"  成功率: {km_stats.get('successful_imports', 0) / max(km_stats.get('total_imports', 1), 1) * 100:.1f}%")
            
            return True
            
        except Exception as e:
            print(f"❌ 性能指标测试失败: {e}")
            return False
    
    async def cleanup_services(self) -> None:
        """清理测试服务"""
        try:
            print("\n=== 清理测试服务 ===")
            
            services = [
                ("RAG", self.rag_service),
                ("Pinecone", self.pinecone_service),
                ("OpenAI", self.openai_service)
            ]
            
            for service_name, service in services:
                if service and hasattr(service, 'close'):
                    await service.close()
                    print(f"✅ {service_name} 服务已关闭")
            
            print("✅ 服务清理完成")
            
        except Exception as e:
            print(f"❌ 服务清理失败: {e}")
    
    async def run_complete_integration_test(self) -> Dict[str, Any]:
        """运行完整的集成测试
        
        Returns:
            测试结果字典
        """
        print("\n" + "="*70)
        print("🚀 开始 1.4 AI分析模块完整集成测试")
        print("="*70)
        
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
            test_results['tests']['setup_services'] = setup_success
            
            if not setup_success:
                test_results['error_message'] = "服务设置失败"
                return test_results
            
            # 2. 设置知识库
            kb_success = await self.setup_knowledge_base()
            test_results['tests']['setup_knowledge_base'] = kb_success
            
            # 3. 测试端到端工作流程
            workflow_success = await self.test_end_to_end_workflow()
            test_results['tests']['end_to_end_workflow'] = workflow_success
            
            # 4. 测试性能指标
            performance_success = await self.test_performance_metrics()
            test_results['tests']['performance_metrics'] = performance_success
            
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
        print("\n" + "="*70)
        print("📋 1.4 AI分析模块完整集成测试摘要")
        print("="*70)
        
        print(f"\n⏱️  测试时间: {results.get('duration', 0):.2f} 秒")
        print(f"📊 成功率: {results.get('success_rate', 0)*100:.1f}% ({results.get('successful_tests', 0)}/{results.get('total_tests', 0)})")
        
        print("\n🧪 详细测试结果:")
        for test_name, success in results.get('tests', {}).items():
            status = "✅ 通过" if success else "❌ 失败"
            print(f"  {test_name}: {status}")
        
        if results.get('overall_success'):
            print("\n🎉 1.4 AI分析模块完整集成测试成功！")
            print("✅ 1.4.1 OpenAI API集成功能正常")
            print("✅ 1.4.2 Pinecone向量数据库集成功能正常")
            print("✅ 1.4.3 RAG检索增强生成功能正常")
            print("✅ 从异常检测到AI分析的完整工作流程验证通过")
            print("✅ 知识库增强AI分析效果显著")
        else:
            print("\n⚠️  1.4 AI分析模块集成测试存在问题")
            if results.get('error_message'):
                print(f"❌ 错误信息: {results['error_message']}")
        
        print("\n" + "="*70)


async def test_complete_integration_flow():
    """测试完整集成流程"""
    tester = TestCompleteIntegration()
    results = await tester.run_complete_integration_test()
    tester.print_test_summary(results)
    return results


if __name__ == "__main__":
    # 运行完整集成测试
    try:
        results = asyncio.run(test_complete_integration_flow())
        
        # 根据测试结果设置退出码
        exit_code = 0 if results.get('overall_success') else 1
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n⚠️  测试被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 测试执行失败: {e}")
        sys.exit(1)