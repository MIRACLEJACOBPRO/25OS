#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAG服务测试脚本
测试Pinecone向量数据库和RAG检索增强功能
"""

import asyncio
import sys
import os
from datetime import datetime
from typing import List, Dict, Any

# 添加项目路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src', 'backend'))

from models.knowledge import KnowledgeItem, KnowledgeType
from models.events import StandardizedEvent, Priority
from services.pinecone_service import PineconeService
from services.rag_service import RAGService
from services.knowledge_manager import KnowledgeManager

class RAGServiceTester:
    """RAG服务测试器"""
    
    def __init__(self):
        self.pinecone_service = None
        self.rag_service = None
        self.knowledge_manager = None
        
    async def setup_services(self) -> bool:
        """初始化服务"""
        try:
            print("🔧 初始化服务...")
            
            # 初始化Pinecone服务
            self.pinecone_service = PineconeService()
            pinecone_init = await self.pinecone_service.initialize()
            if not pinecone_init:
                print("❌ Pinecone服务初始化失败")
                return False
            print("✅ Pinecone服务初始化成功")
            
            # 初始化RAG服务
            self.rag_service = RAGService()
            rag_init = await self.rag_service.initialize()
            if not rag_init:
                print("❌ RAG服务初始化失败")
                return False
            print("✅ RAG服务初始化成功")
            
            # 初始化知识管理器
            self.knowledge_manager = KnowledgeManager(self.pinecone_service)
            print("✅ 知识管理器初始化成功")
            
            return True
            
        except Exception as e:
            print(f"❌ 服务初始化失败: {e}")
            return False
    
    def create_test_knowledge_items(self) -> List[KnowledgeItem]:
        """创建测试知识项"""
        knowledge_items = [
            KnowledgeItem(
                id="security_rule_001",
                title="SSH暴力破解检测规则",
                content="当检测到短时间内多次SSH登录失败时，应立即阻止源IP并记录事件。建议设置阈值为5分钟内失败3次。",
                knowledge_type=KnowledgeType.SECURITY_RULE,
                tags=["ssh", "brute_force", "authentication", "network_security"],
                metadata={"severity": "high", "category": "authentication"},
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            KnowledgeItem(
                id="threat_pattern_001",
                title="恶意软件网络通信模式",
                content="恶意软件通常会与C&C服务器建立持续连接，特征包括：定期心跳包、加密通信、异常端口使用。",
                knowledge_type=KnowledgeType.THREAT_PATTERN,
                tags=["malware", "c2", "network_traffic", "encryption"],
                metadata={"threat_type": "malware", "confidence": 0.9},
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            KnowledgeItem(
                id="incident_case_001",
                title="APT攻击案例分析",
                content="某企业遭受APT攻击，攻击者通过钓鱼邮件获得初始访问权限，然后进行横向移动和数据窃取。",
                knowledge_type=KnowledgeType.INCIDENT_CASE,
                tags=["apt", "phishing", "lateral_movement", "data_exfiltration"],
                metadata={"industry": "finance", "impact": "high"},
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            KnowledgeItem(
                id="remediation_guide_001",
                title="恶意软件清除指南",
                content="发现恶意软件后的处理步骤：1.隔离受感染系统 2.分析恶意软件样本 3.清除恶意文件 4.修复系统漏洞 5.监控后续活动",
                knowledge_type=KnowledgeType.REMEDIATION_GUIDE,
                tags=["malware_removal", "incident_response", "system_recovery"],
                metadata={"difficulty": "medium", "time_required": "2-4 hours"},
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            KnowledgeItem(
                id="vulnerability_info_001",
                title="CVE-2023-12345 远程代码执行漏洞",
                content="该漏洞影响Apache服务器，允许攻击者通过特制请求执行任意代码。CVSS评分9.8，建议立即更新到最新版本。",
                knowledge_type=KnowledgeType.VULNERABILITY_INFO,
                tags=["apache", "rce", "critical", "cve-2023-12345"],
                metadata={"cvss_score": 9.8, "affected_versions": "2.4.0-2.4.50"},
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        ]
        
        return knowledge_items
    
    def create_test_events(self) -> List[StandardizedEvent]:
        """创建测试事件"""
        events = [
            StandardizedEvent(
                id="event_001",
                timestamp=datetime.now(),
                rule_name="SSH Brute Force Attack",
                output="Multiple failed SSH login attempts from 192.168.1.100",
                priority=Priority.HIGH,
                source_ip="192.168.1.100",
                destination_ip="10.0.0.50",
                port=22,
                user="admin",
                event_type="authentication_failure"
            ),
            StandardizedEvent(
                id="event_002",
                timestamp=datetime.now(),
                rule_name="Suspicious Network Traffic",
                output="Encrypted communication to unknown C&C server",
                priority=Priority.CRITICAL,
                source_ip="10.0.0.25",
                destination_ip="203.0.113.10",
                port=8080,
                process_name="malware.exe",
                event_type="network_anomaly"
            )
        ]
        
        return events
    
    async def test_pinecone_service(self) -> bool:
        """测试Pinecone服务"""
        try:
            print("\n🧪 测试Pinecone服务...")
            
            # 测试嵌入向量生成
            test_text = "SSH暴力破解攻击检测"
            embedding = await self.pinecone_service.generate_embedding(test_text)
            if len(embedding) != 1024:
                print(f"❌ 嵌入向量维度错误: {len(embedding)}")
                return False
            print(f"✅ 嵌入向量生成成功，维度: {len(embedding)}")
            
            # 测试知识上传
            knowledge_items = self.create_test_knowledge_items()
            upload_result = await self.pinecone_service.upload_knowledge(knowledge_items)
            if upload_result['successful_uploads'] != len(knowledge_items):
                print(f"❌ 知识上传失败: {upload_result}")
                return False
            print(f"✅ 知识上传成功: {upload_result['successful_uploads']}个")
            
            # 测试知识搜索
            search_results = await self.pinecone_service.search_knowledge_simple(
                query_text="SSH攻击检测",
                top_k=3
            )
            if not search_results:
                print("❌ 知识搜索无结果")
                return False
            print(f"✅ 知识搜索成功: {len(search_results)}个结果")
            
            # 显示搜索结果
            for i, result in enumerate(search_results[:2]):
                print(f"   结果{i+1}: {result.knowledge_item.title} (相似度: {result.similarity_score:.3f})")
            
            return True
            
        except Exception as e:
            print(f"❌ Pinecone服务测试失败: {e}")
            return False
    
    async def test_rag_service(self) -> bool:
        """测试RAG服务"""
        try:
            print("\n🧪 测试RAG服务...")
            
            # 测试事件向量化
            test_events = self.create_test_events()
            event = test_events[0]
            
            vectorized_query = await self.rag_service.vectorize_anomaly_event(event, {})
            if not vectorized_query:
                print("❌ 事件向量化失败")
                return False
            print(f"✅ 事件向量化成功: {vectorized_query[:100]}...")
            
            # 测试知识检索
            relevant_knowledge = await self.rag_service.retrieve_relevant_knowledge(
                query_text="SSH暴力破解攻击",
                event_type="authentication_failure",
                max_items=5
            )
            if not relevant_knowledge:
                print("❌ 相关知识检索无结果")
                return False
            print(f"✅ 相关知识检索成功: {len(relevant_knowledge)}个结果")
            
            # 测试知识增强
            enhanced_result = await self.rag_service.enhance_with_knowledge(
                anomaly_event=event,
                analysis_type="security_analysis"
            )
            if not enhanced_result:
                print("❌ 知识增强失败")
                return False
            print("✅ 知识增强成功")
            
            # 显示增强结果摘要
            if isinstance(enhanced_result, dict):
                metadata = enhanced_result.get('enhancement_metadata', {})
                print(f"   知识来源数量: {metadata.get('knowledge_sources', 0)}")
                print(f"   置信度提升: {metadata.get('confidence_boost', 0):.3f}")
                print(f"   上下文摘要: {metadata.get('context_summary', 'N/A')[:100]}...")
            
            return True
            
        except Exception as e:
            print(f"❌ RAG服务测试失败: {e}")
            return False
    
    async def test_knowledge_manager(self) -> bool:
        """测试知识管理器"""
        try:
            print("\n🧪 测试知识管理器...")
            
            # 测试创建知识项
            knowledge_item = await self.knowledge_manager.create_knowledge_item(
                title="测试安全规则",
                content="这是一个测试用的安全规则，用于验证知识管理功能。",
                knowledge_type=KnowledgeType.SECURITY_RULE,
                tags=["test", "security"],
                metadata={"test": True}
            )
            if not knowledge_item:
                print("❌ 创建知识项失败")
                return False
            print(f"✅ 创建知识项成功: {knowledge_item.id}")
            
            # 测试获取统计信息
            stats = await self.knowledge_manager.get_statistics()
            if not stats:
                print("❌ 获取统计信息失败")
                return False
            print("✅ 获取统计信息成功")
            print(f"   知识管理器统计: {stats.get('knowledge_manager_stats', {})}")
            print(f"   Pinecone统计: {stats.get('pinecone_stats', {})}")
            
            return True
            
        except Exception as e:
            print(f"❌ 知识管理器测试失败: {e}")
            return False
    
    async def run_all_tests(self) -> bool:
        """运行所有测试"""
        print("🚀 开始RAG服务测试")
        print("=" * 50)
        
        # 初始化服务
        if not await self.setup_services():
            return False
        
        # 运行测试
        tests = [
            ("Pinecone服务", self.test_pinecone_service),
            ("RAG服务", self.test_rag_service),
            ("知识管理器", self.test_knowledge_manager)
        ]
        
        passed_tests = 0
        total_tests = len(tests)
        
        for test_name, test_func in tests:
            try:
                if await test_func():
                    passed_tests += 1
                    print(f"✅ {test_name}测试通过")
                else:
                    print(f"❌ {test_name}测试失败")
            except Exception as e:
                print(f"❌ {test_name}测试异常: {e}")
        
        # 测试结果汇总
        print("\n" + "=" * 50)
        print(f"📊 测试结果汇总: {passed_tests}/{total_tests} 通过")
        
        if passed_tests == total_tests:
            print("🎉 所有测试通过！RAG服务功能正常")
            return True
        else:
            print("⚠️  部分测试失败，请检查配置和服务状态")
            return False
    
    async def cleanup(self):
        """清理资源"""
        try:
            if self.rag_service:
                await self.rag_service.close()
            if self.pinecone_service:
                await self.pinecone_service.close()
            print("🧹 资源清理完成")
        except Exception as e:
            print(f"⚠️  资源清理失败: {e}")

async def main():
    """主函数"""
    tester = RAGServiceTester()
    
    try:
        success = await tester.run_all_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n⏹️  测试被用户中断")
        return 1
    except Exception as e:
        print(f"\n💥 测试过程中发生异常: {e}")
        return 1
    finally:
        await tester.cleanup()

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)