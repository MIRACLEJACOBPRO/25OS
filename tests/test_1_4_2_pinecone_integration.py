#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pinecone 向量数据库集成测试

测试 1.4.2 Pinecone 向量数据库集成功能，包括：
1. Pinecone 服务初始化
2. 知识向量化和上传
3. 向量搜索和检索
4. 知识管理功能

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
    PineconeService, KnowledgeItem, KnowledgeType, 
    VectorSearchRequest, SearchResult, EmbeddingModel
)
from services.knowledge_manager import KnowledgeManager, ImportFormat, ValidationLevel
from config.pinecone_config import get_config_manager


class TestPineconeIntegration:
    """Pinecone 集成测试类"""
    
    def __init__(self):
        """初始化测试"""
        self.config_manager = get_config_manager()
        self.pinecone_service = None
        self.knowledge_manager = None
        
        # 测试数据
        self.test_knowledge_items = [
            {
                "title": "SQL注入攻击检测规则",
                "content": "SQL注入是一种常见的Web应用安全漏洞，攻击者通过在输入字段中插入恶意SQL代码来操控数据库。检测方法包括：1. 监控异常的SQL查询模式 2. 检查输入参数中的SQL关键字 3. 分析数据库错误日志 4. 使用参数化查询防护",
                "knowledge_type": KnowledgeType.SECURITY_RULE,
                "tags": ["SQL注入", "Web安全", "数据库安全"],
                "source": "安全规则库"
            },
            {
                "title": "异常进程行为分析",
                "content": "异常进程行为可能表明系统受到攻击或恶意软件感染。关键指标包括：1. 进程创建频率异常 2. 未知进程执行 3. 进程权限提升 4. 网络连接异常 5. 文件系统访问模式异常。建议使用行为分析和机器学习算法进行检测",
                "knowledge_type": KnowledgeType.THREAT_INTELLIGENCE,
                "tags": ["进程监控", "行为分析", "恶意软件"],
                "source": "威胁情报"
            },
            {
                "title": "网络流量异常检测",
                "content": "网络流量异常可能指示DDoS攻击、数据泄露或恶意通信。检测方法：1. 流量基线建立 2. 异常流量模式识别 3. 协议异常分析 4. 地理位置异常检测 5. 时间模式分析。推荐使用统计分析和深度学习方法",
                "knowledge_type": KnowledgeType.ANALYSIS_TEMPLATE,
                "tags": ["网络安全", "流量分析", "DDoS"],
                "source": "分析模板"
            }
        ]
    
    async def setup_services(self) -> bool:
        """设置测试服务
        
        Returns:
            是否设置成功
        """
        try:
            print("\n=== 设置 Pinecone 和知识管理服务 ===")
            
            # 获取配置
            pinecone_config = self.config_manager.get_pinecone_config()
            embedding_config = self.config_manager.get_embedding_config()
            km_config = self.config_manager.get_knowledge_management_config()
            
            # 初始化 Pinecone 服务
            self.pinecone_service = PineconeService(
                api_key=pinecone_config.api_key,
                environment=pinecone_config.environment,
                index_name=pinecone_config.index_name,
                openai_api_key=os.getenv("OPENAI_API_KEY")
            )
            
            # 初始化知识管理服务
            self.knowledge_manager = KnowledgeManager(
                pinecone_service=self.pinecone_service
            )
            
            # 初始化服务
            pinecone_success = await self.pinecone_service.initialize()
            if not pinecone_success:
                print("❌ Pinecone 服务初始化失败")
                return False
            
            print("✅ 服务设置完成")
            return True
            
        except Exception as e:
            print(f"❌ 服务设置失败: {e}")
            return False
    
    async def test_knowledge_upload(self) -> bool:
        """测试知识上传功能
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试知识上传功能 ===")
            
            upload_results = []
            
            for i, item_data in enumerate(self.test_knowledge_items):
                print(f"\n上传知识 {i+1}: {item_data['title']}")
                
                # 创建知识项
                knowledge_item = KnowledgeItem(
                    id=f"test_knowledge_{i+1}",
                    title=item_data["title"],
                    content=item_data["content"],
                    knowledge_type=item_data["knowledge_type"],
                    tags=item_data["tags"],
                    source=item_data["source"]
                )
                
                # 上传知识
                success = await self.pinecone_service.upload_knowledge(knowledge_item)
                upload_results.append(success)
                
                if success:
                    print(f"✅ 知识上传成功: {knowledge_item.title}")
                else:
                    print(f"❌ 知识上传失败: {knowledge_item.title}")
                
                # 短暂延迟
                await asyncio.sleep(1)
            
            success_count = sum(upload_results)
            total_count = len(upload_results)
            
            print(f"\n📊 上传结果: {success_count}/{total_count} 成功")
            
            return success_count == total_count
            
        except Exception as e:
            print(f"❌ 知识上传测试失败: {e}")
            return False
    
    async def test_knowledge_search(self) -> bool:
        """测试知识搜索功能
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试知识搜索功能 ===")
            
            # 测试查询
            test_queries = [
                {
                    "query": "SQL注入攻击如何检测和防护",
                    "expected_type": KnowledgeType.SECURITY_RULE,
                    "expected_keywords": ["SQL", "注入", "检测"]
                },
                {
                    "query": "进程行为异常分析方法",
                    "expected_type": KnowledgeType.THREAT_INTELLIGENCE,
                    "expected_keywords": ["进程", "行为", "异常"]
                },
                {
                    "query": "网络流量监控和分析",
                    "expected_type": KnowledgeType.ANALYSIS_TEMPLATE,
                    "expected_keywords": ["网络", "流量", "分析"]
                }
            ]
            
            search_results = []
            
            for i, query_data in enumerate(test_queries):
                print(f"\n搜索测试 {i+1}: {query_data['query']}")
                
                # 创建搜索请求
                search_request = VectorSearchRequest(
                    query_text=query_data["query"],
                    top_k=3,
                    similarity_threshold=0.7
                )
                
                # 执行搜索
                results = await self.pinecone_service.search_knowledge(search_request)
                
                if results:
                    print(f"✅ 找到 {len(results)} 个相关知识")
                    
                    for j, result in enumerate(results):
                        print(f"  结果 {j+1}: {result.knowledge_item.title} (相似度: {result.score:.3f})")
                        print(f"    类型: {result.knowledge_item.knowledge_type.value}")
                        print(f"    标签: {result.knowledge_item.tags}")
                    
                    search_results.append(True)
                else:
                    print(f"❌ 未找到相关知识")
                    search_results.append(False)
                
                await asyncio.sleep(1)
            
            success_count = sum(search_results)
            total_count = len(search_results)
            
            print(f"\n📊 搜索结果: {success_count}/{total_count} 成功")
            
            return success_count >= total_count * 0.8  # 80% 成功率
            
        except Exception as e:
            print(f"❌ 知识搜索测试失败: {e}")
            return False
    
    async def test_knowledge_management(self) -> bool:
        """测试知识管理功能
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试知识管理功能 ===")
            
            # 测试批量导入
            print("\n测试批量知识导入...")
            
            batch_knowledge = [
                {
                    "title": "XSS攻击防护策略",
                    "content": "跨站脚本攻击(XSS)防护包括输入验证、输出编码、CSP策略等",
                    "knowledge_type": "security_rule",
                    "tags": ["XSS", "Web安全"],
                    "source": "安全指南"
                },
                {
                    "title": "CSRF攻击检测",
                    "content": "跨站请求伪造攻击检测需要验证请求来源、使用CSRF令牌等",
                    "knowledge_type": "security_rule",
                    "tags": ["CSRF", "Web安全"],
                    "source": "安全指南"
                }
            ]
            
            # 批量上传
            upload_results = await self.knowledge_manager.batch_upload_knowledge(
                knowledge_items=batch_knowledge,
                batch_size=2
            )
            
            if upload_results["success_count"] > 0:
                print(f"✅ 批量上传成功: {upload_results['success_count']} 个知识项")
            else:
                print(f"❌ 批量上传失败")
                return False
            
            # 测试知识统计
            print("\n获取知识统计信息...")
            stats = await self.knowledge_manager.get_stats()
            print(f"📊 知识统计:")
            print(f"  总导入数: {stats.get('total_imports', 0)}")
            print(f"  成功数: {stats.get('successful_imports', 0)}")
            print(f"  失败数: {stats.get('failed_imports', 0)}")
            
            return True
            
        except Exception as e:
            print(f"❌ 知识管理测试失败: {e}")
            return False
    
    async def test_service_performance(self) -> bool:
        """测试服务性能
        
        Returns:
            是否测试成功
        """
        try:
            print("\n=== 测试服务性能 ===")
            
            # 获取 Pinecone 服务统计
            pinecone_stats = await self.pinecone_service.get_stats()
            print(f"\n📊 Pinecone 服务统计:")
            print(f"  总嵌入数: {pinecone_stats.get('total_embeddings', 0)}")
            print(f"  总上传数: {pinecone_stats.get('total_uploads', 0)}")
            print(f"  总搜索数: {pinecone_stats.get('total_searches', 0)}")
            print(f"  缓存命中: {pinecone_stats.get('cache_hits', 0)}")
            print(f"  缓存未命中: {pinecone_stats.get('cache_misses', 0)}")
            print(f"  平均嵌入时间: {pinecone_stats.get('embedding_time', 0):.3f}s")
            print(f"  平均搜索时间: {pinecone_stats.get('search_time', 0):.3f}s")
            
            # 获取知识管理统计
            km_stats = await self.knowledge_manager.get_stats()
            print(f"\n📊 知识管理统计:")
            print(f"  总导入: {km_stats.get('total_imports', 0)}")
            print(f"  成功导入: {km_stats.get('successful_imports', 0)}")
            print(f"  失败导入: {km_stats.get('failed_imports', 0)}")
            
            return True
            
        except Exception as e:
            print(f"❌ 性能测试失败: {e}")
            return False
    
    async def cleanup_services(self) -> None:
        """清理测试服务"""
        try:
            print("\n=== 清理测试服务 ===")
            
            if self.pinecone_service:
                await self.pinecone_service.close()
                print("✅ Pinecone 服务已关闭")
            
            print("✅ 服务清理完成")
            
        except Exception as e:
            print(f"❌ 服务清理失败: {e}")
    
    async def run_integration_test(self) -> Dict[str, Any]:
        """运行完整的集成测试
        
        Returns:
            测试结果字典
        """
        print("\n" + "="*60)
        print("🚀 开始 Pinecone 向量数据库集成测试")
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
            
            # 2. 测试知识上传
            upload_success = await self.test_knowledge_upload()
            test_results['tests']['knowledge_upload'] = upload_success
            
            # 3. 测试知识搜索
            search_success = await self.test_knowledge_search()
            test_results['tests']['knowledge_search'] = search_success
            
            # 4. 测试知识管理
            management_success = await self.test_knowledge_management()
            test_results['tests']['knowledge_management'] = management_success
            
            # 5. 测试服务性能
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
        print("📋 Pinecone 集成测试摘要")
        print("="*60)
        
        print(f"\n⏱️  测试时间: {results.get('duration', 0):.2f} 秒")
        print(f"📊 成功率: {results.get('success_rate', 0)*100:.1f}% ({results.get('successful_tests', 0)}/{results.get('total_tests', 0)})")
        
        print("\n🧪 详细测试结果:")
        for test_name, success in results.get('tests', {}).items():
            status = "✅ 通过" if success else "❌ 失败"
            print(f"  {test_name}: {status}")
        
        if results.get('overall_success'):
            print("\n🎉 Pinecone 集成测试整体成功！")
            print("✅ 1.4.2 Pinecone 向量数据库集成功能验证通过")
        else:
            print("\n⚠️  Pinecone 集成测试存在问题")
            if results.get('error_message'):
                print(f"❌ 错误信息: {results['error_message']}")
        
        print("\n" + "="*60)


async def test_integration_flow():
    """测试集成流程"""
    tester = TestPineconeIntegration()
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