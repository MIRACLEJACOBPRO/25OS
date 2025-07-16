#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS RAG检索增强生成服务模块

实现1.4.3 RAG检索增强功能的核心功能:
1. 异常事件向量化
2. 相关知识检索
3. 上下文增强
4. 智能问答增强
5. 知识融合
6. 响应优化

设计原则:
- 智能检索: 基于语义相似度的知识检索
- 上下文融合: 将检索到的知识与原始查询融合
- 多模态支持: 支持多种类型的知识源
- 缓存优化: 减少重复检索
- 质量控制: 确保检索结果的相关性和准确性
"""

import asyncio
import json
import time
import hashlib
from typing import Dict, List, Any, Optional, Union, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import re
from functools import wraps

from loguru import logger

# 导入相关服务
from .pinecone_service import (
    PineconeService, VectorSearchRequest, SearchResult, 
    KnowledgeType, KnowledgeItem
)
from .openai_service import (
    OpenAIService, AnalysisRequest, AnalysisResponse, 
    AnalysisType, Priority
)
from .interfaces import (
    StandardizedEvent, FilterContext, AnomalyScore, 
    FilterResult, EventPriority
)


class RAGMode(Enum):
    """RAG模式枚举"""
    SIMPLE = "simple"                    # 简单检索
    ENHANCED = "enhanced"                # 增强检索
    CONTEXTUAL = "contextual"            # 上下文检索
    MULTI_STEP = "multi_step"            # 多步检索


class RetrievalStrategy(Enum):
    """检索策略枚举"""
    SEMANTIC_SIMILARITY = "semantic_similarity"  # 语义相似度
    KEYWORD_MATCHING = "keyword_matching"        # 关键词匹配
    HYBRID = "hybrid"                            # 混合策略
    CONTEXTUAL_EMBEDDING = "contextual_embedding" # 上下文嵌入


@dataclass
class RAGRequest:
    """RAG请求数据结构"""
    query_text: str
    events: List[Dict[str, Any]]
    analysis_type: AnalysisType
    mode: RAGMode = RAGMode.ENHANCED
    strategy: RetrievalStrategy = RetrievalStrategy.HYBRID
    max_knowledge_items: int = 5
    similarity_threshold: float = 0.7
    context_window: int = 4000  # 上下文窗口大小
    priority: Priority = Priority.MEDIUM
    request_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.request_id is None:
            content_hash = hashlib.md5(self.query_text.encode()).hexdigest()[:8]
            timestamp = int(time.time() * 1000)
            self.request_id = f"rag_{content_hash}_{timestamp}"


@dataclass
class RAGResponse:
    """RAG响应数据结构"""
    request_id: str
    enhanced_analysis: AnalysisResponse
    retrieved_knowledge: List[SearchResult]
    context_summary: str
    knowledge_relevance_scores: Dict[str, float]
    processing_metrics: Dict[str, Any]
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'request_id': self.request_id,
            'enhanced_analysis': self.enhanced_analysis.to_dict(),
            'retrieved_knowledge': [kr.to_dict() for kr in self.retrieved_knowledge],
            'context_summary': self.context_summary,
            'knowledge_relevance_scores': self.knowledge_relevance_scores,
            'processing_metrics': self.processing_metrics,
            'timestamp': self.timestamp.isoformat()
        }


class RAGService:
    """RAG检索增强生成服务"""
    
    def __init__(self, 
                 pinecone_service: PineconeService,
                 openai_service: OpenAIService):
        """
        初始化RAG服务
        
        Args:
            pinecone_service: Pinecone向量数据库服务
            openai_service: OpenAI分析服务
        """
        self.pinecone_service = pinecone_service
        self.openai_service = openai_service
        self.is_initialized = False
        
        # 缓存
        self._context_cache = {}
        self._cache_max_size = 500
        
        # 事件向量缓存
        self.event_vectors = {}
        
        # 统计信息
        self.stats = {
            'total_requests': 0,
            'total_retrievals': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'average_retrieval_time': 0.0,
            'average_enhancement_time': 0.0,
            'knowledge_usage_by_type': {},
            'retrieval_success_rate': 0.0
        }
        
        self.logger = logger.bind(service="rag")
    
    async def initialize(self) -> bool:
        """初始化RAG服务
        
        Returns:
            是否初始化成功
        """
        try:
            self.logger.info("开始初始化RAG服务...")
            
            # 初始化Pinecone服务
            if not await self.pinecone_service.initialize():
                self.logger.error("Pinecone服务初始化失败")
                return False
            
            # 初始化OpenAI服务
            if not await self.openai_service.initialize():
                self.logger.error("OpenAI服务初始化失败")
                return False
            
            self.is_initialized = True
            self.logger.info("RAG服务初始化成功")
            return True
            
        except Exception as e:
            self.logger.error(f"RAG服务初始化失败: {e}")
            return False
    
    async def enhance_analysis(self, request: RAGRequest) -> RAGResponse:
        """增强分析请求
        
        Args:
            request: RAG请求
            
        Returns:
            RAGResponse: 增强后的分析响应
        """
        start_time = time.time()
        
        try:
            self.logger.info(f"开始RAG增强分析: {request.request_id}")
            
            # 1. 事件向量化和知识检索
            retrieved_knowledge = await self._retrieve_relevant_knowledge(request)
            
            # 2. 构建增强上下文
            enhanced_context = await self._build_enhanced_context(
                request, retrieved_knowledge
            )
            
            # 3. 创建增强的分析请求
            enhanced_request = AnalysisRequest(
                analysis_type=request.analysis_type,
                events=request.events,
                context=enhanced_context,
                priority=request.priority,
                max_tokens=4000,  # 增加token限制以容纳更多上下文
                temperature=0.1
            )
            
            # 4. 执行增强分析
            analysis_response = await self.openai_service.analyze_events(enhanced_request)
            
            # 5. 计算知识相关性分数
            relevance_scores = await self._calculate_relevance_scores(
                request.query_text, retrieved_knowledge
            )
            
            # 6. 生成上下文摘要
            context_summary = await self._generate_context_summary(retrieved_knowledge)
            
            # 7. 构建处理指标
            processing_time = (time.time() - start_time) * 1000
            processing_metrics = {
                'total_processing_time': processing_time,
                'retrieval_time': getattr(self, '_last_retrieval_time', 0),
                'analysis_time': getattr(analysis_response, 'processing_time', 0),
                'knowledge_items_retrieved': len(retrieved_knowledge),
                'context_length': len(enhanced_context.get('retrieved_knowledge', '')),
                'mode': request.mode.value,
                'strategy': request.strategy.value
            }
            
            # 8. 构建响应
            rag_response = RAGResponse(
                request_id=request.request_id,
                enhanced_analysis=analysis_response,
                retrieved_knowledge=retrieved_knowledge,
                context_summary=context_summary,
                knowledge_relevance_scores=relevance_scores,
                processing_metrics=processing_metrics,
                timestamp=datetime.now()
            )
            
            # 9. 更新统计信息
            await self._update_statistics(request, rag_response, processing_time)
            
            self.logger.info(f"RAG增强分析完成: {request.request_id}, 耗时: {processing_time:.2f}ms")
            return rag_response
            
        except Exception as e:
            self.logger.error(f"RAG增强分析失败: {e}")
            raise
    
    async def _retrieve_relevant_knowledge(self, request: RAGRequest) -> List[SearchResult]:
        """检索相关知识
        
        Args:
            request: RAG请求
            
        Returns:
            List[SearchResult]: 检索到的知识列表
        """
        start_time = time.time()
        
        try:
            # 构建查询文本
            query_components = [request.query_text]
            
            # 从事件中提取关键信息
            for event in request.events:
                if isinstance(event, dict):
                    # 提取事件描述
                    if 'output' in event:
                        query_components.append(event['output'])
                    if 'rule' in event:
                        query_components.append(event['rule'])
                    if 'rule_name' in event:
                        query_components.append(event['rule_name'])
            
            # 组合查询文本
            combined_query = " ".join(query_components)
            
            # 根据分析类型确定知识类型过滤
            knowledge_types = self._get_relevant_knowledge_types(request.analysis_type)
            
            # 创建向量搜索请求
            search_request = VectorSearchRequest(
                query_text=combined_query,
                top_k=request.max_knowledge_items,
                knowledge_types=knowledge_types,
                similarity_threshold=request.similarity_threshold
            )
            
            # 执行检索
            search_results = await self.pinecone_service.search_knowledge(search_request)
            
            # 记录检索时间
            self._last_retrieval_time = (time.time() - start_time) * 1000
            
            self.logger.info(f"检索到 {len(search_results)} 个相关知识项")
            return search_results
            
        except Exception as e:
            self.logger.error(f"知识检索失败: {e}")
            return []
    
    async def retrieve_relevant_knowledge(
        self, 
        query_text: str, 
        event_type: str = None,
        max_items: int = 5
    ) -> List[Any]:
        """检索相关知识
        
        Args:
            query_text: 查询文本
            event_type: 事件类型
            max_items: 最大返回数量
            
        Returns:
            相关知识列表
        """
        try:
            if not self.is_initialized:
                self.logger.error("RAG服务未初始化")
                return []
            
            start_time = time.time()
            
            # 检查缓存
            cache_key = f"knowledge_{hash(query_text)}_{event_type}_{max_items}"
            if cache_key in self._context_cache:
                self.stats['cache_hits'] += 1
                return self._context_cache[cache_key]
            
            # 根据事件类型确定知识类型过滤
            knowledge_type = self._map_event_to_knowledge_type(event_type)
            
            # 提取查询关键词用于标签过滤
            tags = self._extract_query_tags(query_text, event_type)
            
            # 创建向量搜索请求
            search_request = VectorSearchRequest(
                query_text=query_text,
                top_k=max_items * 2,  # 获取更多结果用于后续过滤
                knowledge_types=[knowledge_type] if knowledge_type else None,
                similarity_threshold=0.3
            )
            
            # 执行向量搜索
            search_results = await self.pinecone_service.search_knowledge(search_request)
            
            # 过滤和排序结果
            filtered_results = self._filter_and_rank_results(
                search_results, 
                query_text, 
                event_type, 
                max_items
            )
            
            # 缓存结果
            if len(self._context_cache) < self._cache_max_size:
                self._context_cache[cache_key] = filtered_results
                self.stats['cache_misses'] += 1
            
            # 更新统计信息
            self.stats['total_retrievals'] += 1
            self.stats['average_retrieval_time'] = (
                (self.stats['average_retrieval_time'] * (self.stats['total_retrievals'] - 1) + 
                 (time.time() - start_time) * 1000) / self.stats['total_retrievals']
            )
            
            self.logger.info(f"知识检索完成: 查询='{query_text[:50]}...', 结果数={len(filtered_results)}")
            return filtered_results
            
        except Exception as e:
            self.logger.error(f"知识检索失败: {e}")
            return []
    
    def _map_event_to_knowledge_type(self, event_type: str) -> Optional[KnowledgeType]:
        """将事件类型映射到知识类型
        
        Args:
            event_type: 事件类型
            
        Returns:
            对应的知识类型
        """
        try:
            mapping = {
                'web_attack': KnowledgeType.SECURITY_RULE,
                'sql_injection': KnowledgeType.SECURITY_RULE,
                'xss': KnowledgeType.SECURITY_RULE,
                'process_anomaly': KnowledgeType.THREAT_PATTERN,
                'malware': KnowledgeType.THREAT_PATTERN,
                'network_anomaly': KnowledgeType.THREAT_PATTERN,
                'ddos': KnowledgeType.THREAT_PATTERN,
                'apt': KnowledgeType.THREAT_PATTERN,
                'privilege_escalation': KnowledgeType.SECURITY_RULE,
                'incident': KnowledgeType.INCIDENT_CASE,
                'vulnerability': KnowledgeType.VULNERABILITY_INFO,
                'remediation': KnowledgeType.REMEDIATION_GUIDE,
                'best_practice': KnowledgeType.BEST_PRACTICE
            }
            
            return mapping.get(event_type)
            
        except Exception as e:
            self.logger.error(f"事件类型映射失败: {e}")
            return None
    
    def _extract_query_tags(self, query_text: str, event_type: str) -> List[str]:
        """从查询文本中提取标签
        
        Args:
            query_text: 查询文本
            event_type: 事件类型
            
        Returns:
            标签列表
        """
        tags = []
        
        try:
            # 基于事件类型的标签
            if event_type:
                tags.append(event_type)
            
            # 基于查询文本的关键词提取
            keywords = {
                'SQL注入': ['sql', 'injection', 'database'],
                'XSS': ['xss', 'script', 'javascript'],
                '恶意进程': ['process', 'malware', 'executable'],
                '网络异常': ['network', 'traffic', 'connection'],
                'DDoS': ['ddos', 'flood', 'attack'],
                'APT': ['apt', 'persistent', 'advanced'],
                '权限提升': ['privilege', 'escalation', 'admin'],
                '文件操作': ['file', 'write', 'delete', 'modify'],
                '登录异常': ['login', 'authentication', 'credential'],
                '端口扫描': ['port', 'scan', 'probe'],
                '暴力破解': ['brute', 'force', 'password']
            }
            
            query_lower = query_text.lower()
            for tag, keywords_list in keywords.items():
                if any(keyword in query_lower for keyword in keywords_list):
                    tags.append(tag)
            
            # 去重并限制数量
            tags = list(set(tags))[:5]
            
        except Exception as e:
            self.logger.error(f"提取查询标签失败: {e}")
        
        return tags
    
    def _filter_and_rank_results(
        self, 
        search_results: List[SearchResult], 
        query_text: str, 
        event_type: str, 
        max_items: int
    ) -> List[SearchResult]:
        """过滤和排序搜索结果
        
        Args:
            search_results: 原始搜索结果
            query_text: 查询文本
            event_type: 事件类型
            max_items: 最大返回数量
            
        Returns:
            过滤后的结果列表
        """
        try:
            # 计算相关性分数
            scored_results = []
            
            for result in search_results:
                relevance_score = self._calculate_result_relevance_score(
                    result, query_text, event_type
                )
                
                # 只保留相关性分数超过阈值的结果
                if relevance_score > 0.3:  # 相关性阈值
                    scored_results.append((result, relevance_score))
            
            # 按相关性分数排序
            scored_results.sort(key=lambda x: x[1], reverse=True)
            
            # 返回前N个结果
            return [result for result, score in scored_results[:max_items]]
            
        except Exception as e:
            self.logger.error(f"过滤排序结果失败: {e}")
            return search_results[:max_items]
    
    def _calculate_result_relevance_score(
        self, 
        search_result: SearchResult, 
        query_text: str, 
        event_type: str
    ) -> float:
        """计算相关性分数
        
        Args:
            search_result: 搜索结果
            query_text: 查询文本
            event_type: 事件类型
            
        Returns:
            相关性分数 (0-1)
        """
        try:
            base_score = search_result.similarity_score  # Pinecone相似度分数
            
            # 标题匹配加分
            title_bonus = 0
            if hasattr(search_result, 'knowledge_item'):
                title = search_result.knowledge_item.title.lower()
                query_lower = query_text.lower()
                
                # 检查关键词匹配
                query_words = set(query_lower.split())
                title_words = set(title.split())
                
                if query_words & title_words:  # 有交集
                    title_bonus = 0.1
            
            # 事件类型匹配加分
            type_bonus = 0
            if event_type and hasattr(search_result, 'knowledge_item'):
                tags = search_result.knowledge_item.tags
                if event_type in [tag.lower() for tag in tags]:
                    type_bonus = 0.15
            
            # 内容相关性加分
            content_bonus = 0
            if hasattr(search_result, 'knowledge_item'):
                content = search_result.knowledge_item.content.lower()
                query_lower = query_text.lower()
                
                # 简单的关键词匹配
                query_words = query_lower.split()
                matched_words = sum(1 for word in query_words if word in content)
                if matched_words > 0:
                    content_bonus = min(matched_words / len(query_words) * 0.1, 0.1)
            
            # 计算最终分数
            final_score = min(base_score + title_bonus + type_bonus + content_bonus, 1.0)
            
            return final_score
            
        except Exception as e:
            self.logger.error(f"计算相关性分数失败: {e}")
            return search_result.similarity_score if hasattr(search_result, 'similarity_score') else 0.5
    
    def _get_relevant_knowledge_types(self, analysis_type: AnalysisType) -> List[KnowledgeType]:
        """根据分析类型获取相关的知识类型
        
        Args:
            analysis_type: 分析类型
            
        Returns:
            List[KnowledgeType]: 相关知识类型列表
        """
        type_mapping = {
            AnalysisType.SECURITY_ANALYSIS: [
                KnowledgeType.SECURITY_RULE,
                KnowledgeType.THREAT_PATTERN,
                KnowledgeType.VULNERABILITY_INFO
            ],
            AnalysisType.THREAT_ASSESSMENT: [
                KnowledgeType.THREAT_PATTERN,
                KnowledgeType.INCIDENT_CASE,
                KnowledgeType.VULNERABILITY_INFO
            ],
            AnalysisType.INCIDENT_RESPONSE: [
                KnowledgeType.INCIDENT_CASE,
                KnowledgeType.BEST_PRACTICE,
                KnowledgeType.REMEDIATION_GUIDE
            ],
            AnalysisType.REMEDIATION_ADVICE: [
                KnowledgeType.REMEDIATION_GUIDE,
                KnowledgeType.BEST_PRACTICE,
                KnowledgeType.SECURITY_RULE
            ],
            AnalysisType.PATTERN_ANALYSIS: [
                KnowledgeType.THREAT_PATTERN,
                KnowledgeType.INCIDENT_CASE,
                KnowledgeType.SECURITY_RULE
            ],
            AnalysisType.RISK_EVALUATION: [
                KnowledgeType.VULNERABILITY_INFO,
                KnowledgeType.THREAT_PATTERN,
                KnowledgeType.BEST_PRACTICE
            ]
        }
        
        return type_mapping.get(analysis_type, list(KnowledgeType))
    
    async def _build_enhanced_context(self, 
                                    request: RAGRequest, 
                                    knowledge_results: List[SearchResult]) -> Dict[str, Any]:
        """构建增强上下文
        
        Args:
            request: RAG请求
            knowledge_results: 检索到的知识结果
            
        Returns:
            Dict[str, Any]: 增强上下文
        """
        try:
            # 基础上下文
            context = {
                'original_query': request.query_text,
                'analysis_type': request.analysis_type.value,
                'event_count': len(request.events),
                'retrieval_timestamp': datetime.now().isoformat()
            }
            
            # 添加检索到的知识
            if knowledge_results:
                knowledge_context = []
                
                for result in knowledge_results:
                    knowledge_item = result.knowledge_item
                    knowledge_context.append({
                        'title': knowledge_item.title,
                        'content': knowledge_item.content,
                        'type': knowledge_item.knowledge_type.value,
                        'relevance_score': result.similarity_score,
                        'tags': knowledge_item.tags
                    })
                
                context['retrieved_knowledge'] = self._format_knowledge_for_context(
                    knowledge_context, request.context_window
                )
                context['knowledge_summary'] = self._summarize_knowledge(knowledge_context)
            
            # 添加事件上下文
            context['events_summary'] = self._summarize_events(request.events)
            
            return context
            
        except Exception as e:
            self.logger.error(f"构建增强上下文失败: {e}")
            return {'error': str(e)}
    
    def _format_knowledge_for_context(self, 
                                    knowledge_items: List[Dict[str, Any]], 
                                    max_length: int) -> str:
        """格式化知识项为上下文字符串
        
        Args:
            knowledge_items: 知识项列表
            max_length: 最大长度
            
        Returns:
            str: 格式化的知识上下文
        """
        formatted_items = []
        current_length = 0
        
        for item in knowledge_items:
            item_text = f"""### {item['title']} (相关度: {item['relevance_score']:.3f})
类型: {item['type']}
标签: {', '.join(item['tags'])}
内容: {item['content']}

"""
            
            if current_length + len(item_text) > max_length:
                break
            
            formatted_items.append(item_text)
            current_length += len(item_text)
        
        return "\n".join(formatted_items)
    
    def _summarize_knowledge(self, knowledge_items: List[Dict[str, Any]]) -> str:
        """总结知识项
        
        Args:
            knowledge_items: 知识项列表
            
        Returns:
            str: 知识摘要
        """
        if not knowledge_items:
            return "未检索到相关知识"
        
        type_counts = {}
        total_relevance = 0
        
        for item in knowledge_items:
            item_type = item['type']
            type_counts[item_type] = type_counts.get(item_type, 0) + 1
            total_relevance += item['relevance_score']
        
        avg_relevance = total_relevance / len(knowledge_items)
        
        summary_parts = [
            f"检索到 {len(knowledge_items)} 个相关知识项",
            f"平均相关度: {avg_relevance:.3f}",
            f"知识类型分布: {', '.join([f'{k}({v})' for k, v in type_counts.items()])}"
        ]
        
        return "; ".join(summary_parts)
    
    def _summarize_events(self, events: List[Dict[str, Any]]) -> str:
        """总结事件信息
        
        Args:
            events: 事件列表
            
        Returns:
            str: 事件摘要
        """
        if not events:
            return "无事件数据"
        
        priority_counts = {}
        rule_counts = {}
        
        for event in events:
            if isinstance(event, dict):
                # 统计优先级
                priority = event.get('priority', 'UNKNOWN')
                priority_counts[priority] = priority_counts.get(priority, 0) + 1
                
                # 统计规则
                rule = event.get('rule', event.get('rule_name', 'UNKNOWN'))
                rule_counts[rule] = rule_counts.get(rule, 0) + 1
        
        summary_parts = [
            f"事件总数: {len(events)}",
            f"优先级分布: {', '.join([f'{k}({v})' for k, v in priority_counts.items()])}",
            f"主要规则: {', '.join(list(rule_counts.keys())[:3])}"
        ]
        
        return "; ".join(summary_parts)
    
    async def _calculate_relevance_scores(self, 
                                        query: str, 
                                        knowledge_results: List[SearchResult]) -> Dict[str, float]:
        """计算知识相关性分数
        
        Args:
            query: 查询文本
            knowledge_results: 知识检索结果
            
        Returns:
            Dict[str, float]: 相关性分数字典
        """
        relevance_scores = {}
        
        for result in knowledge_results:
            knowledge_id = result.knowledge_item.id
            
            # 基础相似度分数
            base_score = result.similarity_score
            
            # 根据知识类型调整权重
            type_weight = self._get_knowledge_type_weight(result.knowledge_item.knowledge_type)
            
            # 根据标签匹配调整权重
            tag_weight = self._calculate_tag_relevance(query, result.knowledge_item.tags)
            
            # 综合计算相关性分数
            final_score = base_score * type_weight * tag_weight
            relevance_scores[knowledge_id] = final_score
        
        return relevance_scores
    
    def _get_knowledge_type_weight(self, knowledge_type: KnowledgeType) -> float:
        """获取知识类型权重
        
        Args:
            knowledge_type: 知识类型
            
        Returns:
            float: 权重值
        """
        weights = {
            KnowledgeType.SECURITY_RULE: 1.0,
            KnowledgeType.THREAT_PATTERN: 0.9,
            KnowledgeType.INCIDENT_CASE: 0.8,
            KnowledgeType.REMEDIATION_GUIDE: 0.85,
            KnowledgeType.BEST_PRACTICE: 0.7,
            KnowledgeType.VULNERABILITY_INFO: 0.9
        }
        
        return weights.get(knowledge_type, 0.5)
    
    def _calculate_tag_relevance(self, query: str, tags: List[str]) -> float:
        """计算标签相关性
        
        Args:
            query: 查询文本
            tags: 标签列表
            
        Returns:
            float: 标签相关性权重
        """
        if not tags:
            return 1.0
        
        query_lower = query.lower()
        matching_tags = [tag for tag in tags if tag.lower() in query_lower]
        
        if matching_tags:
            return 1.0 + 0.1 * len(matching_tags)  # 每个匹配标签增加10%权重
        
        return 1.0
    
    async def _generate_context_summary(self, knowledge_results: List[SearchResult]) -> str:
        """生成上下文摘要
        
        Args:
            knowledge_results: 知识检索结果
            
        Returns:
            str: 上下文摘要
        """
        if not knowledge_results:
            return "未检索到相关知识，基于事件数据进行分析"
        
        # 按相关性排序
        sorted_results = sorted(knowledge_results, key=lambda x: x.similarity_score, reverse=True)
        
        # 提取关键信息
        key_insights = []
        for result in sorted_results[:3]:  # 取前3个最相关的
            insight = f"{result.knowledge_item.title} (相关度: {result.similarity_score:.3f})"
            key_insights.append(insight)
        
        summary = f"基于 {len(knowledge_results)} 个相关知识项进行增强分析，主要参考: {'; '.join(key_insights)}"
        return summary
    
    async def _update_statistics(self, 
                               request: RAGRequest, 
                               response: RAGResponse, 
                               processing_time: float) -> None:
        """更新统计信息
        
        Args:
            request: RAG请求
            response: RAG响应
            processing_time: 处理时间
        """
        self.stats['total_requests'] += 1
        self.stats['total_retrievals'] += len(response.retrieved_knowledge)
        
        # 更新平均处理时间
        self.stats['average_enhancement_time'] = (
            (self.stats['average_enhancement_time'] * (self.stats['total_requests'] - 1) + processing_time) /
            self.stats['total_requests']
        )
        
        # 更新知识类型使用统计
        for result in response.retrieved_knowledge:
            knowledge_type = result.knowledge_item.knowledge_type.value
            self.stats['knowledge_usage_by_type'][knowledge_type] = (
                self.stats['knowledge_usage_by_type'].get(knowledge_type, 0) + 1
            )
        
        # 更新检索成功率
        if response.retrieved_knowledge:
            successful_retrievals = self.stats.get('successful_retrievals', 0) + 1
            self.stats['successful_retrievals'] = successful_retrievals
            self.stats['retrieval_success_rate'] = successful_retrievals / self.stats['total_requests']
    
    async def vectorize_anomaly_event(self, 
                                     event: StandardizedEvent, 
                                     filter_result: Dict[str, Any]) -> str:
        """将异常事件向量化为查询文本
        
        Args:
            event: 标准化事件
            filter_result: 过滤结果
            
        Returns:
            str: 向量化查询文本
        """
        try:
            if not self.is_initialized:
                self.logger.error("RAG服务未初始化")
                return f"异常事件: {getattr(event, 'rule_name', 'unknown')}"
            
            # 构建查询文本组件
            query_components = []
            
            # 添加事件基本信息
            if hasattr(event, 'rule_name') and event.rule_name:
                query_components.append(f"规则: {event.rule_name}")
            
            if hasattr(event, 'output') and event.output:
                query_components.append(f"事件描述: {event.output}")
            
            if hasattr(event, 'priority') and event.priority:
                query_components.append(f"优先级: {event.priority.name}")
            
            # 添加过滤结果信息
            if filter_result:
                decision = filter_result.get('decision', '')
                reason = filter_result.get('reason', '')
                
                if decision:
                    query_components.append(f"过滤决策: {decision}")
                if reason:
                    query_components.append(f"过滤原因: {reason}")
                
                # 添加异常分数信息
                anomaly_score = filter_result.get('anomaly_score', {})
                if anomaly_score:
                    risk_level = anomaly_score.get('risk_level', '')
                    explanation = anomaly_score.get('explanation', '')
                    
                    if risk_level:
                        query_components.append(f"风险等级: {risk_level}")
                    if explanation:
                        query_components.append(f"异常解释: {explanation}")
            
            # 添加技术细节
            technical_details = self._extract_technical_details(event)
            if technical_details:
                query_components.extend(technical_details)
            
            # 组合查询文本
            vectorized_query = " | ".join(query_components)
            
            # 生成嵌入向量并缓存（可选）
            await self._cache_event_vector(event, vectorized_query)
            
            self.logger.debug(f"事件向量化完成: {vectorized_query[:100]}...")
            return vectorized_query
            
        except Exception as e:
            self.logger.error(f"事件向量化失败: {e}")
            return f"异常事件: {getattr(event, 'rule_name', 'unknown')}"
    
    def _extract_technical_details(self, event: StandardizedEvent) -> List[str]:
        """提取事件技术细节
        
        Args:
            event: 标准化事件
            
        Returns:
            List[str]: 技术细节列表
        """
        details = []
        
        try:
            # 提取网络相关信息
            if hasattr(event, 'source_ip') and event.source_ip:
                details.append(f"源IP: {event.source_ip}")
            
            if hasattr(event, 'destination_ip') and event.destination_ip:
                details.append(f"目标IP: {event.destination_ip}")
            
            if hasattr(event, 'port') and event.port:
                details.append(f"端口: {event.port}")
            
            # 提取进程相关信息
            if hasattr(event, 'process_name') and event.process_name:
                details.append(f"进程: {event.process_name}")
            
            if hasattr(event, 'process_path') and event.process_path:
                details.append(f"进程路径: {event.process_path}")
            
            # 提取文件相关信息
            if hasattr(event, 'file_path') and event.file_path:
                details.append(f"文件路径: {event.file_path}")
            
            if hasattr(event, 'file_hash') and event.file_hash:
                details.append(f"文件哈希: {event.file_hash}")
            
            # 提取用户相关信息
            if hasattr(event, 'user') and event.user:
                details.append(f"用户: {event.user}")
            
            # 提取URL相关信息
            if hasattr(event, 'url') and event.url:
                details.append(f"URL: {event.url}")
            
            # 提取命令行信息
            if hasattr(event, 'command_line') and event.command_line:
                details.append(f"命令行: {event.command_line}")
            
        except Exception as e:
            self.logger.error(f"提取技术细节失败: {e}")
        
        return details
    
    async def _cache_event_vector(self, event: StandardizedEvent, vectorized_query: str) -> None:
        """缓存事件向量
        
        Args:
            event: 标准化事件
            vectorized_query: 向量化查询文本
        """
        try:
            # 生成事件ID
            event_id = getattr(event, 'id', f"event_{int(time.time())}")
            
            # 生成嵌入向量
            embedding = await self.pinecone_service.generate_embedding(vectorized_query)
            
            if embedding:
                # 缓存向量信息
                cache_key = f"event_vector_{event_id}"
                self._context_cache[cache_key] = {
                    'embedding': embedding,
                    'query_text': vectorized_query,
                    'event_data': {
                        'rule_name': getattr(event, 'rule_name', ''),
                        'priority': getattr(event, 'priority', ''),
                        'timestamp': getattr(event, 'timestamp', datetime.now())
                    },
                    'cached_at': time.time()
                }
                
                # 清理过期缓存
                await self._cleanup_expired_cache()
                
                self.logger.debug(f"事件向量已缓存: {event_id}")
            
        except Exception as e:
            self.logger.error(f"缓存事件向量失败: {e}")
    
    async def _cleanup_expired_cache(self) -> None:
        """清理过期缓存"""
        try:
            current_time = time.time()
            cache_ttl = 3600  # 1小时过期
            
            expired_keys = []
            for key, value in self._context_cache.items():
                if key.startswith('event_vector_'):
                    cached_at = value.get('cached_at', 0)
                    if current_time - cached_at > cache_ttl:
                        expired_keys.append(key)
            
            for key in expired_keys:
                del self._context_cache[key]
            
            if expired_keys:
                self.logger.debug(f"清理了 {len(expired_keys)} 个过期缓存项")
                
        except Exception as e:
            self.logger.error(f"清理过期缓存失败: {e}")
    
    async def get_statistics(self) -> Dict[str, Any]:
        """获取RAG服务统计信息"""
        return {
            'rag_stats': self.stats,
            'cache_stats': {
                'cache_size': len(self._context_cache),
                'cache_max_size': self._cache_max_size
            },
            'service_status': {
                'pinecone_connected': self.pinecone_service.index is not None,
                'openai_available': self.openai_service is not None
            }
        }
    
    async def clear_cache(self) -> None:
        """清空缓存"""
        self._context_cache.clear()
        await self.pinecone_service.clear_cache()
        self.logger.info("RAG服务缓存已清空")
    
    async def enhance_with_knowledge(
        self, 
        anomaly_event: Any, 
        analysis_type: str = "comprehensive"
    ) -> Any:
        """使用知识增强异常事件分析
        
        Args:
            anomaly_event: 异常事件
            analysis_type: 分析类型
            
        Returns:
            增强后的分析结果
        """
        try:
            if not self.is_initialized:
                self.logger.error("RAG服务未初始化")
                return anomaly_event
            
            start_time = time.time()
            
            # 1. 向量化异常事件
            event_vector = await self.vectorize_anomaly_event(anomaly_event, {})
            if not event_vector:
                self.logger.warning("异常事件向量化失败，返回原始事件")
                return anomaly_event
            
            # 2. 构建查询文本
            query_text = self._build_knowledge_query(anomaly_event)
            event_type = getattr(anomaly_event, 'event_type', None)
            
            # 3. 检索相关知识
            relevant_knowledge = await self.retrieve_relevant_knowledge(
                query_text=query_text,
                event_type=event_type,
                max_items=8  # 获取更多知识用于增强
            )
            
            # 4. 融合知识和事件
            enhanced_context = self._fuse_knowledge_with_event(
                anomaly_event, 
                relevant_knowledge, 
                analysis_type
            )
            
            # 5. 生成增强分析结果
            enhanced_result = self._generate_enhanced_analysis(
                anomaly_event,
                enhanced_context,
                analysis_type
            )
            
            # 更新统计信息
            self.stats['total_enhancements'] = self.stats.get('total_enhancements', 0) + 1
            self.stats['average_enhancement_time'] = (
                (self.stats.get('average_enhancement_time', 0) * (self.stats['total_enhancements'] - 1) + 
                 (time.time() - start_time) * 1000) / self.stats['total_enhancements']
            )
            
            self.logger.info(f"知识增强完成: 事件类型={event_type}, 知识数量={len(relevant_knowledge)}")
            return enhanced_result
            
        except Exception as e:
            self.logger.error(f"知识增强失败: {e}")
            return anomaly_event
    
    def _build_knowledge_query(self, anomaly_event: Any) -> str:
        """构建知识检索查询
        
        Args:
            anomaly_event: 异常事件
            
        Returns:
            查询文本
        """
        try:
            query_parts = []
            
            # 事件类型
            if hasattr(anomaly_event, 'event_type'):
                query_parts.append(anomaly_event.event_type)
            
            # 事件描述
            if hasattr(anomaly_event, 'description'):
                query_parts.append(anomaly_event.description)
            
            # 规则名称
            if hasattr(anomaly_event, 'rule_name'):
                query_parts.append(anomaly_event.rule_name)
            
            # 输出信息
            if hasattr(anomaly_event, 'output'):
                query_parts.append(anomaly_event.output)
            
            # 技术细节
            if hasattr(anomaly_event, 'technical_details'):
                for key, value in anomaly_event.technical_details.items():
                    if isinstance(value, str) and len(value) < 100:
                        query_parts.append(f"{key}: {value}")
            
            # 威胁指标
            if hasattr(anomaly_event, 'threat_indicators'):
                query_parts.extend(anomaly_event.threat_indicators[:3])  # 限制数量
            
            # 组合查询文本
            query_text = " ".join(query_parts)
            
            # 限制长度
            if len(query_text) > 500:
                query_text = query_text[:500] + "..."
            
            return query_text
            
        except Exception as e:
            self.logger.error(f"构建知识查询失败: {e}")
            return str(anomaly_event)[:200]
    
    def _fuse_knowledge_with_event(
        self, 
        anomaly_event: Any, 
        knowledge_items: List[Any], 
        analysis_type: str
    ) -> Dict[str, Any]:
        """融合知识和事件
        
        Args:
            anomaly_event: 异常事件
            knowledge_items: 相关知识列表
            analysis_type: 分析类型
            
        Returns:
            融合后的上下文
        """
        try:
            context = {
                'event': anomaly_event,
                'knowledge_base': [],
                'analysis_context': {
                    'type': analysis_type,
                    'timestamp': time.time(),
                    'knowledge_count': len(knowledge_items)
                },
                'threat_intelligence': [],
                'security_rules': [],
                'remediation_guides': [],
                'similar_incidents': []
            }
            
            # 按知识类型分类
            for item in knowledge_items:
                if not hasattr(item, 'knowledge_item'):
                    continue
                    
                knowledge = item.knowledge_item
                knowledge_type = getattr(knowledge, 'knowledge_type', None)
                
                # 构建知识条目
                knowledge_entry = {
                    'title': knowledge.title,
                    'content': knowledge.content,
                    'type': knowledge_type,
                    'tags': getattr(knowledge, 'tags', []),
                    'similarity_score': getattr(item, 'similarity_score', 0),
                    'source': getattr(knowledge, 'source', 'unknown')
                }
                
                context['knowledge_base'].append(knowledge_entry)
                
                # 按类型分类存储
                if knowledge_type == KnowledgeType.THREAT_PATTERN:
                    context['threat_intelligence'].append(knowledge_entry)
                elif knowledge_type == KnowledgeType.SECURITY_RULE:
                    context['security_rules'].append(knowledge_entry)
                elif knowledge_type == KnowledgeType.REMEDIATION_GUIDE:
                    context['remediation_guides'].append(knowledge_entry)
                elif knowledge_type == KnowledgeType.INCIDENT_CASE:
                    context['similar_incidents'].append(knowledge_entry)
            
            # 生成上下文摘要
            context['summary'] = self._generate_fusion_summary(context)
            
            return context
            
        except Exception as e:
            self.logger.error(f"知识融合失败: {e}")
            return {'event': anomaly_event, 'knowledge_base': []}
    
    def _generate_fusion_summary(self, context: Dict[str, Any]) -> str:
        """生成融合摘要
        
        Args:
            context: 融合后的上下文
            
        Returns:
            融合摘要
        """
        try:
            summary_parts = []
            
            # 事件基本信息
            event = context.get('event')
            if event:
                event_type = getattr(event, 'event_type', '未知')
                summary_parts.append(f"检测到{event_type}类型异常事件")
            
            # 知识库统计
            knowledge_count = len(context.get('knowledge_base', []))
            if knowledge_count > 0:
                summary_parts.append(f"匹配到{knowledge_count}条相关知识")
            
            # 威胁情报
            threat_count = len(context.get('threat_intelligence', []))
            if threat_count > 0:
                summary_parts.append(f"包含{threat_count}条威胁情报")
            
            # 安全规则
            rule_count = len(context.get('security_rules', []))
            if rule_count > 0:
                summary_parts.append(f"{rule_count}条安全规则")
            
            # 修复指南
            guide_count = len(context.get('remediation_guides', []))
            if guide_count > 0:
                summary_parts.append(f"{guide_count}条修复指南")
            
            # 相似事件
            incident_count = len(context.get('similar_incidents', []))
            if incident_count > 0:
                summary_parts.append(f"{incident_count}个相似事件案例")
            
            return "，".join(summary_parts) if summary_parts else "无相关知识匹配"
            
        except Exception as e:
            self.logger.error(f"生成融合摘要失败: {e}")
            return "融合摘要生成失败"
    
    def _generate_enhanced_analysis(
        self, 
        anomaly_event: Any, 
        enhanced_context: Dict[str, Any], 
        analysis_type: str
    ) -> Any:
        """生成增强分析结果
        
        Args:
            anomaly_event: 原始异常事件
            enhanced_context: 增强上下文
            analysis_type: 分析类型
            
        Returns:
            增强后的分析结果
        """
        try:
            # 创建增强结果对象
            enhanced_result = {
                'original_event': anomaly_event,
                'enhanced_context': enhanced_context,
                'analysis_type': analysis_type,
                'enhancement_metadata': {
                    'timestamp': time.time(),
                    'knowledge_sources': len(enhanced_context.get('knowledge_base', [])),
                    'confidence_boost': self._calculate_confidence_boost(enhanced_context),
                    'context_summary': enhanced_context.get('summary', '')
                },
                'recommendations': self._generate_recommendations(enhanced_context),
                'threat_assessment': self._assess_threat_level(anomaly_event, enhanced_context)
            }
            
            return enhanced_result
            
        except Exception as e:
            self.logger.error(f"生成增强分析失败: {e}")
            return anomaly_event
    
    def _calculate_confidence_boost(self, enhanced_context: Dict[str, Any]) -> float:
        """计算置信度提升
        
        Args:
            enhanced_context: 增强上下文
            
        Returns:
            置信度提升值 (0-1)
        """
        try:
            knowledge_base = enhanced_context.get('knowledge_base', [])
            if not knowledge_base:
                return 0.0
            
            # 基于知识数量和相似度的置信度计算
            total_similarity = sum(
                item.get('similarity_score', 0) for item in knowledge_base
            )
            avg_similarity = total_similarity / len(knowledge_base)
            
            # 知识多样性加分
            knowledge_types = set(
                item.get('type') for item in knowledge_base if item.get('type')
            )
            diversity_bonus = min(len(knowledge_types) * 0.1, 0.3)
            
            # 计算最终置信度提升
            confidence_boost = min(avg_similarity + diversity_bonus, 1.0)
            
            return confidence_boost
            
        except Exception as e:
            self.logger.error(f"计算置信度提升失败: {e}")
            return 0.0
    
    def _generate_recommendations(self, enhanced_context: Dict[str, Any]) -> List[str]:
        """生成推荐建议
        
        Args:
            enhanced_context: 增强上下文
            
        Returns:
            推荐建议列表
        """
        try:
            recommendations = []
            
            # 基于修复指南的建议
            remediation_guides = enhanced_context.get('remediation_guides', [])
            for guide in remediation_guides[:3]:  # 限制数量
                if guide.get('content'):
                    recommendations.append(f"修复建议: {guide['content'][:100]}...")
            
            # 基于安全规则的建议
            security_rules = enhanced_context.get('security_rules', [])
            for rule in security_rules[:2]:
                if rule.get('content'):
                    recommendations.append(f"安全规则: {rule['content'][:100]}...")
            
            # 基于相似事件的建议
            similar_incidents = enhanced_context.get('similar_incidents', [])
            if similar_incidents:
                recommendations.append(f"参考相似事件处理经验，共{len(similar_incidents)}个案例")
            
            return recommendations[:5]  # 最多返回5条建议
            
        except Exception as e:
            self.logger.error(f"生成推荐建议失败: {e}")
            return []
    
    def _assess_threat_level(self, anomaly_event: Any, enhanced_context: Dict[str, Any]) -> str:
        """评估威胁等级
        
        Args:
            anomaly_event: 异常事件
            enhanced_context: 增强上下文
            
        Returns:
            威胁等级
        """
        try:
            # 基础威胁等级
            base_threat = getattr(anomaly_event, 'threat_level', 'medium')
            
            # 威胁情报加权
            threat_intelligence = enhanced_context.get('threat_intelligence', [])
            if len(threat_intelligence) >= 3:
                return 'high'  # 多个威胁情报匹配，提升威胁等级
            elif len(threat_intelligence) >= 1:
                if base_threat == 'low':
                    return 'medium'
                elif base_threat == 'medium':
                    return 'high'
            
            return base_threat
            
        except Exception as e:
            self.logger.error(f"评估威胁等级失败: {e}")
            return 'medium'
    
    async def close(self) -> None:
        """关闭RAG服务"""
        await self.pinecone_service.close()
        self.logger.info("RAG服务已关闭")