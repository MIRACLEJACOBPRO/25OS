#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS Pinecone向量数据库集成服务模块

实现1.4.2 Pinecone向量数据库集成的核心功能:
1. Pinecone客户端管理
2. 向量嵌入生成
3. 知识库管理
4. 向量检索
5. 相似度搜索
6. 知识上传和管理

设计原则:
- 异步处理: 支持高并发向量操作
- 缓存优化: 减少重复嵌入计算
- 批量处理: 提高向量操作效率
- 错误处理: 完善的异常处理机制
- 可扩展性: 支持多种嵌入模型
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import json
import hashlib
from functools import lru_cache
import time
import numpy as np
from concurrent.futures import ThreadPoolExecutor

try:
    import pinecone
    from pinecone import Pinecone, ServerlessSpec
except ImportError:
    pinecone = None
    Pinecone = None
    ServerlessSpec = None

try:
    import openai
except ImportError:
    openai = None

try:
    import tiktoken
except ImportError:
    tiktoken = None

from loguru import logger
from core.config import settings


class EmbeddingModel(Enum):
    """嵌入模型枚举"""
    TEXT_EMBEDDING_ADA_002 = "text-embedding-ada-002"
    TEXT_EMBEDDING_3_SMALL = "text-embedding-3-small"
    TEXT_EMBEDDING_3_LARGE = "text-embedding-3-large"


class KnowledgeType(Enum):
    """知识类型枚举"""
    SECURITY_RULE = "security_rule"          # 安全规则
    THREAT_PATTERN = "threat_pattern"        # 威胁模式
    INCIDENT_CASE = "incident_case"          # 事件案例
    REMEDIATION_GUIDE = "remediation_guide"  # 修复指南
    BEST_PRACTICE = "best_practice"          # 最佳实践
    VULNERABILITY_INFO = "vulnerability_info" # 漏洞信息


@dataclass
class KnowledgeItem:
    """知识项数据结构"""
    id: str
    title: str
    content: str
    knowledge_type: KnowledgeType
    metadata: Dict[str, Any]
    tags: List[str]
    created_at: datetime
    updated_at: datetime
    embedding: Optional[List[float]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = asdict(self)
        result['knowledge_type'] = self.knowledge_type.value
        result['created_at'] = self.created_at.isoformat()
        result['updated_at'] = self.updated_at.isoformat()
        return result


@dataclass
class SearchResult:
    """搜索结果数据结构"""
    knowledge_item: KnowledgeItem
    similarity_score: float
    rank: int
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'knowledge_item': self.knowledge_item.to_dict(),
            'similarity_score': self.similarity_score,
            'rank': self.rank
        }


@dataclass
class VectorSearchRequest:
    """向量搜索请求"""
    query_text: str
    top_k: int = 5
    knowledge_types: Optional[List[KnowledgeType]] = None
    tags: Optional[List[str]] = None
    metadata_filter: Optional[Dict[str, Any]] = None
    similarity_threshold: float = 0.7
    request_id: Optional[str] = None
    
    def __post_init__(self):
        if self.request_id is None:
            content_hash = hashlib.md5(self.query_text.encode()).hexdigest()[:8]
            timestamp = int(time.time() * 1000)
            self.request_id = f"search_{content_hash}_{timestamp}"


class PineconeService:
    """Pinecone向量数据库服务"""
    
    def __init__(self, 
                 api_key: str,
                 environment: str,
                 index_name: str = "neuronos-knowledge",
                 dimension: int = 1024,
                 embedding_model: EmbeddingModel = EmbeddingModel.TEXT_EMBEDDING_3_SMALL,
                 openai_api_key: Optional[str] = None):
        """
        初始化Pinecone服务
        
        Args:
            api_key: Pinecone API密钥
            environment: Pinecone环境
            index_name: 索引名称
            dimension: 向量维度
            embedding_model: 嵌入模型
            openai_api_key: OpenAI API密钥（用于生成嵌入）
        """
        if not pinecone:
            raise ImportError("请安装pinecone-client: pip install pinecone-client")
        
        if not openai:
            raise ImportError("请安装openai: pip install openai")
        
        self.api_key = api_key
        self.environment = environment
        self.index_name = index_name
        self.dimension = dimension
        self.embedding_model = embedding_model
        self.openai_api_key = openai_api_key or settings.openai_api_key
        
        # 初始化客户端
        self.pc = Pinecone(api_key=api_key)
        
        # OpenAI 客户端
        try:
            from openai import AsyncOpenAI
            self.openai_client = AsyncOpenAI(api_key=self.openai_api_key)
        except ImportError:
            self.openai_client = openai.OpenAI(api_key=self.openai_api_key)
        
        # 索引对象
        self.index = None
        
        # 缓存
        self._embedding_cache = {}
        self._cache_max_size = 1000
        
        # 线程池
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # 统计信息
        self.stats = {
            'total_embeddings': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'total_searches': 0,
            'total_uploads': 0,
            'total_tokens': 0,
            'average_search_time': 0.0,
            'average_embedding_time': 0.0,
            'upload_time': 0.0
        }
        
        self.logger = logger.bind(service="pinecone")
        
        # 初始化标志
        self._initialized = False
    
    async def initialize(self) -> bool:
        """初始化 Pinecone 连接
        
        Returns:
            是否初始化成功
        """
        try:
            self.logger.info(f"正在初始化 Pinecone 服务: {self.index_name}")
            
            # 检查索引是否存在
            existing_indexes = self.pc.list_indexes()
            index_names = [idx.name for idx in existing_indexes.indexes]
            
            if self.index_name not in index_names:
                self.logger.info(f"创建新索引: {self.index_name}")
                # 创建索引，维度设置为1024
                self.pc.create_index(
                    name=self.index_name,
                    dimension=1024,  # 确保维度为1024
                    metric="cosine",
                    spec=ServerlessSpec(
                        cloud="aws",
                        region="us-east-1"
                    )
                )
                # 等待索引创建完成
                import time
                while self.index_name not in [idx.name for idx in self.pc.list_indexes().indexes]:
                    time.sleep(1)
                
                self.logger.info(f"索引 {self.index_name} 创建成功")
            else:
                self.logger.info(f"使用现有索引: {self.index_name}")
            
            # 连接到索引
            self.index = self.pc.Index(self.index_name)
            
            # 测试连接
            stats = self.index.describe_index_stats()
            self.logger.info(f"Pinecone 连接成功，索引统计: {stats}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Pinecone 初始化失败: {e}")
            return False
    
    async def generate_embedding(self, text: str, use_cache: bool = True) -> List[float]:
        """生成文本嵌入向量
        
        Args:
            text: 输入文本
            use_cache: 是否使用缓存
            
        Returns:
            List[float]: 嵌入向量（1024维）
        """
        start_time = time.time()
        
        # 清理和预处理文本
        cleaned_text = text.strip().replace('\n', ' ').replace('\r', ' ')
        if not cleaned_text:
            self.logger.warning("输入文本为空")
            return [0.0] * 1024  # 返回零向量
        
        # 检查缓存
        if use_cache:
            text_hash = hashlib.md5(cleaned_text.encode()).hexdigest()
            if text_hash in self._embedding_cache:
                self.stats['cache_hits'] += 1
                return self._embedding_cache[text_hash]
            else:
                self.stats['cache_misses'] += 1
        
        try:
            # 调用OpenAI API生成嵌入
            response = await self.openai_client.embeddings.create(
                model=self.embedding_model.value,
                input=cleaned_text,
                dimensions=1024  # 确保输出1024维向量
            )
            
            embedding = response.data[0].embedding
            
            # 验证向量维度
            if len(embedding) != 1024:
                self.logger.error(f"嵌入向量维度错误: {len(embedding)}, 期望: 1024")
                return [0.0] * 1024  # 返回零向量
            
            # 更新缓存
            if use_cache and len(self._embedding_cache) < self._cache_max_size:
                self._embedding_cache[text_hash] = embedding
            
            # 更新统计信息
            self.stats['total_embeddings'] += 1
            if hasattr(response, 'usage') and response.usage:
                self.stats['total_tokens'] += response.usage.total_tokens
            
            embedding_time = (time.time() - start_time) * 1000
            self.stats['average_embedding_time'] = (
                (self.stats['average_embedding_time'] * (self.stats['total_embeddings'] - 1) + embedding_time) /
                self.stats['total_embeddings']
            )
            
            self.logger.debug(f"生成嵌入向量成功，维度: {len(embedding)}, 耗时: {embedding_time:.2f}ms")
            return embedding
            
        except Exception as e:
            self.logger.error(f"生成嵌入向量失败: {e}")
            raise
    
    async def upload_knowledge(self, knowledge_items: List[KnowledgeItem]) -> Dict[str, Any]:
        """上传知识到向量数据库
        
        Args:
            knowledge_items: 知识项列表
            
        Returns:
            Dict[str, Any]: 上传结果
        """
        if not self.index:
            raise RuntimeError("Pinecone索引未初始化")
        
        start_time = time.time()
        successful_uploads = 0
        failed_uploads = 0
        
        try:
            # 批量处理知识项
            batch_size = 100
            for i in range(0, len(knowledge_items), batch_size):
                batch = knowledge_items[i:i + batch_size]
                vectors_to_upsert = []
                
                for item in batch:
                    try:
                        # 生成嵌入向量
                        if item.embedding is None:
                            # 组合标题和内容生成嵌入
                            text_to_embed = f"{item.title}\n\n{item.content}"
                            item.embedding = await self.generate_embedding(text_to_embed)
                        
                        # 准备向量数据
                        vector_data = {
                            'id': item.id,
                            'values': item.embedding,
                            'metadata': {
                                'title': item.title,
                                'content': item.content[:1000],  # 限制内容长度
                                'knowledge_type': item.knowledge_type.value,
                                'tags': item.tags,
                                'created_at': item.created_at.isoformat(),
                                'updated_at': item.updated_at.isoformat(),
                                **item.metadata
                            }
                        }
                        
                        vectors_to_upsert.append(vector_data)
                        successful_uploads += 1
                        
                    except Exception as e:
                        self.logger.error(f"处理知识项 {item.id} 失败: {e}")
                        failed_uploads += 1
                        continue
                
                # 批量上传到Pinecone
                if vectors_to_upsert:
                    self.index.upsert(vectors=vectors_to_upsert)
                    self.logger.info(f"批量上传 {len(vectors_to_upsert)} 个向量到Pinecone")
            
            # 更新统计信息
            self.stats['total_uploads'] += successful_uploads
            processing_time = (time.time() - start_time) * 1000
            
            result = {
                'successful_uploads': successful_uploads,
                'failed_uploads': failed_uploads,
                'total_items': len(knowledge_items),
                'processing_time': processing_time,
                'timestamp': datetime.now().isoformat()
            }
            
            self.logger.info(f"知识上传完成: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"上传知识到向量数据库失败: {e}")
            raise
    
    async def search_knowledge(self, request: VectorSearchRequest) -> List[SearchResult]:
        """搜索相关知识
        
        Args:
            request: 搜索请求
            
        Returns:
            List[SearchResult]: 搜索结果列表
        """
        if not self.index:
            raise RuntimeError("Pinecone索引未初始化")
        
        start_time = time.time()
        
        try:
            # 生成查询向量
            query_embedding = await self.generate_embedding(request.query_text)
            
            # 构建过滤条件
            filter_conditions = {}
            
            if request.knowledge_types:
                filter_conditions['knowledge_type'] = {
                    '$in': [kt.value for kt in request.knowledge_types]
                }
            
            if request.tags:
                filter_conditions['tags'] = {
                    '$in': request.tags
                }
            
            if request.metadata_filter:
                filter_conditions.update(request.metadata_filter)
            
            # 执行向量搜索
            search_response = self.index.query(
                vector=query_embedding,
                top_k=request.top_k,
                filter=filter_conditions if filter_conditions else None,
                include_metadata=True,
                include_values=False
            )
            
            # 处理搜索结果
            results = []
            for i, match in enumerate(search_response.matches):
                if match.score >= request.similarity_threshold:
                    # 重构知识项
                    metadata = match.metadata
                    knowledge_item = KnowledgeItem(
                        id=match.id,
                        title=metadata.get('title', ''),
                        content=metadata.get('content', ''),
                        knowledge_type=KnowledgeType(metadata.get('knowledge_type', 'security_rule')),
                        metadata={k: v for k, v in metadata.items() 
                                if k not in ['title', 'content', 'knowledge_type', 'tags', 'created_at', 'updated_at']},
                        tags=metadata.get('tags', []),
                        created_at=datetime.fromisoformat(metadata.get('created_at', datetime.now().isoformat())),
                        updated_at=datetime.fromisoformat(metadata.get('updated_at', datetime.now().isoformat()))
                    )
                    
                    search_result = SearchResult(
                        knowledge_item=knowledge_item,
                        similarity_score=match.score,
                        rank=i + 1
                    )
                    
                    results.append(search_result)
            
            # 更新统计信息
            self.stats['total_searches'] += 1
            search_time = (time.time() - start_time) * 1000
            self.stats['average_search_time'] = (
                (self.stats['average_search_time'] * (self.stats['total_searches'] - 1) + search_time) /
                self.stats['total_searches']
            )
            
            self.logger.info(f"向量搜索完成: 查询='{request.query_text}', 结果数量={len(results)}, 耗时={search_time:.2f}ms")
            return results
            
        except Exception as e:
            self.logger.error(f"向量搜索失败: {e}")
            raise
    
    async def search_knowledge_simple(
        self, 
        query_text: str, 
        top_k: int = 5,
        knowledge_type: Optional[KnowledgeType] = None,
        tags: Optional[List[str]] = None
    ) -> List[SearchResult]:
        """简化的知识搜索接口
        
        Args:
            query_text: 查询文本
            top_k: 返回结果数量
            knowledge_type: 知识类型过滤
            tags: 标签过滤
            
        Returns:
            搜索结果列表
        """
        # 构建搜索请求
        request = VectorSearchRequest(
            query_text=query_text,
            top_k=top_k,
            knowledge_types=[knowledge_type] if knowledge_type else None,
            tags=tags
        )
        
        return await self.search_knowledge(request)
    
    async def delete_knowledge(self, knowledge_ids: List[str]) -> Dict[str, Any]:
        """删除知识项
        
        Args:
            knowledge_ids: 知识项ID列表
            
        Returns:
            Dict[str, Any]: 删除结果
        """
        if not self.index:
            raise RuntimeError("Pinecone索引未初始化")
        
        try:
            # 批量删除
            self.index.delete(ids=knowledge_ids)
            
            result = {
                'deleted_count': len(knowledge_ids),
                'deleted_ids': knowledge_ids,
                'timestamp': datetime.now().isoformat()
            }
            
            self.logger.info(f"删除知识项完成: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"删除知识项失败: {e}")
            raise
    
    async def get_statistics(self) -> Dict[str, Any]:
        """获取服务统计信息"""
        index_stats = None
        if self.index:
            try:
                index_stats = self.index.describe_index_stats()
            except Exception as e:
                self.logger.error(f"获取索引统计信息失败: {e}")
        
        return {
            'service_stats': self.stats,
            'index_stats': {
                'total_vector_count': index_stats.total_vector_count if index_stats else 0,
                'dimension': self.dimension,
                'index_name': self.index_name
            },
            'cache_stats': {
                'cache_size': len(self._embedding_cache),
                'cache_max_size': self._cache_max_size,
                'hit_rate': self.stats['cache_hits'] / max(1, self.stats['cache_hits'] + self.stats['cache_misses'])
            }
        }
    
    async def clear_cache(self) -> None:
        """清空嵌入缓存"""
        self._embedding_cache.clear()
        self.logger.info("嵌入缓存已清空")
    
    async def update_knowledge(self, knowledge_item: KnowledgeItem) -> bool:
        """更新单个知识项
        
        Args:
            knowledge_item: 要更新的知识项
            
        Returns:
            bool: 是否更新成功
        """
        try:
            result = await self.upload_knowledge([knowledge_item])
            return result['successful_uploads'] > 0
        except Exception as e:
            self.logger.error(f"更新知识项失败: {e}")
            return False
    
    async def close(self) -> None:
        """关闭服务"""
        if hasattr(self.openai_client, 'close'):
            await self.openai_client.close()
        
        self.logger.info("Pinecone服务已关闭")