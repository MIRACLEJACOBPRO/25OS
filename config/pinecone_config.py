#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pinecone 和 RAG 服务配置管理模块

该模块负责加载和管理 Pinecone 向量数据库和 RAG 检索增强生成服务的配置参数。
提供配置验证、环境变量支持、默认值管理等功能。

作者: NeuronOS 开发团队
版本: 1.0.0
创建时间: 2024-01-20
"""

import json
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PineconeConfig:
    """Pinecone 配置"""
    api_key: str
    environment: str
    index_name: str
    dimension: int
    metric: str
    cloud: str
    region: str


@dataclass
class EmbeddingConfig:
    """嵌入模型配置"""
    model: str
    dimension: int
    batch_size: int
    cache_enabled: bool
    cache_max_size: int
    retry_attempts: int
    retry_delay: float


@dataclass
class RAGConfig:
    """RAG 服务配置"""
    default_mode: str
    default_strategy: str
    max_knowledge_items: int
    similarity_threshold: float
    context_window: int
    cache_enabled: bool
    cache_max_size: int
    retrieval_timeout: float


@dataclass
class KnowledgeManagementConfig:
    """知识管理配置"""
    default_validation_level: str
    default_batch_size: int
    auto_generate_id: bool
    overwrite_existing: bool
    supported_formats: list
    max_content_length: int
    min_content_length: int


@dataclass
class PerformanceConfig:
    """性能配置"""
    max_concurrent_embeddings: int
    max_concurrent_searches: int
    embedding_timeout: float
    search_timeout: float
    upload_timeout: float


@dataclass
class LoggingConfig:
    """日志配置"""
    level: str
    log_embeddings: bool
    log_searches: bool
    log_uploads: bool
    performance_logging: bool


class PineconeConfigManager:
    """Pinecone 配置管理器"""
    
    def __init__(self, config_path: Optional[str] = None):
        """初始化配置管理器
        
        Args:
            config_path: 配置文件路径，默认为 config/pinecone_config.json
        """
        if config_path is None:
            current_dir = Path(__file__).parent
            config_path = current_dir / "pinecone_config.json"
        
        self.config_path = Path(config_path)
        self._config_data: Optional[Dict[str, Any]] = None
        self._load_config()
    
    def _load_config(self) -> None:
        """加载配置文件"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self._config_data = json.load(f)
            else:
                raise FileNotFoundError(f"配置文件不存在: {self.config_path}")
        except Exception as e:
            raise RuntimeError(f"加载配置文件失败: {e}")
    
    def _get_env_value(self, key: str, default: Any = None) -> Any:
        """获取环境变量值
        
        Args:
            key: 环境变量键名
            default: 默认值
            
        Returns:
            环境变量值或默认值
        """
        env_key = f"NEURONOS_{key.upper()}"
        return os.getenv(env_key, default)
    
    def get_pinecone_config(self) -> PineconeConfig:
        """获取 Pinecone 配置"""
        config = self._config_data.get("pinecone", {})
        
        return PineconeConfig(
            api_key=self._get_env_value("pinecone_api_key", config.get("api_key")),
            environment=self._get_env_value("pinecone_environment", config.get("environment", "us-east-1-aws")),
            index_name=self._get_env_value("pinecone_index_name", config.get("index_name", "neuronos-knowledge")),
            dimension=int(self._get_env_value("pinecone_dimension", config.get("dimension", 1024))),
            metric=self._get_env_value("pinecone_metric", config.get("metric", "cosine")),
            cloud=self._get_env_value("pinecone_cloud", config.get("cloud", "aws")),
            region=self._get_env_value("pinecone_region", config.get("region", "us-east-1"))
        )
    
    def get_embedding_config(self) -> EmbeddingConfig:
        """获取嵌入模型配置"""
        config = self._config_data.get("embedding", {})
        
        return EmbeddingConfig(
            model=self._get_env_value("embedding_model", config.get("model", "text-embedding-3-small")),
            dimension=int(self._get_env_value("embedding_dimension", config.get("dimension", 1024))),
            batch_size=int(self._get_env_value("embedding_batch_size", config.get("batch_size", 100))),
            cache_enabled=bool(self._get_env_value("embedding_cache_enabled", config.get("cache_enabled", True))),
            cache_max_size=int(self._get_env_value("embedding_cache_max_size", config.get("cache_max_size", 1000))),
            retry_attempts=int(self._get_env_value("embedding_retry_attempts", config.get("retry_attempts", 3))),
            retry_delay=float(self._get_env_value("embedding_retry_delay", config.get("retry_delay", 1.0)))
        )
    
    def get_rag_config(self) -> RAGConfig:
        """获取 RAG 配置"""
        config = self._config_data.get("rag", {})
        
        return RAGConfig(
            default_mode=self._get_env_value("rag_default_mode", config.get("default_mode", "enhanced")),
            default_strategy=self._get_env_value("rag_default_strategy", config.get("default_strategy", "hybrid")),
            max_knowledge_items=int(self._get_env_value("rag_max_knowledge_items", config.get("max_knowledge_items", 5))),
            similarity_threshold=float(self._get_env_value("rag_similarity_threshold", config.get("similarity_threshold", 0.7))),
            context_window=int(self._get_env_value("rag_context_window", config.get("context_window", 4000))),
            cache_enabled=bool(self._get_env_value("rag_cache_enabled", config.get("cache_enabled", True))),
            cache_max_size=int(self._get_env_value("rag_cache_max_size", config.get("cache_max_size", 500))),
            retrieval_timeout=float(self._get_env_value("rag_retrieval_timeout", config.get("retrieval_timeout", 30.0)))
        )
    
    def get_knowledge_management_config(self) -> KnowledgeManagementConfig:
        """获取知识管理配置"""
        config = self._config_data.get("knowledge_management", {})
        
        return KnowledgeManagementConfig(
            default_validation_level=self._get_env_value("km_default_validation_level", config.get("default_validation_level", "moderate")),
            default_batch_size=int(self._get_env_value("km_default_batch_size", config.get("default_batch_size", 50))),
            auto_generate_id=bool(self._get_env_value("km_auto_generate_id", config.get("auto_generate_id", True))),
            overwrite_existing=bool(self._get_env_value("km_overwrite_existing", config.get("overwrite_existing", False))),
            supported_formats=config.get("supported_formats", ["json", "csv", "txt", "markdown"]),
            max_content_length=int(self._get_env_value("km_max_content_length", config.get("max_content_length", 5000))),
            min_content_length=int(self._get_env_value("km_min_content_length", config.get("min_content_length", 10)))
        )
    
    def get_performance_config(self) -> PerformanceConfig:
        """获取性能配置"""
        config = self._config_data.get("performance", {})
        
        return PerformanceConfig(
            max_concurrent_embeddings=int(self._get_env_value("perf_max_concurrent_embeddings", config.get("max_concurrent_embeddings", 10))),
            max_concurrent_searches=int(self._get_env_value("perf_max_concurrent_searches", config.get("max_concurrent_searches", 5))),
            embedding_timeout=float(self._get_env_value("perf_embedding_timeout", config.get("embedding_timeout", 30.0))),
            search_timeout=float(self._get_env_value("perf_search_timeout", config.get("search_timeout", 15.0))),
            upload_timeout=float(self._get_env_value("perf_upload_timeout", config.get("upload_timeout", 60.0)))
        )
    
    def get_logging_config(self) -> LoggingConfig:
        """获取日志配置"""
        config = self._config_data.get("logging", {})
        
        return LoggingConfig(
            level=self._get_env_value("log_level", config.get("level", "INFO")),
            log_embeddings=bool(self._get_env_value("log_embeddings", config.get("log_embeddings", False))),
            log_searches=bool(self._get_env_value("log_searches", config.get("log_searches", True))),
            log_uploads=bool(self._get_env_value("log_uploads", config.get("log_uploads", True))),
            performance_logging=bool(self._get_env_value("log_performance", config.get("performance_logging", True)))
        )
    
    def validate_config(self) -> bool:
        """验证配置有效性
        
        Returns:
            配置是否有效
        """
        try:
            pinecone_config = self.get_pinecone_config()
            embedding_config = self.get_embedding_config()
            rag_config = self.get_rag_config()
            
            # 验证必需的配置项
            if not pinecone_config.api_key or pinecone_config.api_key == "your-pinecone-api-key-here":
                raise ValueError("Pinecone API key 未配置")
            
            if pinecone_config.dimension != embedding_config.dimension:
                raise ValueError("Pinecone 和 Embedding 的维度不匹配")
            
            if pinecone_config.dimension != 1024:
                raise ValueError("向量维度必须为 1024")
            
            if rag_config.similarity_threshold < 0 or rag_config.similarity_threshold > 1:
                raise ValueError("相似度阈值必须在 0-1 之间")
            
            return True
            
        except Exception as e:
            print(f"配置验证失败: {e}")
            return False
    
    def reload_config(self) -> None:
        """重新加载配置"""
        self._load_config()


# 全局配置管理器实例
config_manager = PineconeConfigManager()


def get_config_manager() -> PineconeConfigManager:
    """获取配置管理器实例"""
    return config_manager


if __name__ == "__main__":
    # 测试配置加载
    try:
        manager = PineconeConfigManager()
        
        print("=== Pinecone 配置 ===")
        pinecone_config = manager.get_pinecone_config()
        print(f"Index Name: {pinecone_config.index_name}")
        print(f"Dimension: {pinecone_config.dimension}")
        print(f"Environment: {pinecone_config.environment}")
        
        print("\n=== Embedding 配置 ===")
        embedding_config = manager.get_embedding_config()
        print(f"Model: {embedding_config.model}")
        print(f"Dimension: {embedding_config.dimension}")
        print(f"Batch Size: {embedding_config.batch_size}")
        
        print("\n=== RAG 配置 ===")
        rag_config = manager.get_rag_config()
        print(f"Default Mode: {rag_config.default_mode}")
        print(f"Max Knowledge Items: {rag_config.max_knowledge_items}")
        print(f"Similarity Threshold: {rag_config.similarity_threshold}")
        
        print("\n=== 配置验证 ===")
        is_valid = manager.validate_config()
        print(f"配置有效性: {is_valid}")
        
    except Exception as e:
        print(f"配置测试失败: {e}")