#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAG配置加载器
负责加载和管理RAG服务的配置参数
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

class Environment(Enum):
    """环境类型"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

@dataclass
class PineconeConfig:
    """Pinecone配置"""
    api_key: str
    index_name: str
    dimension: int
    metric: str
    cloud: str
    region: str
    batch_size: int
    max_retries: int
    timeout: int
    cache_enabled: bool
    cache_max_size: int
    cache_ttl: int

@dataclass
class OpenAIConfig:
    """OpenAI配置"""
    api_key: str
    embedding_model: str
    embedding_dimensions: int
    max_retries: int
    timeout: int
    base_url: Optional[str]
    requests_per_minute: int
    tokens_per_minute: int

@dataclass
class RAGConfig:
    """RAG服务配置"""
    default_top_k: int
    max_top_k: int
    similarity_threshold: float
    context_window: int
    max_knowledge_items: int
    relevance_weight: float
    diversity_weight: float
    type_preference: Dict[str, float]
    cache_enabled: bool
    cache_max_size: int
    cache_ttl: int
    cleanup_interval: int

@dataclass
class KnowledgeManagementConfig:
    """知识管理配置"""
    supported_formats: list
    max_file_size: int
    batch_size: int
    validation_level: str
    auto_generate_id: bool
    default_format: str
    max_items_per_export: int
    include_metadata: bool
    templates: Dict[str, Dict[str, list]]

@dataclass
class LoggingConfig:
    """日志配置"""
    level: str
    format: str
    file_enabled: bool
    file_path: str
    file_max_size: int
    file_backup_count: int
    console_enabled: bool
    console_level: str
    loggers: Dict[str, str]

@dataclass
class MonitoringConfig:
    """监控配置"""
    metrics_enabled: bool
    collection_interval: int
    retention_period: int
    thresholds: Dict[str, float]
    alerts_enabled: bool
    email_notifications: bool
    webhook_url: Optional[str]

@dataclass
class SecurityConfig:
    """安全配置"""
    rotation_enabled: bool
    rotation_interval_days: int
    encrypt_sensitive_data: bool
    mask_personal_info: bool
    audit_log_enabled: bool
    rate_limiting: bool
    ip_whitelist: list
    require_authentication: bool

class RAGConfigLoader:
    """RAG配置加载器"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # 确定配置文件路径
        if config_path:
            self.config_path = Path(config_path)
        else:
            # 默认配置文件路径
            project_root = Path(__file__).parent.parent.parent.parent
            self.config_path = project_root / "config" / "rag_config.yaml"
        
        self.config_data: Dict[str, Any] = {}
        self.environment = Environment.DEVELOPMENT
        
        # 加载配置
        self._load_config()
        self._apply_environment_overrides()
        self._substitute_environment_variables()
    
    def _load_config(self) -> None:
        """加载配置文件"""
        try:
            if not self.config_path.exists():
                self.logger.warning(f"配置文件不存在: {self.config_path}，使用默认配置")
                self.config_data = self._get_default_config()
                return
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config_data = yaml.safe_load(f)
            
            self.logger.info(f"配置文件加载成功: {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"加载配置文件失败: {e}")
            self.config_data = self._get_default_config()
    
    def _apply_environment_overrides(self) -> None:
        """应用环境特定的配置覆盖"""
        try:
            # 获取当前环境
            env_name = os.getenv('ENVIRONMENT', 'development')
            self.environment = Environment(env_name)
            
            # 应用环境覆盖
            overrides = self.config_data.get('environment', {}).get('overrides', {})
            env_overrides = overrides.get(env_name, {})
            
            if env_overrides:
                self._deep_update(self.config_data, env_overrides)
                self.logger.info(f"应用环境覆盖配置: {env_name}")
            
        except Exception as e:
            self.logger.error(f"应用环境覆盖失败: {e}")
    
    def _substitute_environment_variables(self) -> None:
        """替换环境变量"""
        try:
            self._substitute_env_vars_recursive(self.config_data)
            self.logger.debug("环境变量替换完成")
            
        except Exception as e:
            self.logger.error(f"环境变量替换失败: {e}")
    
    def _substitute_env_vars_recursive(self, obj: Any) -> Any:
        """递归替换环境变量"""
        if isinstance(obj, dict):
            return {k: self._substitute_env_vars_recursive(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._substitute_env_vars_recursive(item) for item in obj]
        elif isinstance(obj, str) and obj.startswith('${') and obj.endswith('}'):
            # 提取环境变量名
            env_var = obj[2:-1]
            default_value = None
            
            # 支持默认值语法: ${VAR_NAME:default_value}
            if ':' in env_var:
                env_var, default_value = env_var.split(':', 1)
            
            return os.getenv(env_var, default_value)
        else:
            return obj
    
    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """深度更新字典"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                # 支持点号分隔的键路径
                if '.' in key:
                    keys = key.split('.')
                    current = base_dict
                    for k in keys[:-1]:
                        if k not in current:
                            current[k] = {}
                        current = current[k]
                    current[keys[-1]] = value
                else:
                    base_dict[key] = value
    
    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            'pinecone': {
                'api_key': None,
                'index_name': 'b25os-knowledge-base',
                'dimension': 1024,
                'metric': 'cosine',
                'cloud': 'aws',
                'region': 'us-east-1',
                'batch_size': 100,
                'max_retries': 3,
                'timeout': 30,
                'cache_enabled': True,
                'cache_max_size': 1000,
                'cache_ttl': 3600
            },
            'openai': {
                'api_key': None,
                'embedding_model': 'text-embedding-3-large',
                'embedding_dimensions': 1024,
                'max_retries': 3,
                'timeout': 30,
                'base_url': None,
                'requests_per_minute': 3000,
                'tokens_per_minute': 1000000
            },
            'rag': {
                'retrieval': {
                    'default_top_k': 5,
                    'max_top_k': 20,
                    'similarity_threshold': 0.7,
                    'context_window': 4000
                },
                'fusion': {
                    'max_knowledge_items': 10,
                    'relevance_weight': 0.7,
                    'diversity_weight': 0.3,
                    'type_preference': {
                        'security_rule': 1.0,
                        'threat_pattern': 0.9,
                        'incident_case': 0.8,
                        'remediation_guide': 0.85,
                        'best_practice': 0.7,
                        'vulnerability_info': 0.9
                    }
                },
                'cache': {
                    'enabled': True,
                    'max_size': 500,
                    'ttl': 1800,
                    'cleanup_interval': 300
                }
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': {
                    'enabled': True,
                    'path': 'logs/rag_service.log',
                    'max_size': 10485760,
                    'backup_count': 5
                },
                'console': {
                    'enabled': True,
                    'level': 'INFO'
                }
            }
        }
    
    def get_pinecone_config(self) -> PineconeConfig:
        """获取Pinecone配置"""
        config = self.config_data.get('pinecone', {})
        return PineconeConfig(
            api_key=config.get('api_key'),
            index_name=config.get('index_name', 'b25os-knowledge-base'),
            dimension=config.get('dimension', 1024),
            metric=config.get('metric', 'cosine'),
            cloud=config.get('cloud', 'aws'),
            region=config.get('region', 'us-east-1'),
            batch_size=config.get('batch_size', 100),
            max_retries=config.get('max_retries', 3),
            timeout=config.get('timeout', 30),
            cache_enabled=config.get('cache_enabled', True),
            cache_max_size=config.get('cache_max_size', 1000),
            cache_ttl=config.get('cache_ttl', 3600)
        )
    
    def get_openai_config(self) -> OpenAIConfig:
        """获取OpenAI配置"""
        config = self.config_data.get('openai', {})
        return OpenAIConfig(
            api_key=config.get('api_key'),
            embedding_model=config.get('embedding_model', 'text-embedding-3-large'),
            embedding_dimensions=config.get('embedding_dimensions', 1024),
            max_retries=config.get('max_retries', 3),
            timeout=config.get('timeout', 30),
            base_url=config.get('base_url'),
            requests_per_minute=config.get('requests_per_minute', 3000),
            tokens_per_minute=config.get('tokens_per_minute', 1000000)
        )
    
    def get_rag_config(self) -> RAGConfig:
        """获取RAG配置"""
        rag_config = self.config_data.get('rag', {})
        retrieval = rag_config.get('retrieval', {})
        fusion = rag_config.get('fusion', {})
        cache = rag_config.get('cache', {})
        
        return RAGConfig(
            default_top_k=retrieval.get('default_top_k', 5),
            max_top_k=retrieval.get('max_top_k', 20),
            similarity_threshold=retrieval.get('similarity_threshold', 0.7),
            context_window=retrieval.get('context_window', 4000),
            max_knowledge_items=fusion.get('max_knowledge_items', 10),
            relevance_weight=fusion.get('relevance_weight', 0.7),
            diversity_weight=fusion.get('diversity_weight', 0.3),
            type_preference=fusion.get('type_preference', {}),
            cache_enabled=cache.get('enabled', True),
            cache_max_size=cache.get('max_size', 500),
            cache_ttl=cache.get('ttl', 1800),
            cleanup_interval=cache.get('cleanup_interval', 300)
        )
    
    def get_knowledge_management_config(self) -> KnowledgeManagementConfig:
        """获取知识管理配置"""
        config = self.config_data.get('knowledge_management', {})
        import_config = config.get('import', {})
        export_config = config.get('export', {})
        
        return KnowledgeManagementConfig(
            supported_formats=import_config.get('supported_formats', ['json', 'csv', 'txt', 'markdown']),
            max_file_size=import_config.get('max_file_size', 10485760),
            batch_size=import_config.get('batch_size', 50),
            validation_level=import_config.get('validation_level', 'moderate'),
            auto_generate_id=import_config.get('auto_generate_id', True),
            default_format=export_config.get('default_format', 'json'),
            max_items_per_export=export_config.get('max_items_per_export', 1000),
            include_metadata=export_config.get('include_metadata', True),
            templates=config.get('templates', {})
        )
    
    def get_logging_config(self) -> LoggingConfig:
        """获取日志配置"""
        config = self.config_data.get('logging', {})
        file_config = config.get('file', {})
        console_config = config.get('console', {})
        
        return LoggingConfig(
            level=config.get('level', 'INFO'),
            format=config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            file_enabled=file_config.get('enabled', True),
            file_path=file_config.get('path', 'logs/rag_service.log'),
            file_max_size=file_config.get('max_size', 10485760),
            file_backup_count=file_config.get('backup_count', 5),
            console_enabled=console_config.get('enabled', True),
            console_level=console_config.get('level', 'INFO'),
            loggers=config.get('loggers', {})
        )
    
    def get_monitoring_config(self) -> MonitoringConfig:
        """获取监控配置"""
        config = self.config_data.get('monitoring', {})
        metrics = config.get('metrics', {})
        alerts = config.get('alerts', {})
        
        return MonitoringConfig(
            metrics_enabled=metrics.get('enabled', True),
            collection_interval=metrics.get('collection_interval', 60),
            retention_period=metrics.get('retention_period', 86400),
            thresholds=config.get('thresholds', {}),
            alerts_enabled=alerts.get('enabled', True),
            email_notifications=alerts.get('email_notifications', False),
            webhook_url=alerts.get('webhook_url')
        )
    
    def get_security_config(self) -> SecurityConfig:
        """获取安全配置"""
        config = self.config_data.get('security', {})
        api_keys = config.get('api_keys', {})
        data_protection = config.get('data_protection', {})
        access_control = config.get('access_control', {})
        
        return SecurityConfig(
            rotation_enabled=api_keys.get('rotation_enabled', False),
            rotation_interval_days=api_keys.get('rotation_interval_days', 90),
            encrypt_sensitive_data=data_protection.get('encrypt_sensitive_data', True),
            mask_personal_info=data_protection.get('mask_personal_info', True),
            audit_log_enabled=data_protection.get('audit_log_enabled', True),
            rate_limiting=access_control.get('rate_limiting', True),
            ip_whitelist=access_control.get('ip_whitelist', []),
            require_authentication=access_control.get('require_authentication', False)
        )
    
    def get_config_value(self, key_path: str, default: Any = None) -> Any:
        """获取配置值（支持点号分隔的键路径）"""
        try:
            keys = key_path.split('.')
            value = self.config_data
            
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return default
            
            return value
            
        except Exception as e:
            self.logger.error(f"获取配置值失败: {key_path}, {e}")
            return default
    
    def reload_config(self) -> bool:
        """重新加载配置"""
        try:
            self._load_config()
            self._apply_environment_overrides()
            self._substitute_environment_variables()
            self.logger.info("配置重新加载成功")
            return True
            
        except Exception as e:
            self.logger.error(f"配置重新加载失败: {e}")
            return False
    
    def validate_config(self) -> bool:
        """验证配置完整性"""
        try:
            # 验证必需的配置项
            required_configs = [
                'pinecone.api_key',
                'openai.api_key',
                'pinecone.index_name',
                'openai.embedding_model'
            ]
            
            missing_configs = []
            for config_key in required_configs:
                value = self.get_config_value(config_key)
                if value is None:
                    missing_configs.append(config_key)
            
            if missing_configs:
                self.logger.error(f"缺少必需的配置项: {missing_configs}")
                return False
            
            self.logger.info("配置验证通过")
            return True
            
        except Exception as e:
            self.logger.error(f"配置验证失败: {e}")
            return False
    
    @property
    def is_development(self) -> bool:
        """是否为开发环境"""
        return self.environment == Environment.DEVELOPMENT
    
    @property
    def is_production(self) -> bool:
        """是否为生产环境"""
        return self.environment == Environment.PRODUCTION

# 全局配置实例
_config_loader: Optional[RAGConfigLoader] = None

def get_config_loader(config_path: Optional[str] = None) -> RAGConfigLoader:
    """获取配置加载器实例（单例模式）"""
    global _config_loader
    
    if _config_loader is None:
        _config_loader = RAGConfigLoader(config_path)
    
    return _config_loader

def reload_config() -> bool:
    """重新加载配置"""
    global _config_loader
    
    if _config_loader:
        return _config_loader.reload_config()
    
    return False