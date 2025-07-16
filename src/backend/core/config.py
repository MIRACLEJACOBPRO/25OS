#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS Backend Configuration
应用配置管理
"""

import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """应用配置类"""
    
    # 应用基础配置
    app_name: str = "NeuronOS Security Monitoring"
    app_version: str = "1.0.0"
    debug: bool = Field(default=False, env="DEBUG")
    
    # 服务器配置
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    
    # Neo4j数据库配置
    neo4j_uri: str = Field(default="bolt://localhost:7687", env="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", env="NEO4J_USER")
    neo4j_password: str = Field(default="neuronos123", env="NEO4J_PASSWORD")
    neo4j_database: str = Field(default="neo4j", env="NEO4J_DATABASE")
    
    # OpenAI配置
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4", env="OPENAI_MODEL")
    openai_temperature: float = Field(default=0.1, env="OPENAI_TEMPERATURE")
    
    # Pinecone配置
    pinecone_api_key: Optional[str] = Field(default=None, env="PINECONE_API_KEY")
    pinecone_environment: str = Field(default="us-east-1-aws", env="PINECONE_ENVIRONMENT")
    pinecone_index_name: str = Field(default="neuronos-knowledge", env="PINECONE_INDEX_NAME")
    
    # Falco日志配置
    falco_log_path: str = Field(
        default="/home/xzj/01_Project/B_25OS/logs/falco_events.log",
        env="FALCO_LOG_PATH"
    )
    
    # 日志配置
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: str = Field(
        default="/home/xzj/01_Project/B_25OS/logs/backend.log",
        env="LOG_FILE"
    )
    
    # 性能配置
    max_workers: int = Field(default=4, env="MAX_WORKERS")
    batch_size: int = Field(default=100, env="BATCH_SIZE")
    processing_interval: int = Field(default=5, env="PROCESSING_INTERVAL")  # 秒
    
    # 日志量控制配置
    log_volume_control_enabled: bool = Field(default=True, env="LOG_VOLUME_CONTROL_ENABLED")
    max_log_file_size: int = Field(default=100 * 1024 * 1024, env="MAX_LOG_FILE_SIZE")  # 100MB
    max_log_files: int = Field(default=10, env="MAX_LOG_FILES")
    log_compression_enabled: bool = Field(default=True, env="LOG_COMPRESSION_ENABLED")
    log_compression_delay: int = Field(default=3600, env="LOG_COMPRESSION_DELAY")  # 1小时
    base_sampling_rate: float = Field(default=1.0, env="BASE_SAMPLING_RATE")
    max_events_per_second: int = Field(default=1000, env="MAX_EVENTS_PER_SECOND")
    sampling_window: int = Field(default=60, env="SAMPLING_WINDOW")  # 秒
    log_archive_directory: str = Field(
        default="/home/xzj/01_Project/B_25OS/logs/archive",
        env="LOG_ARCHIVE_DIRECTORY"
    )
    
    # 安全配置
    secret_key: str = Field(
        default="neuronos-secret-key-change-in-production",
        env="SECRET_KEY"
    )
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"  # 忽略额外的环境变量

# 创建全局配置实例
settings = Settings()

# 验证必要的配置
def validate_settings():
    """验证必要的配置项"""
    required_fields = [
        ("openai_api_key", settings.openai_api_key),
        ("pinecone_api_key", settings.pinecone_api_key),
    ]
    
    missing_fields = []
    for field_name, field_value in required_fields:
        if not field_value:
            missing_fields.append(field_name)
    
    if missing_fields:
        raise ValueError(f"Missing required configuration: {', '.join(missing_fields)}")
    
    return True

# 在导入时验证配置
if __name__ != "__main__":
    try:
        validate_settings()
    except ValueError as e:
        print(f"Configuration error: {e}")
        print("Please check your environment variables or .env file")