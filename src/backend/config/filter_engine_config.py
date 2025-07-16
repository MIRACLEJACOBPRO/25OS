#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS 过滤引擎配置模块

提供过滤引擎的配置管理功能，包括:
1. 过滤器配置
2. 白名单配置
3. 性能配置
4. 监控配置
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from pathlib import Path
from enum import Enum


class EventPriority(Enum):
    """事件优先级枚举"""
    EMERGENCY = "Emergency"
    ALERT = "Alert"
    CRITICAL = "Critical"
    ERROR = "Error"
    WARNING = "Warning"
    NOTICE = "Notice"
    INFO = "Informational"
    DEBUG = "Debug"


@dataclass
class FilterEngineConfig:
    """过滤引擎配置类"""
    
    # 基础配置
    enabled: bool = True
    max_concurrent_filters: int = 10
    correlation_window: int = 300  # 秒
    
    # 过滤器配置
    priority_filter_enabled: bool = True
    min_priority: str = "NOTICE"
    
    frequency_filter_enabled: bool = True
    max_events_per_minute: int = 100
    frequency_time_window: int = 60
    
    ip_whitelist_enabled: bool = True
    whitelist_ips: List[str] = field(default_factory=lambda: [
        "127.0.0.1",
        "::1",
        "192.168.1.0/24",
        "10.0.0.0/8"
    ])
    
    process_whitelist_enabled: bool = True
    whitelist_processes: List[str] = field(default_factory=lambda: [
        "systemd",
        "kernel",
        "docker",
        "ssh"
    ])
    
    pattern_filter_enabled: bool = True
    block_patterns: List[str] = field(default_factory=lambda: [
        r".*malware.*",
        r".*suspicious.*",
        r".*attack.*"
    ])
    allow_patterns: List[str] = field(default_factory=lambda: [
        r".*system.*",
        r".*kernel.*",
        r".*docker.*"
    ])
    
    adaptive_filter_enabled: bool = False
    adaptive_learning_window: int = 1000
    
    # 白名单配置
    whitelist_file: Optional[str] = None
    
    # 性能配置
    enable_statistics: bool = True
    statistics_interval: int = 60  # 秒
    
    # 日志配置
    log_level: str = "INFO"
    log_filtered_events: bool = True
    
    # 异常检测配置
    anomaly_threshold: float = 0.7
    correlation_threshold: float = 0.8
    
    @classmethod
    def from_file(cls, config_path: str) -> 'FilterEngineConfig':
        """从配置文件加载配置"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # 创建配置实例
            config = cls()
            
            # 更新配置值
            for key, value in config_data.items():
                if hasattr(config, key):
                    setattr(config, key, value)
            
            return config
            
        except FileNotFoundError:
            # 如果文件不存在，返回默认配置
            return cls()
        except Exception as e:
            raise ValueError(f"配置文件加载失败: {e}")
    
    def to_file(self, config_path: str) -> None:
        """保存配置到文件"""
        try:
            # 确保目录存在
            Path(config_path).parent.mkdir(parents=True, exist_ok=True)
            
            # 转换为字典
            config_dict = {
                "enabled": self.enabled,
                "max_concurrent_filters": self.max_concurrent_filters,
                "correlation_window": self.correlation_window,
                "priority_filter_enabled": self.priority_filter_enabled,
                "min_priority": self.min_priority,
                "frequency_filter_enabled": self.frequency_filter_enabled,
                "max_events_per_minute": self.max_events_per_minute,
                "frequency_time_window": self.frequency_time_window,
                "ip_whitelist_enabled": self.ip_whitelist_enabled,
                "whitelist_ips": self.whitelist_ips,
                "process_whitelist_enabled": self.process_whitelist_enabled,
                "whitelist_processes": self.whitelist_processes,
                "pattern_filter_enabled": self.pattern_filter_enabled,
                "block_patterns": self.block_patterns,
                "allow_patterns": self.allow_patterns,
                "adaptive_filter_enabled": self.adaptive_filter_enabled,
                "adaptive_learning_window": self.adaptive_learning_window,
                "whitelist_file": self.whitelist_file,
                "enable_statistics": self.enable_statistics,
                "statistics_interval": self.statistics_interval,
                "log_level": self.log_level,
                "log_filtered_events": self.log_filtered_events,
                "anomaly_threshold": self.anomaly_threshold,
                "correlation_threshold": self.correlation_threshold
            }
            
            # 保存到文件
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            raise ValueError(f"配置文件保存失败: {e}")
    
    def validate(self) -> bool:
        """验证配置有效性"""
        try:
            # 验证优先级
            if self.min_priority.upper() not in [p.name for p in EventPriority]:
                return False
            
            # 验证数值范围
            if self.max_concurrent_filters <= 0:
                return False
            
            if self.correlation_window <= 0:
                return False
            
            if self.max_events_per_minute <= 0:
                return False
            
            if self.frequency_time_window <= 0:
                return False
            
            if not (0.0 <= self.anomaly_threshold <= 1.0):
                return False
            
            if not (0.0 <= self.correlation_threshold <= 1.0):
                return False
            
            return True
            
        except Exception:
            return False
    
    def get_default_config_path(self) -> str:
        """获取默认配置文件路径"""
        return "/home/xzj/01_Project/B_25OS/config/filter_engine_config.json"
    
    def update_from_dict(self, config_dict: Dict[str, Any]) -> None:
        """从字典更新配置"""
        for key, value in config_dict.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "enabled": self.enabled,
            "max_concurrent_filters": self.max_concurrent_filters,
            "correlation_window": self.correlation_window,
            "priority_filter_enabled": self.priority_filter_enabled,
            "min_priority": self.min_priority,
            "frequency_filter_enabled": self.frequency_filter_enabled,
            "max_events_per_minute": self.max_events_per_minute,
            "frequency_time_window": self.frequency_time_window,
            "ip_whitelist_enabled": self.ip_whitelist_enabled,
            "whitelist_ips": self.whitelist_ips,
            "process_whitelist_enabled": self.process_whitelist_enabled,
            "whitelist_processes": self.whitelist_processes,
            "pattern_filter_enabled": self.pattern_filter_enabled,
            "block_patterns": self.block_patterns,
            "allow_patterns": self.allow_patterns,
            "adaptive_filter_enabled": self.adaptive_filter_enabled,
            "adaptive_learning_window": self.adaptive_learning_window,
            "whitelist_file": self.whitelist_file,
            "enable_statistics": self.enable_statistics,
            "statistics_interval": self.statistics_interval,
            "log_level": self.log_level,
            "log_filtered_events": self.log_filtered_events,
            "anomaly_threshold": self.anomaly_threshold,
            "correlation_threshold": self.correlation_threshold
        }


# 默认配置实例
DEFAULT_CONFIG = FilterEngineConfig()


def load_config(config_path: Optional[str] = None) -> FilterEngineConfig:
    """加载配置"""
    if config_path is None:
        config_path = DEFAULT_CONFIG.get_default_config_path()
    
    return FilterEngineConfig.from_file(config_path)


def save_config(config: FilterEngineConfig, config_path: Optional[str] = None) -> None:
    """保存配置"""
    if config_path is None:
        config_path = config.get_default_config_path()
    
    config.to_file(config_path)


def create_default_config_file(config_path: Optional[str] = None) -> None:
    """创建默认配置文件"""
    if config_path is None:
        config_path = DEFAULT_CONFIG.get_default_config_path()
    
    # 确保目录存在
    Path(config_path).parent.mkdir(parents=True, exist_ok=True)
    
    # 保存默认配置
    DEFAULT_CONFIG.to_file(config_path)


if __name__ == "__main__":
    # 创建默认配置文件
    create_default_config_file()
    print("默认配置文件已创建")