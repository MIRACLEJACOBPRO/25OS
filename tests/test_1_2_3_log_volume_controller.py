#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1.2.3 日志量控制器功能测试
测试日志采样、压缩、优先级控制等核心功能
"""

import pytest
import tempfile
import os
import json
import gzip
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

# 添加项目路径
import sys
sys.path.append('/home/xzj/01_Project/B_25OS/src/backend')

from services.log_volume_controller import (
    LogVolumeController, LogVolumeConfig, LogPriority,
    CompressionType, SamplingStrategy
)

class TestLogVolumeConfig:
    """日志量配置测试类"""
    
    def test_default_config(self):
        """测试默认配置"""
        config = LogVolumeConfig()
        
        assert config.max_file_size == 100 * 1024 * 1024  # 100MB
        assert config.max_files_per_day == 1000
        assert config.enable_compression is True
        assert config.compression_type == CompressionType.GZIP
        assert config.sampling_strategy == SamplingStrategy.PRIORITY_BASED
        assert config.base_sampling_rate == 1.0
        assert config.enable_dynamic_sampling is True
    
    def test_custom_config(self):
        """测试自定义配置"""
        config = LogVolumeConfig(
            max_file_size=50 * 1024 * 1024,
            max_files_per_day=500,
            enable_compression=False,
            base_sampling_rate=0.5
        )
        
        assert config.max_file_size == 50 * 1024 * 1024
        assert config.max_files_per_day == 500
        assert config.enable_compression is False
        assert config.base_sampling_rate == 0.5
    
    def test_priority_weights(self):
        """测试优先级权重"""
        config = LogVolumeConfig()
        
        assert config.priority_weights[LogPriority.CRITICAL] == 1.0
        assert config.priority_weights[LogPriority.ERROR] == 0.9
        assert config.priority_weights[LogPriority.WARNING] == 0.7
        assert config.priority_weights[LogPriority.NOTICE] == 0.5
        assert config.priority_weights[LogPriority.INFO] == 0.3
        assert config.priority_weights[LogPriority.DEBUG] == 0.1
    
    def test_critical_rules(self):
        """测试关键规则配置"""
        config = LogVolumeConfig()
        
        assert "Write below binary dir" in config.critical_rules
        assert "Terminal shell in container" in config.critical_rules
        assert "Outbound connection to C2 server" in config.critical_rules
        assert len(config.critical_rules) > 0


class TestLogVolumeController:
    """日志量控制器测试类"""
    
    @pytest.fixture
    def config(self):
        """测试配置"""
        return LogVolumeConfig(
            max_file_size=1 * 1024 * 1024,  # 1MB
            enable_compression=True,
            base_sampling_rate=1.0,
            enable_dynamic_sampling=False  # 禁用动态采样以便测试
        )
    
    @pytest.fixture
    def controller(self, config):
        """创建控制器实例"""
        return LogVolumeController(config)
    
    @pytest.fixture
    def sample_events(self):
        """样本事件数据"""
        return [
            {
                "rule": "Write below binary dir",
                "priority": "Critical",
                "process_name": "touch",
                "user_name": "root",
                "file_path": "/usr/bin/malware",
                "process_pid": 12345,
                "timestamp": datetime.now().isoformat()
            },
            {
                "rule": "Terminal shell in container",
                "priority": "Notice",
                "process_name": "bash",
                "user_name": "attacker",
                "file_path": "/bin/bash",
                "process_pid": 23456,
                "timestamp": datetime.now().isoformat()
            },
            {
                "rule": "Normal process execution",
                "priority": "Info",
                "process_name": "ls",
                "user_name": "user",
                "file_path": "/bin/ls",
                "process_pid": 34567,
                "timestamp": datetime.now().isoformat()
            }
        ]
    
    def test_controller_initialization(self, controller, config):
        """测试控制器初始化"""
        assert controller.config == config
        assert controller._current_sampling_rate == config.base_sampling_rate
        assert controller._processed_hashes == set()
        assert controller._statistics['total_events'] == 0
    
    def test_priority_mapping(self, controller):
        """测试优先级映射"""
        priority_tests = [
            ("Critical", LogPriority.CRITICAL),
            ("Error", LogPriority.ERROR),
            ("Warning", LogPriority.WARNING),
            ("Notice", LogPriority.NOTICE),
            ("Informational", LogPriority.INFO),
            ("Info", LogPriority.INFO),
            ("Debug", LogPriority.DEBUG),
            ("Unknown", LogPriority.INFO)  # 默认值
        ]
        
        for priority_str, expected_priority in priority_tests:
            event = {"priority": priority_str}
            mapped_priority = controller._get_event_priority(event)
            assert mapped_priority == expected_priority
    
    def test_critical_event_detection(self, controller):
        """测试关键事件检测"""
        # 关键事件
        critical_event = {
            "rule": "Write below binary dir",
            "priority": "Notice"
        }
        assert controller._is_critical_event(critical_event) is True
        
        # 普通事件
        normal_event = {
            "rule": "Normal file access",
            "priority": "Info"
        }
        assert controller._is_critical_event(normal_event) is False
    
    def test_event_hashing(self, controller):
        """测试事件哈希"""
        event1 = {
            "rule": "Test rule",
            "process_name": "test_process",
            "user_name": "test_user",
            "file_path": "/tmp/test"
        }
        
        event2 = {
            "rule": "Test rule",
            "process_name": "test_process",
            "user_name": "test_user",
            "file_path": "/tmp/test"
        }
        
        event3 = {
            "rule": "Different rule",
            "process_name": "test_process",
            "user_name": "test_user",
            "file_path": "/tmp/test"
        }
        
        hash1 = controller._calculate_event_hash(event1)
        hash2 = controller._calculate_event_hash(event2)
        hash3 = controller._calculate_event_hash(event3)
        
        assert hash1 == hash2  # 相同事件应该有相同哈希
        assert hash1 != hash3  # 不同事件应该有不同哈希
    
    def test_sampling_decision_critical_events(self, controller):
        """测试关键事件采样决策"""
        critical_event = {
            "rule": "Write below binary dir",
            "priority": "Critical",
            "process_name": "touch",
            "user_name": "root",
            "file_path": "/usr/bin/malware",
            "process_pid": 12345,
            "timestamp": datetime.now().isoformat()
        }
        
        # 关键事件应该总是被采样
        for _ in range(10):
            assert controller.should_sample_event(critical_event) is True
    
    def test_sampling_decision_priority_based(self, controller):
        """测试基于优先级的采样决策"""
        # 测试不同优先级的采样率
        priorities = ['Critical', 'Error', 'Warning', 'Notice', 'Info', 'Debug']
        
        for priority in priorities:
            event = {
                "rule": f"Test {priority} rule",
                "priority": priority,
                "process_name": "test_process",
                "user_name": "test_user",
                "file_path": "/tmp/test",
                "process_pid": 12345,
                "timestamp": datetime.now().isoformat()
            }
            
            # 清空哈希缓存
            controller._processed_hashes.clear()
            
            # 测试多次采样
            sampled_count = 0
            total_count = 100
            
            for i in range(total_count):
                test_event = event.copy()
                test_event["process_pid"] = 12345 + i  # 确保每个事件都不同
                if controller.should_sample_event(test_event):
                    sampled_count += 1
            
            sampling_rate = sampled_count / total_count
            
            # 验证采样率符合预期（允许一定误差）
            priority_enum = controller._get_event_priority(event)
            expected_weight = controller.config.priority_weights.get(priority_enum, 0.1)
            expected_rate = controller._current_sampling_rate * expected_weight
            
            # 允许20%的误差
            assert abs(sampling_rate - expected_rate) <= 0.2
    
    def test_duplicate_event_filtering(self, controller):
        """测试重复事件过滤"""
        event = {
            "rule": "Test rule",
            "priority": "Critical",
            "process_name": "test_process",
            "user_name": "test_user",
            "file_path": "/tmp/test",
            "process_pid": 12345,
            "timestamp": datetime.now().isoformat()
        }
        
        # 第一次应该被采样
        assert controller.should_sample_event(event) is True
        
        # 相同事件再次出现应该被过滤（除非是关键事件）
        # 由于这是Critical事件，可能仍然被采样
        # 但哈希应该被记录
        event_hash = controller._calculate_event_hash(event)
        assert event_hash in controller._processed_hashes
    
    def test_dynamic_sampling_rate_calculation(self, controller):
        """测试动态采样率计算"""
        # 启用动态采样
        controller.config.enable_dynamic_sampling = True
        
        # 模拟高负载情况
        controller._statistics['events_per_minute'] = 1000
        
        dynamic_rate = controller._calculate_dynamic_sampling_rate()
        assert 0 <= dynamic_rate <= 1.0
        
        # 模拟低负载情况
        controller._statistics['events_per_minute'] = 10
        
        dynamic_rate = controller._calculate_dynamic_sampling_rate()
        assert dynamic_rate >= controller.config.base_sampling_rate * 0.5
    
    def test_statistics_tracking(self, controller, sample_events):
        """测试统计信息跟踪"""
        initial_stats = controller.get_statistics()
        assert initial_stats['total_events'] == 0
        assert initial_stats['sampled_events'] == 0
        
        # 处理一些事件
        for event in sample_events:
            controller.should_sample_event(event)
        
        updated_stats = controller.get_statistics()
        assert updated_stats['total_events'] == len(sample_events)
        assert updated_stats['sampled_events'] >= 0
        assert updated_stats['sampling_rate'] >= 0
    
    def test_file_size_monitoring(self, controller):
        """测试文件大小监控"""
        # 创建临时文件
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"x" * (2 * 1024 * 1024))  # 2MB文件
            temp_file_path = temp_file.name
        
        try:
            # 检查文件大小
            file_size = controller._get_file_size(temp_file_path)
            assert file_size == 2 * 1024 * 1024
            
            # 检查是否超过限制
            exceeds_limit = controller._file_exceeds_size_limit(temp_file_path)
            assert exceeds_limit is True  # 2MB > 1MB限制
            
        finally:
            os.unlink(temp_file_path)
    
    def test_compression_functionality(self, controller):
        """测试压缩功能"""
        # 创建测试数据
        test_data = "This is test log data that should be compressed." * 100
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as temp_file:
            temp_file.write(test_data.encode())
            temp_file_path = temp_file.name
        
        try:
            # 压缩文件
            compressed_path = controller._compress_file(temp_file_path)
            
            assert compressed_path.endswith('.gz')
            assert os.path.exists(compressed_path)
            
            # 验证压缩后的文件可以解压
            with gzip.open(compressed_path, 'rt') as f:
                decompressed_data = f.read()
                assert decompressed_data == test_data
            
            # 清理
            os.unlink(compressed_path)
            
        finally:
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    def test_log_rotation(self, controller):
        """测试日志轮转"""
        # 创建临时目录
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            
            # 创建多个日志文件
            for i in range(5):
                log_file = log_dir / f"test_{i}.log"
                log_file.write_text("test data" * 1000)
            
            # 执行日志轮转
            rotated_files = controller._rotate_logs(str(log_dir), max_files=3)
            
            # 验证只保留了指定数量的文件
            remaining_files = list(log_dir.glob("*.log"))
            assert len(remaining_files) <= 3
    
    def test_performance_metrics(self, controller, sample_events):
        """测试性能指标"""
        # 处理一些事件来生成指标
        for event in sample_events:
            controller.should_sample_event(event)
        
        metrics = controller.get_performance_metrics()
        
        assert 'avg_processing_time' in metrics
        assert 'events_per_second' in metrics
        assert 'memory_usage' in metrics
        assert 'cpu_usage' in metrics
        
        assert metrics['avg_processing_time'] >= 0
        assert metrics['events_per_second'] >= 0
    
    def test_configuration_update(self, controller):
        """测试配置更新"""
        # 更新配置
        new_config = LogVolumeConfig(
            max_file_size=50 * 1024 * 1024,
            base_sampling_rate=0.5
        )
        
        controller.update_config(new_config)
        
        assert controller.config.max_file_size == 50 * 1024 * 1024
        assert controller.config.base_sampling_rate == 0.5
        assert controller._current_sampling_rate == 0.5
    
    def test_error_handling(self, controller):
        """测试错误处理"""
        # 测试无效事件
        invalid_event = None
        result = controller.should_sample_event(invalid_event)
        assert result is False
        
        # 测试缺失字段的事件
        incomplete_event = {"rule": "Test rule"}
        result = controller.should_sample_event(incomplete_event)
        assert isinstance(result, bool)
    
    def test_cleanup_old_hashes(self, controller):
        """测试清理旧哈希"""
        # 添加一些哈希
        for i in range(1000):
            controller._processed_hashes.add(f"hash_{i}")
        
        initial_count = len(controller._processed_hashes)
        assert initial_count == 1000
        
        # 清理旧哈希
        controller._cleanup_old_hashes(max_hashes=500)
        
        final_count = len(controller._processed_hashes)
        assert final_count <= 500


if __name__ == "__main__":
    pytest.main([__file__, "-v"])