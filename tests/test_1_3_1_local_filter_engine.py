#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1.3.1 本地过滤引擎功能测试
测试事件过滤、异常检测、白名单管理等核心功能
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, List, Any

# 添加项目路径
import sys
sys.path.append('/home/xzj/01_Project/B_25OS/src/backend')

from services.local_filter_engine import (
    LocalFilterEngine, FilterEngineConfig, create_filter_engine
)
from services.interfaces import FilterResult, FilterDecision
from services.falco_log_parser import StandardizedEvent, TripleExtraction, ActionType, EventPriority
from config.filter_engine_config import FilterEngineConfig as ConfigClass

class TestFilterEngineConfig:
    """过滤引擎配置测试类"""
    
    def test_default_config(self):
        """测试默认配置"""
        config = FilterEngineConfig()
        
        assert config.enabled is True
        assert config.max_concurrent_filters == 10
        assert config.priority_filter_enabled is True
        assert config.min_priority == "MEDIUM"
        assert config.ip_whitelist_enabled is True
        assert config.process_whitelist_enabled is True
        assert config.anomaly_detection_enabled is True
    
    def test_custom_config(self):
        """测试自定义配置"""
        config = FilterEngineConfig(
            enabled=False,
            max_concurrent_filters=5,
            min_priority="HIGH",
            ip_whitelist_enabled=False
        )
        
        assert config.enabled is False
        assert config.max_concurrent_filters == 5
        assert config.min_priority == "HIGH"
        assert config.ip_whitelist_enabled is False
    
    def test_whitelist_configuration(self):
        """测试白名单配置"""
        config = FilterEngineConfig()
        
        assert "127.0.0.1" in config.whitelist_ips
        assert "192.168.1.0/24" in config.whitelist_ips
        assert "systemd" in config.whitelist_processes
        assert "kernel" in config.whitelist_processes
        assert "root" in config.whitelist_users
    
    def test_config_validation(self):
        """测试配置验证"""
        config = FilterEngineConfig()
        assert config.validate() is True
        
        # 测试无效配置
        invalid_config = FilterEngineConfig(max_concurrent_filters=-1)
        assert invalid_config.validate() is False


class TestLocalFilterEngine:
    """本地过滤引擎测试类"""
    
    @pytest.fixture
    def config(self):
        """测试配置"""
        return FilterEngineConfig(
            enabled=True,
            max_concurrent_filters=5,
            priority_filter_enabled=True,
            min_priority="LOW",
            ip_whitelist_enabled=True,
            whitelist_ips=["127.0.0.1", "192.168.1.0/24"],
            process_whitelist_enabled=True,
            whitelist_processes=["systemd", "kernel"],
            anomaly_detection_enabled=True
        )
    
    @pytest.fixture
    def filter_engine(self, config):
        """创建过滤引擎实例"""
        return LocalFilterEngine(config)
    
    @pytest.fixture
    def sample_events(self):
        """样本事件数据"""
        events = []
        
        # 高优先级恶意事件
        triple1 = TripleExtraction(
            subject="attacker",
            action="write",
            object="/usr/bin/malware",
            subject_type="user",
            action_type=ActionType.FILE_WRITE,
            object_type="file",
            confidence=0.9
        )
        
        event1 = StandardizedEvent(
            event_id="malicious_001",
            timestamp=datetime.now(),
            priority=EventPriority.CRITICAL,
            rule_name="Write below binary dir",
            message="Malicious file write detected",
            triple=triple1,
            raw_data={"fd.name": "/usr/bin/malware"},
            host_info={"hostname": "target-host", "ip": "10.0.0.100"},
            process_info={"name": "malware", "pid": 12345, "user": "attacker"}
        )
        events.append(event1)
        
        # 正常系统事件
        triple2 = TripleExtraction(
            subject="systemd",
            action="start",
            object="service",
            subject_type="process",
            action_type=ActionType.PROCESS_EXEC,
            object_type="service",
            confidence=0.8
        )
        
        event2 = StandardizedEvent(
            event_id="system_001",
            timestamp=datetime.now(),
            priority=EventPriority.INFO,
            rule_name="Service started",
            message="System service started",
            triple=triple2,
            raw_data={"proc.name": "systemd"},
            host_info={"hostname": "target-host", "ip": "127.0.0.1"},
            process_info={"name": "systemd", "pid": 1, "user": "root"}
        )
        events.append(event2)
        
        # 可疑网络连接
        triple3 = TripleExtraction(
            subject="wget",
            action="connect",
            object="203.0.113.42:80",
            subject_type="process",
            action_type=ActionType.NETWORK_CONN,
            object_type="network",
            confidence=0.85
        )
        
        event3 = StandardizedEvent(
            event_id="network_001",
            timestamp=datetime.now(),
            priority=EventPriority.WARNING,
            rule_name="Outbound connection",
            message="Suspicious outbound connection",
            triple=triple3,
            raw_data={"fd.rip": "203.0.113.42", "fd.rport": 80},
            host_info={"hostname": "target-host", "ip": "10.0.0.100"},
            process_info={"name": "wget", "pid": 23456, "user": "www-data"}
        )
        events.append(event3)
        
        return events
    
    def test_engine_initialization(self, filter_engine, config):
        """测试引擎初始化"""
        assert filter_engine.config == config
        assert filter_engine._is_running is False
        assert filter_engine._active_filters == 0
        assert filter_engine._statistics.total_processed == 0
    
    @pytest.mark.asyncio
    async def test_engine_lifecycle(self, filter_engine):
        """测试引擎生命周期"""
        # 启动引擎
        await filter_engine.start_engine()
        assert filter_engine._is_running is True
        
        # 停止引擎
        await filter_engine.stop_engine()
        assert filter_engine._is_running is False
    
    @pytest.mark.asyncio
    async def test_priority_filter(self, filter_engine, sample_events):
        """测试优先级过滤"""
        await filter_engine.start_engine()
        
        try:
            # 测试高优先级事件
            high_priority_event = sample_events[0]  # CRITICAL
            result = await filter_engine.process_event(high_priority_event)
            
            assert result['decision'] in [FilterDecision.PASS.value, FilterDecision.SUSPICIOUS.value]
            assert result['confidence'] > 0.5
            
            # 测试低优先级事件（如果最小优先级设置较高）
            filter_engine.config.min_priority = "HIGH"
            
            # 创建一个不在白名单中的低优先级事件
            from datetime import datetime
            
            triple = TripleExtraction(
                subject="unknown_app",
                action="read",
                object="/etc/passwd",
                subject_type="process",
                action_type=ActionType.FILE_READ,
                object_type="file",
                confidence=0.6
            )
            
            low_priority_event = StandardizedEvent(
                event_id="low_priority_001",
                timestamp=datetime.now(),
                priority=EventPriority.INFO,
                rule_name="Low priority test",
                message="Test low priority filtering",
                triple=triple,
                raw_data={"test": "data"},
                host_info={"hostname": "test-host", "ip": "10.0.0.200"},
                process_info={"name": "unknown_app", "pid": 8888, "user": "test"}
            )
            
            result = await filter_engine.process_event(low_priority_event)
            
            # 低优先级事件可能被阻止
            assert result['decision'] in [FilterDecision.BLOCK.value, FilterDecision.PASS.value]
            
        finally:
            await filter_engine.stop_engine()
    
    @pytest.mark.asyncio
    async def test_ip_whitelist_filter(self, filter_engine, sample_events):
        """测试IP白名单过滤"""
        await filter_engine.start_engine()
        
        try:
            # 创建一个只有IP在白名单但进程不在白名单的事件
            from datetime import datetime
            
            triple = TripleExtraction(
                subject="unknown_process",
                action="write",
                object="/tmp/test",
                subject_type="process",
                action_type=ActionType.FILE_WRITE,
                object_type="file",
                confidence=0.8
            )
            
            ip_whitelist_event = StandardizedEvent(
                event_id="ip_test_001",
                timestamp=datetime.now(),
                priority=EventPriority.INFO,
                rule_name="Test event",
                message="Test IP whitelist",
                triple=triple,
                raw_data={"test": "data"},
                host_info={"hostname": "test-host", "ip": "127.0.0.1"},
                process_info={"name": "unknown_process", "pid": 9999, "user": "test"}
            )
            
            result = await filter_engine.process_event(ip_whitelist_event)
            
            assert result['decision'] == FilterDecision.WHITELIST.value
            assert 'whitelist_reason' in result
            assert 'ip' in result['whitelist_reason']
            
            # 测试非白名单IP事件
            non_whitelist_event = sample_events[0]  # 192.168.1.100
            result = await filter_engine.process_event(non_whitelist_event)
            
            assert result['decision'] != FilterDecision.WHITELIST.value
            
        finally:
            await filter_engine.stop_engine()
    
    @pytest.mark.asyncio
    async def test_process_whitelist_filter(self, filter_engine, sample_events):
        """测试进程白名单过滤"""
        await filter_engine.start_engine()
        
        try:
            # 测试白名单进程事件
            whitelist_event = sample_events[1]  # systemd
            result = await filter_engine.process_event(whitelist_event)
            
            assert result['decision'] == FilterDecision.WHITELIST.value
            assert 'whitelist_reason' in result
            assert 'process' in result['whitelist_reason']
            
            # 测试非白名单进程事件
            non_whitelist_event = sample_events[0]  # malware
            result = await filter_engine.process_event(non_whitelist_event)
            
            assert result['decision'] != FilterDecision.WHITELIST.value
            
        finally:
            await filter_engine.stop_engine()
    
    @pytest.mark.asyncio
    async def test_anomaly_detection(self, filter_engine, sample_events):
        """测试异常检测"""
        await filter_engine.start_engine()
        
        try:
            # 测试可疑事件
            suspicious_event = sample_events[0]  # 恶意文件写入
            result = await filter_engine.process_event(suspicious_event)
            
            # 应该被标记为可疑或阻止
            assert result['decision'] in [FilterDecision.SUSPICIOUS.value, FilterDecision.BLOCK.value]
            assert result['confidence'] > 0.7
            
            # 检查异常检测结果
            if 'anomaly_score' in result:
                assert result['anomaly_score']['total_score'] > 0.5
            
        finally:
            await filter_engine.stop_engine()
    
    @pytest.mark.asyncio
    async def test_concurrent_processing(self, filter_engine, sample_events):
        """测试并发处理"""
        await filter_engine.start_engine()
        
        try:
            # 并发处理多个事件
            tasks = []
            for event in sample_events:
                task = asyncio.create_task(filter_engine.process_event(event))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            # 验证所有事件都被处理
            assert len(results) == len(sample_events)
            for result in results:
                assert 'decision' in result
                assert 'confidence' in result
                assert 'processing_time' in result
            
        finally:
            await filter_engine.stop_engine()
    
    @pytest.mark.asyncio
    async def test_filter_chain(self, filter_engine, sample_events):
        """测试过滤链"""
        await filter_engine.start_engine()
        
        try:
            event = sample_events[0]
            result = await filter_engine.process_event(event)
            
            # 验证过滤链信息
            assert 'filter_chain' in result
            assert isinstance(result['filter_chain'], list)
            
            # 验证每个过滤器的结果
            for filter_result in result['filter_chain']:
                assert 'filter_name' in filter_result
                assert 'decision' in filter_result
                assert 'processing_time' in filter_result
            
        finally:
            await filter_engine.stop_engine()
    
    @pytest.mark.asyncio
    async def test_statistics_tracking(self, filter_engine, sample_events):
        """测试统计信息跟踪"""
        await filter_engine.start_engine()
        
        try:
            initial_stats = filter_engine.get_statistics()
            assert initial_stats['total_events'] == 0
            
            # 处理一些事件
            for event in sample_events:
                await filter_engine.process_event(event)
            
            updated_stats = filter_engine.get_statistics()
            assert updated_stats['total_events'] == len(sample_events)
            assert updated_stats['passed_events'] >= 0
            assert updated_stats['blocked_events'] >= 0
            assert updated_stats['suspicious_events'] >= 0
            assert updated_stats['whitelisted_events'] >= 0
            
        finally:
            await filter_engine.stop_engine()
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, filter_engine, sample_events):
        """测试性能指标"""
        await filter_engine.start_engine()
        
        try:
            # 处理一些事件
            for event in sample_events:
                await filter_engine.process_event(event)
            
            metrics = filter_engine.get_performance_metrics()
            
            assert 'avg_processing_time' in metrics
            assert 'events_per_second' in metrics
            assert 'filter_efficiency' in metrics
            assert 'memory_usage' in metrics
            
            assert metrics['avg_processing_time'] > 0
            assert metrics['events_per_second'] >= 0
            
        finally:
            await filter_engine.stop_engine()
    
    @pytest.mark.asyncio
    async def test_filter_configuration_update(self, filter_engine):
        """测试过滤器配置更新"""
        await filter_engine.start_engine()
        
        try:
            # 更新配置
            new_config = FilterEngineConfig(
                enabled=True,
                min_priority="HIGH",
                ip_whitelist_enabled=False
            )
            
            await filter_engine.update_config(new_config)
            
            assert filter_engine.config.min_priority == "HIGH"
            assert filter_engine.config.ip_whitelist_enabled is False
            
        finally:
            await filter_engine.stop_engine()
    
    @pytest.mark.asyncio
    async def test_error_handling(self, filter_engine):
        """测试错误处理"""
        await filter_engine.start_engine()
        
        try:
            # 测试无效事件
            invalid_event = None
            result = await filter_engine.process_event(invalid_event)
            
            assert result['decision'] == FilterDecision.BLOCK.value
            assert 'error' in result
            
            # 测试缺失字段的事件
            incomplete_event = StandardizedEvent(
                event_id="incomplete_001",
                timestamp=datetime.now(),
                priority=EventPriority.INFO,
                rule_name="Test",
                message="Test",
                triple=None,  # 缺失三元组
                raw_data={},
                host_info={},
                process_info={}
            )
            
            result = await filter_engine.process_event(incomplete_event)
            assert 'decision' in result
            
        finally:
            await filter_engine.stop_engine()
    
    @pytest.mark.asyncio
    async def test_filter_bypass(self, filter_engine, sample_events):
        """测试过滤器绕过"""
        # 禁用过滤引擎
        filter_engine.config.enabled = False
        
        await filter_engine.start_engine()
        
        try:
            event = sample_events[0]
            result = await filter_engine.process_event(event)
            
            # 禁用时应该直接通过
            assert result['decision'] == FilterDecision.PASS.value
            assert result['bypass_reason'] == 'engine_disabled'
            
        finally:
            await filter_engine.stop_engine()
    
    def test_whitelist_management(self, filter_engine):
        """测试白名单管理"""
        # 添加IP到白名单
        filter_engine.add_to_ip_whitelist("10.0.0.1")
        assert "10.0.0.1" in filter_engine.config.whitelist_ips
        
        # 从白名单移除IP
        filter_engine.remove_from_ip_whitelist("10.0.0.1")
        assert "10.0.0.1" not in filter_engine.config.whitelist_ips
        
        # 添加进程到白名单
        filter_engine.add_to_process_whitelist("test_process")
        assert "test_process" in filter_engine.config.whitelist_processes
        
        # 从白名单移除进程
        filter_engine.remove_from_process_whitelist("test_process")
        assert "test_process" not in filter_engine.config.whitelist_processes
    
    @pytest.mark.asyncio
    async def test_filter_engine_factory(self):
        """测试过滤引擎工厂函数"""
        config = FilterEngineConfig(enabled=True)
        engine = create_filter_engine(config)
        
        assert isinstance(engine, LocalFilterEngine)
        assert engine.config == config
        
        await engine.start_engine()
        assert engine._is_running is True
        
        await engine.stop_engine()
        assert engine._is_running is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])