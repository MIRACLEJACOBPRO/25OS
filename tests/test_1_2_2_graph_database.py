#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1.2.2 图数据库功能测试
测试Neo4j图数据库操作、节点创建、关系建立等核心功能
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, List, Any

# 添加项目路径
import sys
sys.path.append('/home/xzj/01_Project/B_25OS/src/backend')

from services.graph_database import (
    GraphDatabase, GraphDatabaseManager, EventNode, ProcessNode, 
    UserNode, FileNode, HostNode, RuleNode
)
from services.falco_log_parser import StandardizedEvent, TripleExtraction, ActionType, EventPriority

class TestGraphDatabase:
    """图数据库测试类"""
    
    @pytest.fixture
    def mock_neo4j_driver(self):
        """模拟Neo4j驱动"""
        mock_driver = Mock()
        mock_session = Mock()
        
        # 正确设置上下文管理器
        mock_context_manager = Mock()
        mock_context_manager.__enter__ = Mock(return_value=mock_session)
        mock_context_manager.__exit__ = Mock(return_value=None)
        mock_driver.session.return_value = mock_context_manager
        
        # 模拟查询结果
        mock_result = Mock()
        mock_result.single.return_value = {'count': 1}
        mock_result.data.return_value = [{'n': {'id': 'test_id'}}]
        mock_session.run.return_value = mock_result
        
        return mock_driver
    
    @pytest.fixture
    def graph_db(self, mock_neo4j_driver):
        """创建图数据库实例"""
        with patch('services.graph_database.GraphDatabase._create_driver') as mock_create:
            mock_create.return_value = mock_neo4j_driver
            db = GraphDatabase()
            return db
    
    @pytest.fixture
    def sample_event(self):
        """样本标准化事件"""
        triple = TripleExtraction(
            subject="root",
            action="write",
            object="/usr/bin/malware",
            subject_type="user",
            action_type=ActionType.FILE_WRITE,
            object_type="file",
            confidence=0.9
        )
        
        return StandardizedEvent(
            event_id="test_event_001",
            timestamp=datetime.now(),
            priority=EventPriority.ERROR,
            rule_name="Write below binary dir",
            message="File below a known binary directory opened for writing",
            triple=triple,
            raw_data={
                "proc.name": "touch",
                "proc.pid": 12345,
                "fd.name": "/usr/bin/malware"
            },
            host_info={"hostname": "test-host", "container_id": "host"},
            process_info={"name": "touch", "pid": 12345, "user": "root", "uid": 0, "gid": 0}
        )
    
    def test_database_initialization(self, graph_db):
        """测试数据库初始化"""
        assert graph_db is not None
        assert hasattr(graph_db, '_driver')
        assert hasattr(graph_db, '_uri')
        assert hasattr(graph_db, '_auth')
    
    def test_connection_test(self, graph_db):
        """测试数据库连接"""
        # 测试连接
        is_connected = graph_db.test_connection()
        assert is_connected is True
    
    @pytest.mark.asyncio
    async def test_store_event(self, graph_db, sample_event):
        """测试存储事件"""
        result = await graph_db.store_event(sample_event)
        assert result is True
    
    def test_create_event_node(self, graph_db, sample_event):
        """测试创建事件节点"""
        node = graph_db._create_event_node(sample_event)
        
        assert isinstance(node, EventNode)
        assert node.event_id == sample_event.event_id
        assert node.timestamp == sample_event.timestamp
        assert node.priority == sample_event.priority.value
        assert node.rule_name == sample_event.rule_name
        assert node.message == sample_event.message
    
    def test_create_process_node(self, graph_db, sample_event):
        """测试创建进程节点"""
        node = graph_db._create_process_node(sample_event)
        
        assert isinstance(node, ProcessNode)
        assert node.name == "touch"
        assert node.pid == 12345
        assert node.user == "root"
    
    def test_create_user_node(self, graph_db, sample_event):
        """测试创建用户节点"""
        node = graph_db._create_user_node(sample_event)
        
        assert isinstance(node, UserNode)
        assert node.name == "root"
        assert node.uid is not None
    
    def test_create_file_node(self, graph_db, sample_event):
        """测试创建文件节点"""
        node = graph_db._create_file_node(sample_event)
        
        assert isinstance(node, FileNode)
        assert node.path == "/usr/bin/malware"
        assert node.name == "malware"
        assert node.directory == "/usr/bin"
    
    def test_create_host_node(self, graph_db, sample_event):
        """测试创建主机节点"""
        node = graph_db._create_host_node(sample_event)
        
        assert isinstance(node, HostNode)
        assert node.hostname == "test-host"
        assert node.container_id == "host"
    
    def test_create_rule_node(self, graph_db, sample_event):
        """测试创建规则节点"""
        node = graph_db._create_rule_node(sample_event)
        
        assert isinstance(node, RuleNode)
        assert node.name == "Write below binary dir"
        assert node.priority == sample_event.priority.value
    
    @pytest.mark.asyncio
    async def test_create_relationships(self, graph_db, sample_event):
        """测试创建关系"""
        # 创建节点
        event_node = graph_db._create_event_node(sample_event)
        process_node = graph_db._create_process_node(sample_event)
        user_node = graph_db._create_user_node(sample_event)
        file_node = graph_db._create_file_node(sample_event)
        host_node = graph_db._create_host_node(sample_event)
        rule_node = graph_db._create_rule_node(sample_event)
        
        # 测试创建关系
        result = await graph_db._create_relationships(
            event_node, process_node, user_node, file_node, host_node, rule_node
        )
        assert result is True
    
    @pytest.mark.asyncio
    async def test_get_related_events(self, graph_db):
        """测试获取相关事件"""
        event_id = "test_event_001"
        related_events = await graph_db.get_related_events(event_id)
        
        assert isinstance(related_events, list)
    
    @pytest.mark.asyncio
    async def test_find_suspicious_patterns(self, graph_db):
        """测试查找可疑模式"""
        patterns = await graph_db.find_suspicious_patterns()
        
        assert isinstance(patterns, list)
    
    @pytest.mark.asyncio
    async def test_get_process_tree(self, graph_db):
        """测试获取进程树"""
        process_id = "touch_12345"
        tree = await graph_db.get_process_tree(process_id)
        
        assert isinstance(tree, dict)
    
    @pytest.mark.asyncio
    async def test_get_file_access_history(self, graph_db):
        """测试获取文件访问历史"""
        file_path = "/usr/bin/malware"
        history = await graph_db.get_file_access_history(file_path)
        
        assert isinstance(history, list)
    
    @pytest.mark.asyncio
    async def test_get_user_activity(self, graph_db):
        """测试获取用户活动"""
        username = "root"
        activity = await graph_db.get_user_activity(username)
        
        assert isinstance(activity, list)
    
    @pytest.mark.asyncio
    async def test_get_network_connections(self, graph_db):
        """测试获取网络连接"""
        host = "test-host"
        connections = await graph_db.get_network_connections(host)
        
        assert isinstance(connections, list)
    
    def test_query_builder(self, graph_db):
        """测试查询构建器"""
        # 测试简单查询
        query = graph_db._build_node_query("Event", {"event_id": "test_001"})
        assert "MATCH" in query
        assert "Event" in query
        assert "event_id" in query
        
        # 测试关系查询
        rel_query = graph_db._build_relationship_query(
            "Event", "Process", "TRIGGERED_BY", {"event_id": "test_001"}
        )
        assert "MATCH" in rel_query
        assert "TRIGGERED_BY" in rel_query
    
    @pytest.mark.asyncio
    async def test_batch_operations(self, graph_db):
        """测试批量操作"""
        # 创建多个样本事件
        events = []
        for i in range(3):
            triple = TripleExtraction(
                subject=f"user_{i}",
                action="execute",
                object=f"process_{i}",
                subject_type="user",
                action_type=ActionType.PROCESS_EXEC,
                object_type="process",
                confidence=0.8
            )
            
            event = StandardizedEvent(
                event_id=f"test_event_{i:03d}",
                timestamp=datetime.now(),
                priority=EventPriority.NOTICE,
                rule_name="Test Rule",
                message=f"Test event {i}",
                triple=triple,
                raw_data={},
                host_info={"hostname": "test-host"},
                process_info={"name": f"process_{i}", "pid": 1000 + i}
            )
            events.append(event)
        
        # 批量存储
        results = await graph_db.store_events_batch(events)
        assert len(results) == len(events)
        assert all(results)
    
    def test_error_handling(self, graph_db):
        """测试错误处理"""
        # 测试无效连接
        with patch.object(graph_db, 'driver') as mock_driver:
            mock_driver.session.side_effect = Exception("Connection failed")
            
            is_connected = graph_db.test_connection()
            assert is_connected is False
    
    @pytest.mark.asyncio
    async def test_transaction_handling(self, graph_db, sample_event):
        """测试事务处理"""
        # 测试事务成功
        result = await graph_db.store_event(sample_event)
        assert result is True
        
        # 测试事务失败回滚
        with patch.object(graph_db, 'driver') as mock_driver:
            mock_session = Mock()
            mock_driver.session.return_value.__enter__.return_value = mock_session
            mock_session.run.side_effect = Exception("Transaction failed")
            
            result = await graph_db.store_event(sample_event)
            assert result is False


class TestGraphDatabaseManager:
    """图数据库管理器测试类"""
    
    @pytest.fixture
    def mock_graph_db(self):
        """模拟图数据库"""
        mock_db = Mock(spec=GraphDatabase)
        mock_db.test_connection.return_value = True
        mock_db.store_event = AsyncMock(return_value=True)
        mock_db.get_related_events = AsyncMock(return_value=[])
        return mock_db
    
    @pytest.fixture
    def db_manager(self, mock_graph_db):
        """创建数据库管理器"""
        with patch('services.graph_database.GraphDatabase') as mock_class:
            mock_class.return_value = mock_graph_db
            manager = GraphDatabaseManager()
            return manager
    
    def test_manager_initialization(self, db_manager):
        """测试管理器初始化"""
        assert db_manager is not None
        assert hasattr(db_manager, '_db')
        assert hasattr(db_manager, '_connection_pool')
    
    @pytest.mark.asyncio
    async def test_connection_management(self, db_manager):
        """测试连接管理"""
        # 测试获取连接
        connection = await db_manager.get_connection()
        assert connection is not None
        
        # 测试释放连接
        await db_manager.release_connection(connection)
    
    @pytest.mark.asyncio
    async def test_health_check(self, db_manager):
        """测试健康检查"""
        health_status = await db_manager.health_check()
        assert isinstance(health_status, dict)
        assert 'status' in health_status
        assert 'connection_count' in health_status
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, db_manager):
        """测试性能指标"""
        metrics = await db_manager.get_performance_metrics()
        assert isinstance(metrics, dict)
        assert 'query_count' in metrics
        assert 'avg_query_time' in metrics
        assert 'error_count' in metrics
    
    @pytest.mark.asyncio
    async def test_cleanup_old_data(self, db_manager):
        """测试清理旧数据"""
        days_to_keep = 30
        result = await db_manager.cleanup_old_data(days_to_keep)
        assert isinstance(result, dict)
        assert 'deleted_nodes' in result
        assert 'deleted_relationships' in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])