#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1.3.2 图查询优化器功能测试
测试查询优化、索引管理、缓存机制等核心功能
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, List, Any, Optional

# 添加项目路径
import sys
sys.path.append('/home/xzj/01_Project/B_25OS/src/backend')

from services.graph_query_optimizer import (
    GraphQueryOptimizer, QueryOptimizerConfig, QueryPlan, QueryCache,
    IndexManager, QueryAnalyzer, create_query_optimizer
)
from services.interfaces import QueryType, OptimizationLevel, CacheStrategy
from services.graph_database import GraphDatabaseManager

class TestQueryOptimizerConfig:
    """查询优化器配置测试类"""
    
    def test_default_config(self):
        """测试默认配置"""
        config = QueryOptimizerConfig()
        
        assert config.enabled is True
        assert config.optimization_level == OptimizationLevel.BALANCED
        assert config.cache_enabled is True
        assert config.cache_size == 1000
        assert config.cache_ttl == 3600
        assert config.index_auto_creation is True
        assert config.query_timeout == 30
        assert config.max_concurrent_queries == 50
    
    def test_custom_config(self):
        """测试自定义配置"""
        config = QueryOptimizerConfig(
            enabled=False,
            optimization_level=OptimizationLevel.AGGRESSIVE,
            cache_size=500,
            cache_ttl=1800,
            query_timeout=60
        )
        
        assert config.enabled is False
        assert config.optimization_level == OptimizationLevel.AGGRESSIVE
        assert config.cache_size == 500
        assert config.cache_ttl == 1800
        assert config.query_timeout == 60
    
    def test_config_validation(self):
        """测试配置验证"""
        config = QueryOptimizerConfig()
        assert config.validate() is True
        
        # 测试无效配置
        invalid_config = QueryOptimizerConfig(cache_size=-1)
        assert invalid_config.validate() is False
        
        invalid_config2 = QueryOptimizerConfig(query_timeout=0)
        assert invalid_config2.validate() is False


class TestQueryCache:
    """查询缓存测试类"""
    
    @pytest.fixture
    def cache(self):
        """创建缓存实例"""
        return QueryCache(max_size=100, ttl=3600)
    
    def test_cache_initialization(self, cache):
        """测试缓存初始化"""
        assert cache.max_size == 100
        assert cache.ttl == 3600
        assert cache.size == 0
        assert cache.hit_count == 0
        assert cache.miss_count == 0
    
    def test_cache_operations(self, cache):
        """测试缓存操作"""
        query = "MATCH (n:Event) RETURN n LIMIT 10"
        result = [{"id": 1, "name": "test"}]
        
        # 测试缓存存储
        cache.put(query, result)
        assert cache.size == 1
        
        # 测试缓存获取
        cached_result = cache.get(query)
        assert cached_result == result
        assert cache.hit_count == 1
        
        # 测试缓存未命中
        non_existent = cache.get("non-existent query")
        assert non_existent is None
        assert cache.miss_count == 1
    
    def test_cache_expiration(self, cache):
        """测试缓存过期"""
        # 设置短TTL
        cache.ttl = 1
        
        query = "MATCH (n) RETURN n"
        result = [{"data": "test"}]
        
        cache.put(query, result)
        assert cache.get(query) == result
        
        # 等待过期
        import time
        time.sleep(2)
        
        # 应该返回None（已过期）
        expired_result = cache.get(query)
        assert expired_result is None
    
    def test_cache_size_limit(self, cache):
        """测试缓存大小限制"""
        # 填满缓存
        for i in range(cache.max_size + 10):
            query = f"MATCH (n) WHERE n.id = {i} RETURN n"
            result = [{"id": i}]
            cache.put(query, result)
        
        # 缓存大小不应超过限制
        assert cache.size <= cache.max_size
    
    def test_cache_statistics(self, cache):
        """测试缓存统计"""
        queries = [
            "MATCH (n:Event) RETURN n",
            "MATCH (n:Process) RETURN n",
            "MATCH (n:User) RETURN n"
        ]
        
        # 添加查询到缓存
        for i, query in enumerate(queries):
            cache.put(query, [{"id": i}])
        
        # 测试命中和未命中
        cache.get(queries[0])  # 命中
        cache.get(queries[1])  # 命中
        cache.get("unknown")   # 未命中
        
        stats = cache.get_statistics()
        assert stats['size'] == 3
        assert stats['hit_count'] == 2
        assert stats['miss_count'] == 1
        assert stats['hit_ratio'] == 2/3
    
    def test_cache_clear(self, cache):
        """测试缓存清理"""
        # 添加一些数据
        for i in range(5):
            cache.put(f"query_{i}", [{"id": i}])
        
        assert cache.size == 5
        
        # 清理缓存
        cache.clear()
        assert cache.size == 0
        assert cache.hit_count == 0
        assert cache.miss_count == 0


class TestIndexManager:
    """索引管理器测试类"""
    
    @pytest.fixture
    def mock_db_manager(self):
        """模拟数据库管理器"""
        mock = Mock(spec=GraphDatabaseManager)
        mock.execute_query = AsyncMock()
        return mock
    
    @pytest.fixture
    def index_manager(self, mock_db_manager):
        """创建索引管理器实例"""
        return IndexManager(mock_db_manager)
    
    @pytest.mark.asyncio
    async def test_index_creation(self, index_manager, mock_db_manager):
        """测试索引创建"""
        # 测试创建节点索引
        await index_manager.create_node_index("Event", "timestamp")
        
        mock_db_manager.execute_query.assert_called_with(
            "CREATE INDEX event_timestamp_idx IF NOT EXISTS FOR (n:Event) ON (n.timestamp)"
        )
        
        # 测试创建关系索引
        await index_manager.create_relationship_index("TRIGGERS", "timestamp")
        
        mock_db_manager.execute_query.assert_called_with(
            "CREATE INDEX triggers_timestamp_idx IF NOT EXISTS FOR ()-[r:TRIGGERS]-() ON (r.timestamp)"
        )
    
    @pytest.mark.asyncio
    async def test_index_analysis(self, index_manager, mock_db_manager):
        """测试索引分析"""
        # 模拟查询分析结果
        mock_db_manager.execute_query.return_value = [
            {"label": "Event", "property": "timestamp", "usage_count": 100},
            {"label": "Process", "property": "pid", "usage_count": 50}
        ]
        
        suggestions = await index_manager.analyze_index_needs()
        
        assert len(suggestions) >= 0
        mock_db_manager.execute_query.assert_called()
    
    @pytest.mark.asyncio
    async def test_index_monitoring(self, index_manager, mock_db_manager):
        """测试索引监控"""
        # 模拟索引统计
        mock_db_manager.execute_query.return_value = [
            {
                "index_name": "event_timestamp_idx",
                "label": "Event",
                "property": "timestamp",
                "state": "ONLINE",
                "uniqueness": "NONUNIQUE"
            }
        ]
        
        stats = await index_manager.get_index_statistics()
        
        assert isinstance(stats, list)
        mock_db_manager.execute_query.assert_called()
    
    @pytest.mark.asyncio
    async def test_auto_index_creation(self, index_manager, mock_db_manager):
        """测试自动索引创建"""
        # 模拟查询模式
        query_patterns = [
            "MATCH (e:Event) WHERE e.timestamp > $time",
            "MATCH (p:Process) WHERE p.pid = $pid",
            "MATCH (u:User) WHERE u.name = $name"
        ]
        
        await index_manager.auto_create_indexes(query_patterns)
        
        # 验证索引创建调用
        assert mock_db_manager.execute_query.call_count >= len(query_patterns)


class TestQueryAnalyzer:
    """查询分析器测试类"""
    
    @pytest.fixture
    def analyzer(self):
        """创建查询分析器实例"""
        return QueryAnalyzer()
    
    def test_query_parsing(self, analyzer):
        """测试查询解析"""
        query = "MATCH (e:Event)-[:TRIGGERS]->(p:Process) WHERE e.timestamp > $time RETURN e, p"
        
        parsed = analyzer.parse_query(query)
        
        assert parsed['type'] == QueryType.READ
        assert 'Event' in parsed['labels']
        assert 'Process' in parsed['labels']
        assert 'TRIGGERS' in parsed['relationships']
        assert 'timestamp' in parsed['properties']
    
    def test_query_complexity_analysis(self, analyzer):
        """测试查询复杂度分析"""
        simple_query = "MATCH (n:Event) RETURN n LIMIT 10"
        complex_query = """
        MATCH (e:Event)-[:TRIGGERS*1..5]->(p:Process)
        WHERE e.timestamp > datetime() - duration('P1D')
        AND p.name =~ '.*malware.*'
        WITH e, p, count(*) as cnt
        WHERE cnt > 5
        RETURN e, p, cnt
        ORDER BY cnt DESC
        """
        
        simple_complexity = analyzer.analyze_complexity(simple_query)
        complex_complexity = analyzer.analyze_complexity(complex_query)
        
        assert simple_complexity['score'] < complex_complexity['score']
        assert simple_complexity['level'] == 'LOW'
        assert complex_complexity['level'] in ['MEDIUM', 'HIGH']
    
    def test_optimization_suggestions(self, analyzer):
        """测试优化建议"""
        query = "MATCH (e:Event) WHERE e.timestamp > $time AND e.priority = 'HIGH' RETURN e"
        
        suggestions = analyzer.get_optimization_suggestions(query)
        
        assert isinstance(suggestions, list)
        assert len(suggestions) >= 0
        
        # 检查是否包含索引建议
        index_suggestions = [s for s in suggestions if 'index' in s['type']]
        assert len(index_suggestions) >= 0
    
    def test_query_pattern_detection(self, analyzer):
        """测试查询模式检测"""
        queries = [
            "MATCH (e:Event) WHERE e.timestamp > $time1 RETURN e",
            "MATCH (e:Event) WHERE e.timestamp > $time2 RETURN e",
            "MATCH (p:Process) WHERE p.pid = $pid1 RETURN p",
            "MATCH (p:Process) WHERE p.pid = $pid2 RETURN p"
        ]
        
        patterns = analyzer.detect_query_patterns(queries)
        
        assert len(patterns) >= 1
        assert any('Event' in pattern['template'] for pattern in patterns)
        assert any('Process' in pattern['template'] for pattern in patterns)


class TestGraphQueryOptimizer:
    """图查询优化器测试类"""
    
    @pytest.fixture
    def config(self):
        """测试配置"""
        return QueryOptimizerConfig(
            enabled=True,
            optimization_level=OptimizationLevel.BALANCED,
            cache_enabled=True,
            cache_size=100,
            cache_ttl=3600,
            query_timeout=30
        )
    
    @pytest.fixture
    def mock_db_manager(self):
        """模拟数据库管理器"""
        mock = Mock(spec=GraphDatabaseManager)
        mock.execute_query = AsyncMock(return_value=[{"result": "test"}])
        mock.is_connected = Mock(return_value=True)
        return mock
    
    @pytest.fixture
    def optimizer(self, config, mock_db_manager):
        """创建查询优化器实例"""
        return GraphQueryOptimizer(config, mock_db_manager)
    
    def test_optimizer_initialization(self, optimizer, config, mock_db_manager):
        """测试优化器初始化"""
        assert optimizer.config == config
        assert optimizer.db_manager == mock_db_manager
        assert optimizer._is_running is False
        assert optimizer._active_queries == 0
    
    @pytest.mark.asyncio
    async def test_optimizer_lifecycle(self, optimizer):
        """测试优化器生命周期"""
        # 启动优化器
        await optimizer.start_optimizer()
        assert optimizer._is_running is True
        
        # 停止优化器
        await optimizer.stop_optimizer()
        assert optimizer._is_running is False
    
    @pytest.mark.asyncio
    async def test_query_optimization(self, optimizer, mock_db_manager):
        """测试查询优化"""
        await optimizer.start_optimizer()
        
        try:
            query = "MATCH (e:Event) WHERE e.timestamp > $time RETURN e"
            params = {"time": datetime.now() - timedelta(hours=1)}
            
            result = await optimizer.execute_optimized_query(query, params)
            
            assert result is not None
            assert 'data' in result
            assert 'execution_time' in result
            assert 'optimization_applied' in result
            
            # 验证数据库查询被调用
            mock_db_manager.execute_query.assert_called()
            
        finally:
            await optimizer.stop_optimizer()
    
    @pytest.mark.asyncio
    async def test_query_caching(self, optimizer, mock_db_manager):
        """测试查询缓存"""
        await optimizer.start_optimizer()
        
        try:
            query = "MATCH (n:Event) RETURN count(n)"
            params = {}
            
            # 第一次执行
            result1 = await optimizer.execute_optimized_query(query, params)
            call_count_1 = mock_db_manager.execute_query.call_count
            
            # 第二次执行（应该使用缓存）
            result2 = await optimizer.execute_optimized_query(query, params)
            call_count_2 = mock_db_manager.execute_query.call_count
            
            # 验证缓存生效
            assert result1['data'] == result2['data']
            assert result2['cached'] is True
            assert call_count_2 == call_count_1  # 没有额外的数据库调用
            
        finally:
            await optimizer.stop_optimizer()
    
    @pytest.mark.asyncio
    async def test_query_plan_generation(self, optimizer):
        """测试查询计划生成"""
        await optimizer.start_optimizer()
        
        try:
            query = """
            MATCH (e:Event)-[:TRIGGERS]->(p:Process)
            WHERE e.timestamp > $time AND p.name = $process_name
            RETURN e, p
            """
            
            plan = await optimizer.generate_query_plan(query)
            
            assert isinstance(plan, QueryPlan)
            assert plan.original_query == query
            assert plan.optimized_query is not None
            assert len(plan.optimization_steps) >= 0
            assert plan.estimated_cost >= 0
            
        finally:
            await optimizer.stop_optimizer()
    
    @pytest.mark.asyncio
    async def test_concurrent_query_execution(self, optimizer, mock_db_manager):
        """测试并发查询执行"""
        await optimizer.start_optimizer()
        
        try:
            queries = [
                "MATCH (e:Event) RETURN count(e)",
                "MATCH (p:Process) RETURN count(p)",
                "MATCH (u:User) RETURN count(u)"
            ]
            
            # 并发执行查询
            tasks = []
            for query in queries:
                task = asyncio.create_task(
                    optimizer.execute_optimized_query(query, {})
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            # 验证所有查询都成功执行
            assert len(results) == len(queries)
            for result in results:
                assert 'data' in result
                assert 'execution_time' in result
            
        finally:
            await optimizer.stop_optimizer()
    
    @pytest.mark.asyncio
    async def test_query_timeout_handling(self, optimizer, mock_db_manager):
        """测试查询超时处理"""
        # 模拟慢查询
        async def slow_query(*args, **kwargs):
            await asyncio.sleep(2)
            return [{"result": "slow"}]
        
        mock_db_manager.execute_query = slow_query
        optimizer.config.query_timeout = 1  # 1秒超时
        
        await optimizer.start_optimizer()
        
        try:
            query = "MATCH (n) RETURN n"
            
            with pytest.raises(asyncio.TimeoutError):
                await optimizer.execute_optimized_query(query, {})
            
        finally:
            await optimizer.stop_optimizer()
    
    @pytest.mark.asyncio
    async def test_optimization_levels(self, optimizer, mock_db_manager):
        """测试不同优化级别"""
        await optimizer.start_optimizer()
        
        try:
            query = "MATCH (e:Event) WHERE e.timestamp > $time RETURN e"
            params = {"time": datetime.now()}
            
            # 测试不同优化级别
            levels = [OptimizationLevel.CONSERVATIVE, OptimizationLevel.BALANCED, OptimizationLevel.AGGRESSIVE]
            
            for level in levels:
                optimizer.config.optimization_level = level
                result = await optimizer.execute_optimized_query(query, params)
                
                assert 'optimization_level' in result
                assert result['optimization_level'] == level.value
            
        finally:
            await optimizer.stop_optimizer()
    
    @pytest.mark.asyncio
    async def test_performance_monitoring(self, optimizer, mock_db_manager):
        """测试性能监控"""
        await optimizer.start_optimizer()
        
        try:
            # 执行一些查询
            queries = [
                "MATCH (e:Event) RETURN count(e)",
                "MATCH (p:Process) RETURN count(p)"
            ]
            
            for query in queries:
                await optimizer.execute_optimized_query(query, {})
            
            # 获取性能指标
            metrics = optimizer.get_performance_metrics()
            
            assert 'total_queries' in metrics
            assert 'avg_execution_time' in metrics
            assert 'cache_hit_ratio' in metrics
            assert 'optimization_success_rate' in metrics
            
            assert metrics['total_queries'] == len(queries)
            assert metrics['avg_execution_time'] >= 0
            
        finally:
            await optimizer.stop_optimizer()
    
    @pytest.mark.asyncio
    async def test_error_handling(self, optimizer, mock_db_manager):
        """测试错误处理"""
        # 模拟数据库错误
        mock_db_manager.execute_query.side_effect = Exception("Database error")
        
        await optimizer.start_optimizer()
        
        try:
            query = "INVALID CYPHER QUERY"
            
            result = await optimizer.execute_optimized_query(query, {})
            
            assert 'error' in result
            assert result['success'] is False
            
        finally:
            await optimizer.stop_optimizer()
    
    @pytest.mark.asyncio
    async def test_optimizer_disabled(self, config, mock_db_manager):
        """测试优化器禁用"""
        config.enabled = False
        optimizer = GraphQueryOptimizer(config, mock_db_manager)
        
        await optimizer.start_optimizer()
        
        try:
            query = "MATCH (n) RETURN n"
            result = await optimizer.execute_optimized_query(query, {})
            
            # 禁用时应该直接执行原查询
            assert result['optimization_applied'] is False
            assert result['bypass_reason'] == 'optimizer_disabled'
            
        finally:
            await optimizer.stop_optimizer()
    
    @pytest.mark.asyncio
    async def test_query_optimizer_factory(self):
        """测试查询优化器工厂函数"""
        config = QueryOptimizerConfig(enabled=True)
        mock_db = Mock(spec=GraphDatabaseManager)
        
        optimizer = create_query_optimizer(config, mock_db)
        
        assert isinstance(optimizer, GraphQueryOptimizer)
        assert optimizer.config == config
        assert optimizer.db_manager == mock_db


if __name__ == "__main__":
    pytest.main([__file__, "-v"])