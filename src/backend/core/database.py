#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS Database Connection Management
Neo4j数据库连接管理
"""

import asyncio
from typing import Optional, Dict, Any, List
from neo4j import AsyncGraphDatabase, AsyncDriver
from loguru import logger

from core.config import settings

class Neo4jConnection:
    """Neo4j数据库连接管理器"""
    
    def __init__(self):
        self._driver: Optional[AsyncDriver] = None
        self._session_pool = []
    
    async def connect(self) -> AsyncDriver:
        """建立数据库连接"""
        if self._driver is None:
            try:
                self._driver = AsyncGraphDatabase.driver(
                    settings.neo4j_uri,
                    auth=(settings.neo4j_user, settings.neo4j_password),
                    max_connection_lifetime=3600,
                    max_connection_pool_size=50,
                    connection_acquisition_timeout=60
                )
                logger.info(f"Connected to Neo4j at {settings.neo4j_uri}")
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j: {e}")
                raise
        return self._driver
    
    async def close(self):
        """关闭数据库连接"""
        if self._driver:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j connection closed")
    
    async def verify_connectivity(self) -> bool:
        """验证数据库连接"""
        try:
            driver = await self.connect()
            await driver.verify_connectivity()
            logger.info("Neo4j connectivity verified")
            return True
        except Exception as e:
            logger.error(f"Neo4j connectivity check failed: {e}")
            return False
    
    async def execute_query(
        self, 
        query: str, 
        parameters: Optional[Dict[str, Any]] = None,
        database: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """执行Cypher查询"""
        if not self._driver:
            await self.connect()
        
        async with self._driver.session(
            database=database or settings.neo4j_database
        ) as session:
            try:
                result = await session.run(query, parameters or {})
                records = await result.data()
                logger.debug(f"Query executed: {query[:100]}...")
                return records
            except Exception as e:
                logger.error(f"Query execution failed: {e}")
                logger.error(f"Query: {query}")
                logger.error(f"Parameters: {parameters}")
                raise
    
    async def execute_write_transaction(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
        database: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """执行写事务"""
        if not self._driver:
            await self.connect()
        
        async with self._driver.session(
            database=database or settings.neo4j_database
        ) as session:
            try:
                result = await session.execute_write(
                    self._write_transaction, query, parameters or {}
                )
                return result
            except Exception as e:
                logger.error(f"Write transaction failed: {e}")
                raise
    
    @staticmethod
    async def _write_transaction(tx, query: str, parameters: Dict[str, Any]):
        """写事务处理函数"""
        result = await tx.run(query, parameters)
        return await result.data()
    
    async def create_indexes(self):
        """创建必要的索引"""
        indexes = [
            "CREATE INDEX event_timestamp_idx IF NOT EXISTS FOR (e:Event) ON (e.timestamp)",
            "CREATE INDEX process_name_idx IF NOT EXISTS FOR (p:Process) ON (p.name)",
            "CREATE INDEX file_path_idx IF NOT EXISTS FOR (f:File) ON (f.path)",
            "CREATE INDEX user_name_idx IF NOT EXISTS FOR (u:User) ON (u.name)",
            "CREATE INDEX event_rule_idx IF NOT EXISTS FOR (e:Event) ON (e.rule)",
            "CREATE INDEX event_priority_idx IF NOT EXISTS FOR (e:Event) ON (e.priority)"
        ]
        
        for index_query in indexes:
            try:
                await self.execute_query(index_query)
                logger.info(f"Index created: {index_query.split()[2]}")
            except Exception as e:
                logger.warning(f"Index creation failed: {e}")
    
    async def create_constraints(self):
        """创建约束"""
        constraints = [
            "CREATE CONSTRAINT event_id_unique IF NOT EXISTS FOR (e:Event) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT process_pid_unique IF NOT EXISTS FOR (p:Process) REQUIRE (p.pid, p.timestamp) IS UNIQUE"
        ]
        
        for constraint_query in constraints:
            try:
                await self.execute_query(constraint_query)
                logger.info(f"Constraint created: {constraint_query.split()[2]}")
            except Exception as e:
                logger.warning(f"Constraint creation failed: {e}")
    
    async def initialize_schema(self):
        """初始化数据库模式"""
        logger.info("Initializing Neo4j schema...")
        await self.create_indexes()
        await self.create_constraints()
        logger.info("Neo4j schema initialization completed")

# 创建全局数据库连接实例
neo4j_driver = Neo4jConnection()

# 数据库操作辅助函数
async def get_db_stats() -> Dict[str, Any]:
    """获取数据库统计信息"""
    queries = {
        "total_events": "MATCH (e:Event) RETURN count(e) as count",
        "total_processes": "MATCH (p:Process) RETURN count(p) as count",
        "total_files": "MATCH (f:File) RETURN count(f) as count",
        "total_users": "MATCH (u:User) RETURN count(u) as count",
        "recent_events": "MATCH (e:Event) WHERE e.timestamp > datetime() - duration('PT1H') RETURN count(e) as count"
    }
    
    stats = {}
    for key, query in queries.items():
        try:
            result = await neo4j_driver.execute_query(query)
            stats[key] = result[0]['count'] if result else 0
        except Exception as e:
            logger.error(f"Failed to get {key}: {e}")
            stats[key] = 0
    
    return stats