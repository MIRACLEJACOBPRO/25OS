#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS Graph Builder Service
知识图谱构建服务
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple
from loguru import logger

from core.database import neo4j_driver
from core.config import settings

class GraphBuilder:
    """知识图谱构建器"""
    
    def __init__(self):
        self.node_cache = {}  # 节点缓存，避免重复创建
        self.relationship_cache = set()  # 关系缓存
        
    async def build_graph_from_events(self, events: List[Dict[str, Any]]):
        """从事件列表构建知识图谱"""
        try:
            logger.info(f"Building graph from {len(events)} events")
            
            for event in events:
                await self.process_single_event(event)
            
            # 批量创建关系
            await self.create_temporal_relationships(events)
            await self.create_behavioral_patterns(events)
            
            logger.info(f"Graph building completed for {len(events)} events")
            
        except Exception as e:
            logger.error(f"Failed to build graph from events: {e}")
            raise
    
    async def process_single_event(self, event: Dict[str, Any]):
        """处理单个事件，创建节点和关系"""
        try:
            # 创建事件节点
            event_node = await self.create_event_node(event)
            
            # 创建相关实体节点
            entities = await self.extract_entities(event)
            
            # 创建实体节点
            for entity_type, entity_data in entities.items():
                if entity_data:
                    entity_node = await self.create_entity_node(entity_type, entity_data)
                    if entity_node:
                        await self.create_relationship(
                            event_node['id'], 
                            entity_node['id'],
                            f"INVOLVES_{entity_type.upper()}",
                            {'timestamp': event['timestamp']}
                        )
            
        except Exception as e:
            logger.error(f"Failed to process event {event.get('id', 'unknown')}: {e}")
    
    async def create_event_node(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """创建事件节点"""
        node_data = {
            'id': event['id'],
            'timestamp': event['timestamp'].isoformat(),
            'rule': event['rule'],
            'priority': event['priority'],
            'message': event['message'],
            'source': event['source'],
            'severity_score': self.calculate_severity_score(event),
            'created_at': datetime.utcnow().isoformat()
        }
        
        # 添加额外字段
        if event.get('syscall'):
            node_data['syscall'] = event['syscall']
        
        query = """
        MERGE (e:Event {id: $id})
        SET e += $properties
        RETURN e
        """
        
        result = await neo4j_driver.execute_write_transaction(
            query, 
            {'id': event['id'], 'properties': node_data}
        )
        
        return result[0]['e'] if result else node_data
    
    async def extract_entities(self, event: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """从事件中提取实体信息"""
        entities = {}
        
        # 进程实体
        if event.get('process_name') or event.get('process_pid'):
            entities['process'] = {
                'name': event.get('process_name'),
                'pid': event.get('process_pid'),
                'ppid': event.get('process_ppid'),
                'command_line': event.get('command_line'),
                'parent_process': event.get('parent_process'),
                'timestamp': event['timestamp']
            }
        
        # 用户实体
        if event.get('user_name') or event.get('user_uid'):
            entities['user'] = {
                'name': event.get('user_name'),
                'uid': event.get('user_uid'),
                'timestamp': event['timestamp']
            }
        
        # 文件实体
        if event.get('file_path'):
            entities['file'] = {
                'path': event.get('file_path'),
                'type': event.get('file_type'),
                'timestamp': event['timestamp']
            }
        
        # 容器实体
        if event.get('container_id') or event.get('container_name'):
            entities['container'] = {
                'id': event.get('container_id'),
                'name': event.get('container_name'),
                'timestamp': event['timestamp']
            }
        
        # 网络连接实体
        if event.get('network_connection'):
            net_conn = event['network_connection']
            if any(net_conn.values()):
                entities['network'] = {
                    'src_ip': net_conn.get('src_ip'),
                    'dst_ip': net_conn.get('dst_ip'),
                    'src_port': net_conn.get('src_port'),
                    'dst_port': net_conn.get('dst_port'),
                    'protocol': net_conn.get('protocol'),
                    'timestamp': event['timestamp']
                }
        
        return entities
    
    async def create_entity_node(self, entity_type: str, entity_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """创建实体节点"""
        try:
            if entity_type == 'process':
                return await self.create_process_node(entity_data)
            elif entity_type == 'user':
                return await self.create_user_node(entity_data)
            elif entity_type == 'file':
                return await self.create_file_node(entity_data)
            elif entity_type == 'container':
                return await self.create_container_node(entity_data)
            elif entity_type == 'network':
                return await self.create_network_node(entity_data)
            else:
                logger.warning(f"Unknown entity type: {entity_type}")
                return None
        except Exception as e:
            logger.error(f"Failed to create {entity_type} node: {e}")
            return None
    
    async def create_process_node(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """创建进程节点"""
        # 生成进程唯一标识（简化版，基于name和pid）
        process_id = f"process_{data.get('name', 'unknown')}_{data.get('pid', 'unknown')}"
        
        node_data = {
            'id': process_id,
            'name': data.get('name'),
            'pid': data.get('pid'),
            'ppid': data.get('ppid'),
            'command_line': data.get('command_line'),
            'parent_process': data.get('parent_process'),
            'first_seen': data['timestamp'].isoformat(),
            'last_seen': data['timestamp'].isoformat(),
            'activity_count': 1
        }
        
        query = """
        MERGE (p:Process {name: $name, pid: $pid})
        ON CREATE SET p += $properties, p.created_at = datetime()
        ON MATCH SET p.last_seen = $timestamp, p.activity_count = p.activity_count + 1
        RETURN p
        """
        
        result = await neo4j_driver.execute_write_transaction(
            query,
            {
                'name': data.get('name'),
                'pid': data.get('pid'),
                'timestamp': data['timestamp'].isoformat(),
                'properties': node_data
            }
        )
        
        return result[0]['p'] if result else node_data
    
    async def create_user_node(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """创建用户节点"""
        user_id = f"user_{data.get('name', 'unknown')}"
        
        node_data = {
            'id': user_id,
            'name': data.get('name'),
            'uid': data.get('uid'),
            'first_seen': data['timestamp'].isoformat(),
            'last_seen': data['timestamp'].isoformat(),
            'activity_count': 1
        }
        
        query = """
        MERGE (u:User {name: $name})
        ON CREATE SET u += $properties, u.created_at = datetime()
        ON MATCH SET u.last_seen = $timestamp, u.activity_count = u.activity_count + 1
        RETURN u
        """
        
        result = await neo4j_driver.execute_write_transaction(
            query,
            {
                'name': data.get('name'),
                'timestamp': data['timestamp'].isoformat(),
                'properties': node_data
            }
        )
        
        return result[0]['u'] if result else node_data
    
    async def create_file_node(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """创建文件节点"""
        file_id = f"file_{data.get('path', 'unknown').replace('/', '_')}"
        
        node_data = {
            'id': file_id,
            'path': data.get('path'),
            'type': data.get('type'),
            'first_accessed': data['timestamp'].isoformat(),
            'last_accessed': data['timestamp'].isoformat(),
            'access_count': 1
        }
        
        query = """
        MERGE (f:File {path: $path})
        ON CREATE SET f += $properties, f.created_at = datetime()
        ON MATCH SET f.last_accessed = $timestamp, f.access_count = f.access_count + 1
        RETURN f
        """
        
        result = await neo4j_driver.execute_write_transaction(
            query,
            {
                'path': data.get('path'),
                'timestamp': data['timestamp'].isoformat(),
                'properties': node_data
            }
        )
        
        return result[0]['f'] if result else node_data
    
    async def create_container_node(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """创建容器节点"""
        container_id = f"container_{data.get('id', data.get('name', 'unknown'))}"
        
        node_data = {
            'id': container_id,
            'container_id': data.get('id'),
            'name': data.get('name'),
            'first_seen': data['timestamp'].isoformat(),
            'last_seen': data['timestamp'].isoformat(),
            'activity_count': 1
        }
        
        query = """
        MERGE (c:Container {container_id: $container_id})
        ON CREATE SET c += $properties, c.created_at = datetime()
        ON MATCH SET c.last_seen = $timestamp, c.activity_count = c.activity_count + 1
        RETURN c
        """
        
        result = await neo4j_driver.execute_write_transaction(
            query,
            {
                'container_id': data.get('id'),
                'timestamp': data['timestamp'].isoformat(),
                'properties': node_data
            }
        )
        
        return result[0]['c'] if result else node_data
    
    async def create_network_node(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """创建网络连接节点"""
        connection_id = f"{data.get('src_ip', '')}:{data.get('src_port', '')}->{data.get('dst_ip', '')}:{data.get('dst_port', '')}"
        
        node_data = {
            'id': connection_id,
            'src_ip': data.get('src_ip'),
            'dst_ip': data.get('dst_ip'),
            'src_port': data.get('src_port'),
            'dst_port': data.get('dst_port'),
            'protocol': data.get('protocol'),
            'first_seen': data['timestamp'].isoformat(),
            'last_seen': data['timestamp'].isoformat(),
            'connection_count': 1
        }
        
        query = """
        MERGE (n:NetworkConnection {id: $id})
        ON CREATE SET n += $properties, n.created_at = datetime()
        ON MATCH SET n.last_seen = $timestamp, n.connection_count = n.connection_count + 1
        RETURN n
        """
        
        result = await neo4j_driver.execute_write_transaction(
            query,
            {
                'id': connection_id,
                'timestamp': data['timestamp'].isoformat(),
                'properties': node_data
            }
        )
        
        return result[0]['n'] if result else node_data
    
    async def create_relationship(
        self, 
        from_id: str, 
        to_id: str, 
        rel_type: str, 
        properties: Optional[Dict[str, Any]] = None
    ):
        """创建关系"""
        rel_key = f"{from_id}-{rel_type}-{to_id}"
        if rel_key in self.relationship_cache:
            return
        
        query = """
        MATCH (a), (b)
        WHERE a.id = $from_id AND b.id = $to_id
        MERGE (a)-[r:%s]->(b)
        SET r += $properties
        RETURN r
        """ % rel_type
        
        try:
            await neo4j_driver.execute_write_transaction(
                query,
                {
                    'from_id': from_id,
                    'to_id': to_id,
                    'properties': properties or {}
                }
            )
            self.relationship_cache.add(rel_key)
        except Exception as e:
            logger.error(f"Failed to create relationship {rel_key}: {e}")
    
    async def create_temporal_relationships(self, events: List[Dict[str, Any]]):
        """创建时间序列关系"""
        # 按时间排序事件
        sorted_events = sorted(events, key=lambda x: x['timestamp'])
        
        for i in range(len(sorted_events) - 1):
            current_event = sorted_events[i]
            next_event = sorted_events[i + 1]
            
            # 如果事件间隔很短，创建FOLLOWED_BY关系
            time_diff = (next_event['timestamp'] - current_event['timestamp']).total_seconds()
            if time_diff <= 60:  # 1分钟内
                await self.create_relationship(
                    current_event['id'],
                    next_event['id'],
                    'FOLLOWED_BY',
                    {'time_diff_seconds': time_diff}
                )
    
    async def create_behavioral_patterns(self, events: List[Dict[str, Any]]):
        """创建行为模式关系"""
        # 按进程分组事件
        process_events = {}
        for event in events:
            process_key = f"{event.get('process_name', 'unknown')}_{event.get('process_pid', 'unknown')}"
            if process_key not in process_events:
                process_events[process_key] = []
            process_events[process_key].append(event)
        
        # 为每个进程创建行为模式
        for process_key, proc_events in process_events.items():
            if len(proc_events) > 1:
                await self.create_process_behavior_pattern(proc_events)
    
    async def create_process_behavior_pattern(self, events: List[Dict[str, Any]]):
        """为进程创建行为模式"""
        # 创建进程行为模式节点
        pattern_id = f"pattern_{events[0].get('process_name', 'unknown')}_{events[0].get('process_pid', 'unknown')}"
        
        pattern_data = {
            'id': pattern_id,
            'process_name': events[0].get('process_name'),
            'process_pid': events[0].get('process_pid'),
            'event_count': len(events),
            'start_time': min(e['timestamp'] for e in events).isoformat(),
            'end_time': max(e['timestamp'] for e in events).isoformat(),
            'rules_triggered': list(set(e['rule'] for e in events)),
            'severity_score': sum(self.calculate_severity_score(e) for e in events) / len(events)
        }
        
        query = """
        MERGE (p:BehaviorPattern {id: $id})
        SET p += $properties
        RETURN p
        """
        
        await neo4j_driver.execute_write_transaction(
            query,
            {'id': pattern_id, 'properties': pattern_data}
        )
        
        # 连接事件到行为模式
        for event in events:
            await self.create_relationship(
                pattern_id,
                event['id'],
                'INCLUDES_EVENT',
                {'timestamp': event['timestamp'].isoformat()}
            )
    
    def calculate_severity_score(self, event: Dict[str, Any]) -> float:
        """计算事件严重性分数"""
        priority_scores = {
            'Emergency': 10.0,
            'Alert': 9.0,
            'Critical': 8.0,
            'Error': 7.0,
            'Warning': 6.0,
            'Notice': 5.0,
            'Informational': 4.0,
            'Debug': 3.0
        }
        
        base_score = priority_scores.get(event.get('priority', 'Notice'), 5.0)
        
        # 根据规则类型调整分数
        rule_adjustments = {
            'Unauthorized': 2.0,
            'Suspicious': 1.5,
            'Tampering': 2.5,
            'Privilege': 2.0,
            'Network': 1.0
        }
        
        rule = event.get('rule', '')
        for keyword, adjustment in rule_adjustments.items():
            if keyword.lower() in rule.lower():
                base_score += adjustment
                break
        
        return min(base_score, 10.0)  # 最大分数为10
    
    async def get_graph_stats(self) -> Dict[str, Any]:
        """获取图谱统计信息"""
        queries = {
            'total_nodes': "MATCH (n) RETURN count(n) as count",
            'total_relationships': "MATCH ()-[r]->() RETURN count(r) as count",
            'events_count': "MATCH (e:Event) RETURN count(e) as count",
            'processes_count': "MATCH (p:Process) RETURN count(p) as count",
            'users_count': "MATCH (u:User) RETURN count(u) as count",
            'files_count': "MATCH (f:File) RETURN count(f) as count",
            'patterns_count': "MATCH (bp:BehaviorPattern) RETURN count(bp) as count"
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