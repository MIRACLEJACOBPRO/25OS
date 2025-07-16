#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS Graph API
知识图谱相关API路由
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from loguru import logger
import neo4j.time

from core.database import neo4j_driver, get_db_stats
from services.graph_builder import GraphBuilder

router = APIRouter(prefix="/graph", tags=["graph"])

def convert_neo4j_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """安全地转换Neo4j数据类型为JSON可序列化的格式"""
    converted = {}
    for key, value in data.items():
        if isinstance(value, neo4j.time.DateTime):
            # 转换Neo4j DateTime为ISO格式字符串
            converted[key] = value.iso_format()
        elif isinstance(value, neo4j.time.Date):
            # 转换Neo4j Date为ISO格式字符串
            converted[key] = value.iso_format()
        elif isinstance(value, neo4j.time.Time):
            # 转换Neo4j Time为ISO格式字符串
            converted[key] = value.iso_format()
        elif isinstance(value, neo4j.time.Duration):
            # 转换Neo4j Duration为秒数
            converted[key] = value.seconds
        elif isinstance(value, dict):
            # 递归处理嵌套字典
            converted[key] = convert_neo4j_data(value)
        elif isinstance(value, list):
            # 处理列表中的Neo4j类型
            converted[key] = [convert_neo4j_data(item) if isinstance(item, dict) else 
                            (item.iso_format() if hasattr(item, 'iso_format') else item) 
                            for item in value]
        else:
            # 其他类型直接复制
            converted[key] = value
    return converted

# Pydantic模型
class NodeResponse(BaseModel):
    """节点响应模型"""
    id: str
    labels: List[str]
    properties: Dict[str, Any]

class RelationshipResponse(BaseModel):
    """关系响应模型"""
    id: str
    type: str
    start_node: str
    end_node: str
    properties: Dict[str, Any]

class GraphResponse(BaseModel):
    """图谱响应模型"""
    nodes: List[NodeResponse]
    relationships: List[RelationshipResponse]
    stats: Dict[str, Any]

class GraphStatsResponse(BaseModel):
    """图谱统计响应模型"""
    total_nodes: int
    total_relationships: int
    events_count: int
    processes_count: int
    users_count: int
    files_count: int
    patterns_count: int
    last_updated: datetime

class PathResponse(BaseModel):
    """路径响应模型"""
    path_length: int
    nodes: List[NodeResponse]
    relationships: List[RelationshipResponse]
    path_score: float

@router.get("/stats", response_model=GraphStatsResponse)
async def get_graph_stats():
    """获取图谱统计信息"""
    try:
        # 使用GraphBuilder获取统计信息
        graph_builder = GraphBuilder()
        stats = await graph_builder.get_graph_stats()
        
        return GraphStatsResponse(
            total_nodes=stats.get('total_nodes', 0),
            total_relationships=stats.get('total_relationships', 0),
            events_count=stats.get('events_count', 0),
            processes_count=stats.get('processes_count', 0),
            users_count=stats.get('users_count', 0),
            files_count=stats.get('files_count', 0),
            patterns_count=stats.get('patterns_count', 0),
            last_updated=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Failed to get graph stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve graph statistics")

@router.get("/nodes/{node_type}")
async def get_nodes_by_type(
    node_type: str,
    limit: int = Query(100, ge=1, le=1000, description="返回节点数量限制"),
    skip: int = Query(0, ge=0, description="跳过节点数量")
):
    """根据类型获取节点"""
    try:
        # 验证节点类型
        valid_types = ['Event', 'Process', 'User', 'File', 'Container', 'NetworkConnection', 'BehaviorPattern']
        if node_type not in valid_types:
            raise HTTPException(status_code=400, detail=f"Invalid node type. Valid types: {valid_types}")
        
        query = f"""
        MATCH (n:{node_type})
        RETURN n
        ORDER BY n.timestamp DESC, n.created_at DESC
        SKIP $skip LIMIT $limit
        """
        
        result = await neo4j_driver.execute_query(query, {'skip': skip, 'limit': limit})
        
        nodes = []
        for record in result:
            node_data = record['n']
            nodes.append(NodeResponse(
                id=node_data.get('id', str(node_data.get('name', 'unknown'))),
                labels=[node_type],
                properties=convert_neo4j_data(dict(node_data))
            ))
        
        return {'nodes': nodes, 'total': len(nodes)}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get nodes by type {node_type}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve nodes")

@router.get("/node/{node_id}/relationships")
async def get_node_relationships(node_id: str):
    """获取节点的关系"""
    try:
        query = """
        MATCH (n)-[r]-(m)
        WHERE n.id = $node_id OR n.name = $node_id
        RETURN n, r, m, 
               startNode(r) as start_node,
               endNode(r) as end_node,
               type(r) as rel_type
        LIMIT 100
        """
        
        result = await neo4j_driver.execute_query(query, {'node_id': node_id})
        
        if not result:
            raise HTTPException(status_code=404, detail="Node not found")
        
        relationships = []
        nodes = {}
        
        for record in result:
            # 收集节点
            for node_key in ['n', 'm']:
                node_data = record[node_key]
                node_id_key = node_data.get('id', str(node_data.get('name', 'unknown')))
                if node_id_key not in nodes:
                    nodes[node_id_key] = NodeResponse(
                        id=node_id_key,
                        labels=list(node_data.labels) if hasattr(node_data, 'labels') else ['Unknown'],
                        properties=convert_neo4j_data(dict(node_data))
                    )
            
            # 收集关系
            rel_data = record['r']
            start_node_data = record['start_node']
            end_node_data = record['end_node']
            
            # 安全地获取节点ID
            start_node_dict = dict(start_node_data)
            end_node_dict = dict(end_node_data)
            start_id = start_node_dict.get('id', str(start_node_dict.get('name', 'unknown')))
            end_id = end_node_dict.get('id', str(end_node_dict.get('name', 'unknown')))
            
            # 安全地获取关系属性
            try:
                rel_properties = dict(rel_data) if rel_data else {}
            except (TypeError, ValueError):
                # 如果关系对象无法直接转换为字典，尝试获取其属性
                rel_properties = {}
                if hasattr(rel_data, '__dict__'):
                    rel_properties = rel_data.__dict__.copy()
                elif hasattr(rel_data, 'items'):
                    rel_properties = dict(rel_data.items())
            
            relationships.append(RelationshipResponse(
                id=str(rel_data.id) if hasattr(rel_data, 'id') else f"{start_id}-{end_id}",
                type=record['rel_type'],
                start_node=start_id,
                end_node=end_id,
                properties=convert_neo4j_data(rel_properties)
            ))
        
        return {
            'center_node': node_id,
            'nodes': list(nodes.values()),
            'relationships': relationships
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get node relationships for {node_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve node relationships")

@router.get("/subgraph")
async def get_subgraph(
    node_types: List[str] = Query([], description="节点类型过滤"),
    relationship_types: List[str] = Query([], description="关系类型过滤"),
    start_time: Optional[datetime] = Query(None, description="开始时间"),
    end_time: Optional[datetime] = Query(None, description="结束时间"),
    limit: int = Query(200, ge=1, le=1000, description="节点数量限制")
):
    """获取子图"""
    try:
        # 构建查询条件
        where_conditions = []
        params = {'limit': limit}
        
        if start_time:
            where_conditions.append("(n.timestamp IS NULL OR datetime(n.timestamp) >= datetime($start_time))")
            params['start_time'] = start_time.isoformat()
        
        if end_time:
            where_conditions.append("(n.timestamp IS NULL OR datetime(n.timestamp) <= datetime($end_time))")
            params['end_time'] = end_time.isoformat()
        
        # 节点类型过滤
        if node_types:
            type_conditions = [f"n:{node_type}" for node_type in node_types]
            where_conditions.append(f"({' OR '.join(type_conditions)})")
        
        where_clause = " AND ".join(where_conditions) if where_conditions else "true"
        
        # 获取节点和关系
        query = f"""
        MATCH (n)-[r]-(m)
        WHERE {where_clause}
        RETURN n, r, m, 
               labels(n) as n_labels,
               labels(m) as m_labels,
               type(r) as rel_type
        LIMIT $limit
        """
        
        result = await neo4j_driver.execute_query(query, params)
        
        nodes = {}
        relationships = []
        
        for record in result:
            # 处理节点
            for node_key, labels_key in [('n', 'n_labels'), ('m', 'm_labels')]:
                node_data = record[node_key]
                node_id = node_data.get('id', str(node_data.get('name', 'unknown')))
                
                if node_id not in nodes:
                    nodes[node_id] = NodeResponse(
                        id=node_id,
                        labels=record[labels_key],
                        properties=convert_neo4j_data(dict(node_data))
                    )
            
            # 处理关系
            if not relationship_types or record['rel_type'] in relationship_types:
                rel_data = record['r']
                n_id = record['n'].get('id', str(record['n'].get('name', 'unknown')))
                m_id = record['m'].get('id', str(record['m'].get('name', 'unknown')))
                
                # 安全地获取关系属性
                try:
                    rel_properties = dict(rel_data) if rel_data else {}
                except (TypeError, ValueError):
                    # 如果关系对象无法直接转换为字典，尝试获取其属性
                    rel_properties = {}
                    if hasattr(rel_data, '__dict__'):
                        rel_properties = rel_data.__dict__.copy()
                    elif hasattr(rel_data, 'items'):
                        rel_properties = dict(rel_data.items())
                
                relationships.append(RelationshipResponse(
                    id=f"{n_id}-{record['rel_type']}-{m_id}",
                    type=record['rel_type'],
                    start_node=n_id,
                    end_node=m_id,
                    properties=convert_neo4j_data(rel_properties)
                ))
        
        return GraphResponse(
            nodes=list(nodes.values()),
            relationships=relationships,
            stats={
                'nodes_count': len(nodes),
                'relationships_count': len(relationships),
                'query_time': datetime.utcnow().isoformat()
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to get subgraph: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve subgraph")

@router.get("/path/{start_node_id}/{end_node_id}")
async def find_shortest_path(
    start_node_id: str,
    end_node_id: str,
    max_depth: int = Query(6, ge=1, le=10, description="最大路径深度")
):
    """查找两个节点之间的最短路径"""
    try:
        query = """
        MATCH (start), (end)
        WHERE (start.id = $start_id OR start.name = $start_id) 
          AND (end.id = $end_id OR end.name = $end_id)
        MATCH path = shortestPath((start)-[*1..$max_depth]-(end))
        RETURN path, length(path) as path_length
        ORDER BY path_length
        LIMIT 5
        """
        
        result = await neo4j_driver.execute_query(
            query, 
            {
                'start_id': start_node_id,
                'end_id': end_node_id,
                'max_depth': max_depth
            }
        )
        
        if not result:
            return {'paths': [], 'message': 'No path found between the specified nodes'}
        
        paths = []
        for record in result:
            path_data = record['path']
            path_length = record['path_length']
            
            # 提取路径中的节点和关系
            nodes = []
            relationships = []
            
            # 这里需要根据Neo4j Python驱动的具体实现来解析路径
            # 简化处理，返回基本信息
            paths.append(PathResponse(
                path_length=path_length,
                nodes=[],  # 需要实现路径节点提取
                relationships=[],  # 需要实现路径关系提取
                path_score=1.0 / (path_length + 1)  # 简单的路径评分
            ))
        
        return {'paths': paths}
        
    except Exception as e:
        logger.error(f"Failed to find path between {start_node_id} and {end_node_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to find path")

@router.get("/patterns/behavior")
async def get_behavior_patterns(
    limit: int = Query(50, ge=1, le=200, description="返回模式数量限制"),
    min_events: int = Query(2, ge=1, description="最小事件数量")
):
    """获取行为模式"""
    try:
        query = """
        MATCH (bp:BehaviorPattern)
        WHERE bp.event_count >= $min_events
        OPTIONAL MATCH (bp)-[:INCLUDES_EVENT]->(e:Event)
        RETURN bp, collect(e) as events
        ORDER BY bp.severity_score DESC, bp.event_count DESC
        LIMIT $limit
        """
        
        result = await neo4j_driver.execute_query(
            query, 
            {'limit': limit, 'min_events': min_events}
        )
        
        patterns = []
        for record in result:
            pattern_data = record['bp']
            events_data = record['events']
            
            patterns.append({
                'pattern': convert_neo4j_data(dict(pattern_data)),
                'events': [convert_neo4j_data(dict(event)) for event in events_data],
                'risk_level': 'High' if pattern_data.get('severity_score', 0) >= 7 else 
                             'Medium' if pattern_data.get('severity_score', 0) >= 5 else 'Low'
            })
        
        return {'patterns': patterns, 'total': len(patterns)}
        
    except Exception as e:
        logger.error(f"Failed to get behavior patterns: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve behavior patterns")

@router.get("/analysis/anomalies")
async def detect_anomalies(
    hours: int = Query(24, ge=1, le=168, description="分析时间范围（小时）")
):
    """检测异常行为"""
    try:
        start_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        
        # 检测异常高频活动
        high_frequency_query = """
        MATCH (e:Event)
        WHERE datetime(e.timestamp) >= datetime($start_time)
        WITH e.process_name as process, count(e) as event_count
        WHERE event_count > 100
        RETURN process, event_count
        ORDER BY event_count DESC
        LIMIT 10
        """
        
        # 检测异常用户活动
        user_anomaly_query = """
        MATCH (e:Event)
        WHERE datetime(e.timestamp) >= datetime($start_time)
        WITH e.user_name as user, count(DISTINCT e.process_name) as unique_processes
        WHERE unique_processes > 20
        RETURN user, unique_processes
        ORDER BY unique_processes DESC
        LIMIT 10
        """
        
        # 检测高风险事件
        high_risk_query = """
        MATCH (e:Event)
        WHERE datetime(e.timestamp) >= datetime($start_time)
          AND e.severity_score >= 8
        RETURN e.rule as rule, count(e) as count, avg(e.severity_score) as avg_severity
        ORDER BY count DESC
        LIMIT 10
        """
        
        high_freq_result = await neo4j_driver.execute_query(high_frequency_query, {'start_time': start_time})
        user_anomaly_result = await neo4j_driver.execute_query(user_anomaly_query, {'start_time': start_time})
        high_risk_result = await neo4j_driver.execute_query(high_risk_query, {'start_time': start_time})
        
        return {
            'analysis_period_hours': hours,
            'anomalies': {
                'high_frequency_processes': [
                    {'process': r['process'], 'event_count': r['event_count']} 
                    for r in high_freq_result
                ],
                'suspicious_users': [
                    {'user': r['user'], 'unique_processes': r['unique_processes']} 
                    for r in user_anomaly_result
                ],
                'high_risk_events': [
                    {
                        'rule': r['rule'], 
                        'count': r['count'], 
                        'avg_severity': round(r['avg_severity'], 2)
                    } 
                    for r in high_risk_result
                ]
            },
            'generated_at': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to detect anomalies: {e}")
        raise HTTPException(status_code=500, detail="Failed to detect anomalies")

@router.post("/rebuild")
async def rebuild_graph():
    """重建知识图谱"""
    try:
        # 这里应该触发图谱重建过程
        # 暂时返回成功响应
        return {
            'message': 'Graph rebuild initiated',
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to rebuild graph: {e}")
        raise HTTPException(status_code=500, detail="Failed to rebuild graph")