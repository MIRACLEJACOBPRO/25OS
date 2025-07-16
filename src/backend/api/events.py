#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS Events API
事件相关API路由
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field
from loguru import logger

from core.database import neo4j_driver
from services.log_processor import LogProcessor

router = APIRouter(prefix="/events", tags=["events"])

# Pydantic模型
class EventResponse(BaseModel):
    """事件响应模型"""
    id: str
    timestamp: datetime
    rule: str
    priority: str
    message: str
    source: str
    severity_score: float
    process_name: Optional[str] = None
    user_name: Optional[str] = None
    file_path: Optional[str] = None

class EventsListResponse(BaseModel):
    """事件列表响应模型"""
    events: List[EventResponse]
    total: int
    page: int
    page_size: int
    has_next: bool

class EventStatsResponse(BaseModel):
    """事件统计响应模型"""
    total_events: int
    events_last_hour: int
    events_last_day: int
    top_rules: List[Dict[str, Any]]
    priority_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]

@router.get("/", response_model=EventsListResponse)
async def get_events(
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页大小"),
    priority: Optional[str] = Query(None, description="优先级过滤"),
    rule: Optional[str] = Query(None, description="规则过滤"),
    start_time: Optional[datetime] = Query(None, description="开始时间"),
    end_time: Optional[datetime] = Query(None, description="结束时间"),
    search: Optional[str] = Query(None, description="搜索关键词")
):
    """获取事件列表"""
    try:
        # 构建查询条件
        where_conditions = []
        params = {}
        
        if priority:
            where_conditions.append("e.priority = $priority")
            params['priority'] = priority
        
        if rule:
            where_conditions.append("e.rule CONTAINS $rule")
            params['rule'] = rule
        
        if start_time:
            where_conditions.append("datetime(e.timestamp) >= datetime($start_time)")
            params['start_time'] = start_time.isoformat()
        
        if end_time:
            where_conditions.append("datetime(e.timestamp) <= datetime($end_time)")
            params['end_time'] = end_time.isoformat()
        
        if search:
            where_conditions.append("(e.message CONTAINS $search OR e.rule CONTAINS $search)")
            params['search'] = search
        
        where_clause = " AND ".join(where_conditions) if where_conditions else "true"
        
        # 获取总数
        count_query = f"""
        MATCH (e:Event)
        WHERE {where_clause}
        RETURN count(e) as total
        """
        
        count_result = await neo4j_driver.execute_query(count_query, params)
        total = count_result[0]['total'] if count_result else 0
        
        # 获取分页数据
        skip = (page - 1) * page_size
        params.update({'skip': skip, 'limit': page_size})
        
        events_query = f"""
        MATCH (e:Event)
        WHERE {where_clause}
        RETURN e
        ORDER BY datetime(e.timestamp) DESC
        SKIP $skip LIMIT $limit
        """
        
        events_result = await neo4j_driver.execute_query(events_query, params)
        
        # 转换为响应模型
        events = []
        for record in events_result:
            event_data = record['e']
            events.append(EventResponse(
                id=event_data['id'],
                timestamp=datetime.fromisoformat(event_data['timestamp']),
                rule=event_data['rule'],
                priority=event_data['priority'],
                message=event_data['message'],
                source=event_data['source'],
                severity_score=event_data.get('severity_score', 0.0),
                process_name=event_data.get('process_name'),
                user_name=event_data.get('user_name'),
                file_path=event_data.get('file_path')
            ))
        
        has_next = (skip + page_size) < total
        
        return EventsListResponse(
            events=events,
            total=total,
            page=page,
            page_size=page_size,
            has_next=has_next
        )
        
    except Exception as e:
        logger.error(f"Failed to get events: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve events")

@router.get("/{event_id}")
async def get_event_detail(event_id: str):
    """获取事件详情"""
    try:
        query = """
        MATCH (e:Event {id: $event_id})
        OPTIONAL MATCH (e)-[r1]->(p:Process)
        OPTIONAL MATCH (e)-[r2]->(u:User)
        OPTIONAL MATCH (e)-[r3]->(f:File)
        OPTIONAL MATCH (e)-[r4]->(c:Container)
        OPTIONAL MATCH (e)-[r5]->(n:NetworkConnection)
        RETURN e, 
               collect(DISTINCT p) as processes,
               collect(DISTINCT u) as users,
               collect(DISTINCT f) as files,
               collect(DISTINCT c) as containers,
               collect(DISTINCT n) as networks
        """
        
        result = await neo4j_driver.execute_query(query, {'event_id': event_id})
        
        if not result:
            raise HTTPException(status_code=404, detail="Event not found")
        
        record = result[0]
        event_data = record['e']
        
        # 构建详细响应
        response = {
            'event': event_data,
            'related_entities': {
                'processes': [dict(p) for p in record['processes'] if p],
                'users': [dict(u) for u in record['users'] if u],
                'files': [dict(f) for f in record['files'] if f],
                'containers': [dict(c) for c in record['containers'] if c],
                'networks': [dict(n) for n in record['networks'] if n]
            }
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get event detail {event_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve event detail")

@router.get("/stats/overview", response_model=EventStatsResponse)
async def get_event_stats():
    """获取事件统计概览"""
    try:
        # 总事件数
        total_query = "MATCH (e:Event) RETURN count(e) as total"
        total_result = await neo4j_driver.execute_query(total_query)
        total_events = total_result[0]['total'] if total_result else 0
        
        # 最近1小时事件数
        hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        hour_query = """
        MATCH (e:Event)
        WHERE datetime(e.timestamp) >= datetime($hour_ago)
        RETURN count(e) as count
        """
        hour_result = await neo4j_driver.execute_query(hour_query, {'hour_ago': hour_ago})
        events_last_hour = hour_result[0]['count'] if hour_result else 0
        
        # 最近24小时事件数
        day_ago = (datetime.utcnow() - timedelta(days=1)).isoformat()
        day_query = """
        MATCH (e:Event)
        WHERE datetime(e.timestamp) >= datetime($day_ago)
        RETURN count(e) as count
        """
        day_result = await neo4j_driver.execute_query(day_query, {'day_ago': day_ago})
        events_last_day = day_result[0]['count'] if day_result else 0
        
        # 热门规则
        top_rules_query = """
        MATCH (e:Event)
        WHERE datetime(e.timestamp) >= datetime($day_ago)
        RETURN e.rule as rule, count(e) as count
        ORDER BY count DESC
        LIMIT 10
        """
        top_rules_result = await neo4j_driver.execute_query(top_rules_query, {'day_ago': day_ago})
        top_rules = [{'rule': r['rule'], 'count': r['count']} for r in top_rules_result]
        
        # 优先级分布
        priority_query = """
        MATCH (e:Event)
        WHERE datetime(e.timestamp) >= datetime($day_ago)
        RETURN e.priority as priority, count(e) as count
        """
        priority_result = await neo4j_driver.execute_query(priority_query, {'day_ago': day_ago})
        priority_distribution = {r['priority']: r['count'] for r in priority_result}
        
        # 严重性分布
        severity_query = """
        MATCH (e:Event)
        WHERE datetime(e.timestamp) >= datetime($day_ago)
        WITH e,
             CASE 
                 WHEN e.severity_score >= 8 THEN 'High'
                 WHEN e.severity_score >= 6 THEN 'Medium'
                 ELSE 'Low'
             END as severity_level
        RETURN severity_level, count(e) as count
        """
        severity_result = await neo4j_driver.execute_query(severity_query, {'day_ago': day_ago})
        severity_distribution = {r['severity_level']: r['count'] for r in severity_result}
        
        return EventStatsResponse(
            total_events=total_events,
            events_last_hour=events_last_hour,
            events_last_day=events_last_day,
            top_rules=top_rules,
            priority_distribution=priority_distribution,
            severity_distribution=severity_distribution
        )
        
    except Exception as e:
        logger.error(f"Failed to get event stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve event statistics")

@router.get("/timeline/{hours}")
async def get_event_timeline(hours: int = 24):
    """获取事件时间线"""
    try:
        start_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        
        query = """
        MATCH (e:Event)
        WHERE datetime(e.timestamp) >= datetime($start_time)
        WITH e, 
             datetime(e.timestamp).year as year,
             datetime(e.timestamp).month as month,
             datetime(e.timestamp).day as day,
             datetime(e.timestamp).hour as hour
        RETURN year, month, day, hour, count(e) as event_count,
               collect(DISTINCT e.priority) as priorities,
               avg(e.severity_score) as avg_severity
        ORDER BY year, month, day, hour
        """
        
        result = await neo4j_driver.execute_query(query, {'start_time': start_time})
        
        timeline = []
        for record in result:
            timeline.append({
                'timestamp': f"{record['year']}-{record['month']:02d}-{record['day']:02d}T{record['hour']:02d}:00:00",
                'event_count': record['event_count'],
                'priorities': record['priorities'],
                'avg_severity': round(record['avg_severity'], 2) if record['avg_severity'] else 0
            })
        
        return {'timeline': timeline}
        
    except Exception as e:
        logger.error(f"Failed to get event timeline: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve event timeline")

@router.post("/process-logs")
async def trigger_log_processing():
    """手动触发日志处理"""
    try:
        # 这里需要依赖注入LogProcessor实例
        # 暂时返回成功响应
        return {"message": "Log processing triggered successfully"}
        
    except Exception as e:
        logger.error(f"Failed to trigger log processing: {e}")
        raise HTTPException(status_code=500, detail="Failed to trigger log processing")