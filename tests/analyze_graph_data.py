#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import sys
import os

# 添加项目路径
sys.path.append('/home/xzj/01_Project/B_25OS/src/backend')

# 临时禁用配置验证
os.environ['OPENAI_API_KEY'] = 'test-key'
os.environ['PINECONE_API_KEY'] = 'test-key'

from core.database import neo4j_driver

async def analyze_graph_data():
    """详细分析图数据库中的数据"""
    try:
        await neo4j_driver.connect()
        print("✅ Neo4j连接成功\n")
        
        # 1. 查询总体统计
        print("=== 总体统计 ===")
        result = await neo4j_driver.execute_query('MATCH (n) RETURN count(n) as total')
        total_nodes = result[0]['total'] if result else 0
        print(f"节点总数: {total_nodes}")
        
        result = await neo4j_driver.execute_query('MATCH ()-[r]->() RETURN count(r) as total')
        total_rels = result[0]['total'] if result else 0
        print(f"关系总数: {total_rels}\n")
        
        # 2. 查询节点类型分布
        print("=== 节点类型分布 ===")
        result = await neo4j_driver.execute_query('MATCH (n) RETURN DISTINCT labels(n) as labels, count(n) as count ORDER BY count DESC')
        if result:
            for record in result:
                labels = record['labels']
                count = record['count']
                label_str = ':'.join(labels) if labels else 'No Label'
                print(f"  {label_str}: {count}个")
        print()
        
        # 3. 查询Event节点详情
        print("=== Event节点详情 ===")
        result = await neo4j_driver.execute_query('MATCH (e:Event) RETURN e ORDER BY e.timestamp LIMIT 10')
        if result:
            for i, record in enumerate(result, 1):
                event = record['e']
                print(f"  Event {i}:")
                print(f"    ID: {event.get('id', 'N/A')}")
                print(f"    Rule: {event.get('rule', 'N/A')}")
                print(f"    Priority: {event.get('priority', 'N/A')}")
                print(f"    Timestamp: {event.get('timestamp', 'N/A')}")
                print(f"    Message: {event.get('message', 'N/A')[:100]}...")
                print()
        else:
            print("  未找到Event节点\n")
        
        # 4. 查询Process节点详情
        print("=== Process节点详情 ===")
        result = await neo4j_driver.execute_query('MATCH (p:Process) RETURN p LIMIT 5')
        if result:
            for i, record in enumerate(result, 1):
                process = record['p']
                print(f"  Process {i}:")
                print(f"    Name: {process.get('name', 'N/A')}")
                print(f"    PID: {process.get('pid', 'N/A')}")
                print(f"    Command: {process.get('command_line', 'N/A')}")
                print()
        else:
            print("  未找到Process节点\n")
        
        # 5. 查询User节点详情
        print("=== User节点详情 ===")
        result = await neo4j_driver.execute_query('MATCH (u:User) RETURN u LIMIT 5')
        if result:
            for i, record in enumerate(result, 1):
                user = record['u']
                print(f"  User {i}:")
                print(f"    Name: {user.get('name', 'N/A')}")
                print(f"    UID: {user.get('uid', 'N/A')}")
                print()
        else:
            print("  未找到User节点\n")
        
        # 6. 查询File节点详情
        print("=== File节点详情 ===")
        result = await neo4j_driver.execute_query('MATCH (f:File) RETURN f LIMIT 5')
        if result:
            for i, record in enumerate(result, 1):
                file_node = record['f']
                print(f"  File {i}:")
                print(f"    Path: {file_node.get('path', 'N/A')}")
                print(f"    Type: {file_node.get('type', 'N/A')}")
                print()
        else:
            print("  未找到File节点\n")
        
        # 7. 查询Container节点详情
        print("=== Container节点详情 ===")
        result = await neo4j_driver.execute_query('MATCH (c:Container) RETURN c LIMIT 5')
        if result:
            for i, record in enumerate(result, 1):
                container = record['c']
                print(f"  Container {i}:")
                print(f"    ID: {container.get('id', 'N/A')}")
                print(f"    Name: {container.get('name', 'N/A')}")
                print()
        else:
            print("  未找到Container节点\n")
        
        # 8. 查询关系类型分布
        print("=== 关系类型分布 ===")
        result = await neo4j_driver.execute_query('MATCH ()-[r]->() RETURN DISTINCT type(r) as rel_type, count(r) as count ORDER BY count DESC')
        if result:
            for record in result:
                rel_type = record['rel_type']
                count = record['count']
                print(f"  {rel_type}: {count}个")
        print()
        
        # 9. 查询最近创建的节点
        print("=== 最近创建的节点 ===")
        result = await neo4j_driver.execute_query('MATCH (n) WHERE n.created_at IS NOT NULL RETURN labels(n) as labels, n.created_at as created_at ORDER BY n.created_at DESC LIMIT 10')
        if result:
            for i, record in enumerate(result, 1):
                labels = record['labels']
                created_at = record['created_at']
                label_str = ':'.join(labels) if labels else 'No Label'
                print(f"  {i}. {label_str} - {created_at}")
        print()
        
        await neo4j_driver.close()
        
    except Exception as e:
        print(f"❌ 分析数据库时发生错误: {e}")

if __name__ == "__main__":
    asyncio.run(analyze_graph_data())