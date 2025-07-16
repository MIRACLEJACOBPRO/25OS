#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAG服务使用演示脚本
展示如何与RAG服务进行交互
"""

import requests
import json
import time
from typing import Dict, Any

# 服务配置
BASE_URL = "http://localhost:8000"
HEADERS = {"Content-Type": "application/json"}

def print_section(title: str):
    """打印分节标题"""
    print("\n" + "="*60)
    print(f" {title} ")
    print("="*60)

def print_response(response: requests.Response, title: str = ""):
    """格式化打印响应"""
    if title:
        print(f"\n--- {title} ---")
    
    print(f"状态码: {response.status_code}")
    
    try:
        data = response.json()
        print(f"响应内容: {json.dumps(data, ensure_ascii=False, indent=2)}")
    except:
        print(f"响应内容: {response.text}")

def test_health_check():
    """测试健康检查"""
    print_section("1. 健康检查")
    
    try:
        response = requests.get(f"{BASE_URL}/health")
        print_response(response, "健康检查结果")
        return response.status_code == 200
    except Exception as e:
        print(f"健康检查失败: {e}")
        return False

def test_root_endpoint():
    """测试根端点"""
    print_section("2. 根端点信息")
    
    try:
        response = requests.get(f"{BASE_URL}/")
        print_response(response, "根端点信息")
    except Exception as e:
        print(f"根端点访问失败: {e}")

def test_config():
    """测试配置信息"""
    print_section("3. 配置信息")
    
    try:
        response = requests.get(f"{BASE_URL}/config")
        print_response(response, "配置信息")
    except Exception as e:
        print(f"配置信息获取失败: {e}")

def test_documents_list():
    """测试文档列表"""
    print_section("4. 文档列表")
    
    try:
        response = requests.get(f"{BASE_URL}/documents")
        print_response(response, "文档列表")
    except Exception as e:
        print(f"文档列表获取失败: {e}")

def test_search():
    """测试搜索功能"""
    print_section("5. 搜索功能测试")
    
    search_queries = [
        {"query": "B_25OS", "top_k": 3},
        {"query": "RAG服务", "top_k": 2},
        {"query": "安全监控", "top_k": 1},
        {"query": "Falco", "top_k": 2}
    ]
    
    for i, search_data in enumerate(search_queries, 1):
        try:
            response = requests.post(
                f"{BASE_URL}/search",
                headers=HEADERS,
                json=search_data
            )
            print_response(response, f"搜索测试 {i}: '{search_data['query']}'")
            time.sleep(0.5)  # 避免请求过快
        except Exception as e:
            print(f"搜索测试 {i} 失败: {e}")

def test_chat():
    """测试聊天功能"""
    print_section("6. 聊天功能测试")
    
    chat_messages = [
        "什么是B_25OS系统？",
        "RAG服务有什么功能？",
        "系统如何进行安全监控？",
        "如何使用Falco进行威胁检测？",
        "请介绍一下Neo4j图数据库的作用"
    ]
    
    for i, message in enumerate(chat_messages, 1):
        try:
            chat_data = {
                "message": message,
                "max_tokens": 1000,
                "temperature": 0.7
            }
            
            response = requests.post(
                f"{BASE_URL}/chat",
                headers=HEADERS,
                json=chat_data
            )
            print_response(response, f"聊天测试 {i}: '{message}'")
            time.sleep(1)  # 给服务器一些处理时间
        except Exception as e:
            print(f"聊天测试 {i} 失败: {e}")

def test_add_document():
    """测试添加文档"""
    print_section("7. 添加文档测试")
    
    new_documents = [
        {
            "title": "Docker部署指南",
            "content": "B_25OS支持Docker容器化部署，提供了完整的Dockerfile和docker-compose配置文件，支持一键部署和扩展。",
            "metadata": {"category": "deployment", "priority": "medium"}
        },
        {
            "title": "API接口文档",
            "content": "系统提供RESTful API接口，支持聊天、搜索、文档管理等功能，所有接口都有详细的文档说明。",
            "metadata": {"category": "api", "priority": "high"}
        }
    ]
    
    for i, doc_data in enumerate(new_documents, 1):
        try:
            response = requests.post(
                f"{BASE_URL}/documents",
                headers=HEADERS,
                json=doc_data
            )
            print_response(response, f"添加文档 {i}: '{doc_data['title']}'")
            time.sleep(0.5)
        except Exception as e:
            print(f"添加文档 {i} 失败: {e}")

def test_updated_documents_list():
    """测试更新后的文档列表"""
    print_section("8. 更新后的文档列表")
    
    try:
        response = requests.get(f"{BASE_URL}/documents")
        print_response(response, "更新后的文档列表")
    except Exception as e:
        print(f"文档列表获取失败: {e}")

def test_search_new_content():
    """测试搜索新添加的内容"""
    print_section("9. 搜索新内容测试")
    
    search_queries = [
        {"query": "Docker", "top_k": 2},
        {"query": "API", "top_k": 2},
        {"query": "部署", "top_k": 3}
    ]
    
    for i, search_data in enumerate(search_queries, 1):
        try:
            response = requests.post(
                f"{BASE_URL}/search",
                headers=HEADERS,
                json=search_data
            )
            print_response(response, f"新内容搜索 {i}: '{search_data['query']}'")
            time.sleep(0.5)
        except Exception as e:
            print(f"新内容搜索 {i} 失败: {e}")

def main():
    """主函数"""
    print("\n🚀 开始RAG服务演示")
    print(f"服务地址: {BASE_URL}")
    print(f"API文档: {BASE_URL}/docs")
    
    # 1. 健康检查
    if not test_health_check():
        print("\n❌ 服务未正常运行，请检查服务状态")
        return
    
    print("\n✅ 服务运行正常，开始功能演示...")
    
    # 2. 基础信息测试
    test_root_endpoint()
    test_config()
    
    # 3. 文档管理测试
    test_documents_list()
    
    # 4. 搜索功能测试
    test_search()
    
    # 5. 聊天功能测试
    test_chat()
    
    # 6. 添加文档测试
    test_add_document()
    
    # 7. 验证新文档
    test_updated_documents_list()
    test_search_new_content()
    
    print_section("演示完成")
    print("\n🎉 RAG服务演示完成！")
    print(f"\n📖 查看完整API文档: {BASE_URL}/docs")
    print(f"📊 查看ReDoc文档: {BASE_URL}/redoc")
    print("\n💡 提示:")
    print("  - 所有API都支持JSON格式的请求和响应")
    print("  - 聊天功能会自动从知识库检索相关上下文")
    print("  - 搜索功能支持关键词匹配和相关性排序")
    print("  - 文档管理支持动态添加和查询")
    print("  - 服务支持CORS，可以从前端直接调用")

if __name__ == "__main__":
    main()