#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS 知识管理服务模块

实现知识库管理的核心功能:
1. 知识上传和导入
2. 知识编辑和更新
3. 知识分类和标签管理
4. 批量知识处理
5. 知识质量控制
6. 知识库统计和分析

设计原则:
- 灵活导入: 支持多种格式的知识导入
- 质量控制: 确保知识的准确性和相关性
- 版本管理: 支持知识的版本控制
- 批量处理: 高效的批量操作
- 元数据管理: 丰富的元数据支持
"""

import asyncio
import json
import csv
import time
import hashlib
import uuid
from typing import Dict, List, Any, Optional, Union, Tuple, IO
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import re
from functools import wraps

from loguru import logger

# 导入相关服务
from .pinecone_service import (
    PineconeService, KnowledgeItem, KnowledgeType
)


class ImportFormat(Enum):
    """导入格式枚举"""
    JSON = "json"
    CSV = "csv"
    TXT = "txt"
    MARKDOWN = "markdown"
    XML = "xml"


class ValidationLevel(Enum):
    """验证级别枚举"""
    STRICT = "strict"        # 严格验证
    MODERATE = "moderate"    # 中等验证
    LENIENT = "lenient"      # 宽松验证
    NONE = "none"            # 无验证


@dataclass
class ImportRequest:
    """导入请求数据结构"""
    format: ImportFormat
    content: Union[str, bytes, Dict[str, Any], List[Dict[str, Any]]]
    default_knowledge_type: KnowledgeType = KnowledgeType.SECURITY_RULE
    default_tags: List[str] = None
    validation_level: ValidationLevel = ValidationLevel.MODERATE
    batch_size: int = 50
    auto_generate_id: bool = True
    overwrite_existing: bool = False
    request_id: Optional[str] = None
    
    def __post_init__(self):
        if self.default_tags is None:
            self.default_tags = []
        if self.request_id is None:
            self.request_id = f"import_{uuid.uuid4().hex[:8]}_{int(time.time())}"


@dataclass
class ImportResult:
    """导入结果数据结构"""
    request_id: str
    total_items: int
    successful_imports: int
    failed_imports: int
    skipped_items: int
    validation_errors: List[Dict[str, Any]]
    processing_time: float
    imported_ids: List[str]
    failed_items: List[Dict[str, Any]]
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result


@dataclass
class KnowledgeTemplate:
    """知识模板数据结构"""
    name: str
    description: str
    knowledge_type: KnowledgeType
    required_fields: List[str]
    optional_fields: List[str]
    default_tags: List[str]
    validation_rules: Dict[str, Any]
    example: Dict[str, Any]


class KnowledgeManager:
    """知识管理服务"""
    
    def __init__(self, pinecone_service: PineconeService):
        """
        初始化知识管理服务
        
        Args:
            pinecone_service: Pinecone向量数据库服务
        """
        self.pinecone_service = pinecone_service
        
        # 知识模板
        self.templates = self._initialize_templates()
        
        # 统计信息
        self.stats = {
            'total_imports': 0,
            'total_knowledge_items': 0,
            'successful_imports': 0,
            'failed_imports': 0,
            'knowledge_by_type': {},
            'average_import_time': 0.0,
            'last_import_time': None
        }
        
        self.logger = logger.bind(service="knowledge_manager")
    
    def _initialize_templates(self) -> Dict[str, KnowledgeTemplate]:
        """初始化知识模板"""
        templates = {
            'security_rule': KnowledgeTemplate(
                name="安全规则",
                description="安全检测规则和模式",
                knowledge_type=KnowledgeType.SECURITY_RULE,
                required_fields=['title', 'content', 'rule_pattern'],
                optional_fields=['severity', 'category', 'references'],
                default_tags=['security', 'rule'],
                validation_rules={
                    'title': {'min_length': 5, 'max_length': 200},
                    'content': {'min_length': 20, 'max_length': 5000},
                    'rule_pattern': {'required': True}
                },
                example={
                    'title': '可疑文件访问检测',
                    'content': '检测对敏感文件的异常访问行为，包括系统配置文件、密码文件等',
                    'rule_pattern': 'file_access AND (path contains "/etc/passwd" OR path contains "/etc/shadow")',
                    'severity': 'HIGH',
                    'category': 'file_access'
                }
            ),
            'threat_pattern': KnowledgeTemplate(
                name="威胁模式",
                description="已知的攻击模式和威胁指标",
                knowledge_type=KnowledgeType.THREAT_PATTERN,
                required_fields=['title', 'content', 'indicators'],
                optional_fields=['mitre_tactics', 'mitre_techniques', 'severity'],
                default_tags=['threat', 'pattern'],
                validation_rules={
                    'title': {'min_length': 5, 'max_length': 200},
                    'content': {'min_length': 50, 'max_length': 5000},
                    'indicators': {'type': 'list', 'min_items': 1}
                },
                example={
                    'title': 'SQL注入攻击模式',
                    'content': 'SQL注入是一种常见的Web应用攻击方式，通过在输入中插入恶意SQL代码来操控数据库',
                    'indicators': ['UNION SELECT', 'OR 1=1', 'DROP TABLE'],
                    'mitre_tactics': ['Initial Access'],
                    'mitre_techniques': ['T1190']
                }
            ),
            'remediation_guide': KnowledgeTemplate(
                name="修复指南",
                description="安全问题的修复和缓解措施",
                knowledge_type=KnowledgeType.REMEDIATION_GUIDE,
                required_fields=['title', 'content', 'steps'],
                optional_fields=['prerequisites', 'tools_required', 'estimated_time'],
                default_tags=['remediation', 'guide'],
                validation_rules={
                    'title': {'min_length': 5, 'max_length': 200},
                    'content': {'min_length': 50, 'max_length': 5000},
                    'steps': {'type': 'list', 'min_items': 1}
                },
                example={
                    'title': 'SQL注入漏洞修复指南',
                    'content': '针对SQL注入漏洞的系统性修复方案',
                    'steps': [
                        '使用参数化查询',
                        '输入验证和过滤',
                        '最小权限原则',
                        '定期安全审计'
                    ],
                    'estimated_time': '2-4小时'
                }
            )
        }
        
        return templates
    
    async def import_knowledge(self, request: ImportRequest) -> ImportResult:
        """导入知识到向量数据库
        
        Args:
            request: 导入请求
            
        Returns:
            ImportResult: 导入结果
        """
        start_time = time.time()
        
        try:
            self.logger.info(f"开始导入知识: {request.request_id}, 格式: {request.format.value}")
            
            # 1. 解析内容
            parsed_items = await self._parse_content(request)
            
            # 2. 验证知识项
            validated_items, validation_errors = await self._validate_knowledge_items(
                parsed_items, request.validation_level
            )
            
            # 3. 转换为KnowledgeItem对象
            knowledge_items = await self._convert_to_knowledge_items(
                validated_items, request
            )
            
            # 4. 批量上传到向量数据库
            upload_result = await self._batch_upload_knowledge(
                knowledge_items, request.batch_size
            )
            
            # 5. 构建导入结果
            processing_time = (time.time() - start_time) * 1000
            
            import_result = ImportResult(
                request_id=request.request_id,
                total_items=len(parsed_items),
                successful_imports=upload_result['successful_uploads'],
                failed_imports=upload_result['failed_uploads'],
                skipped_items=len(parsed_items) - len(validated_items),
                validation_errors=validation_errors,
                processing_time=processing_time,
                imported_ids=[item.id for item in knowledge_items[:upload_result['successful_uploads']]],
                failed_items=upload_result.get('failed_items', []),
                timestamp=datetime.now()
            )
            
            # 6. 更新统计信息
            await self._update_import_statistics(import_result)
            
            self.logger.info(f"知识导入完成: {request.request_id}, 成功: {import_result.successful_imports}, 失败: {import_result.failed_imports}")
            return import_result
            
        except Exception as e:
            self.logger.error(f"知识导入失败: {e}")
            raise
    
    async def _parse_content(self, request: ImportRequest) -> List[Dict[str, Any]]:
        """解析导入内容
        
        Args:
            request: 导入请求
            
        Returns:
            List[Dict[str, Any]]: 解析后的知识项列表
        """
        try:
            if request.format == ImportFormat.JSON:
                return await self._parse_json_content(request.content)
            elif request.format == ImportFormat.CSV:
                return await self._parse_csv_content(request.content)
            elif request.format == ImportFormat.TXT:
                return await self._parse_txt_content(request.content)
            elif request.format == ImportFormat.MARKDOWN:
                return await self._parse_markdown_content(request.content)
            else:
                raise ValueError(f"不支持的导入格式: {request.format.value}")
                
        except Exception as e:
            self.logger.error(f"内容解析失败: {e}")
            raise
    
    async def _parse_json_content(self, content: Union[str, Dict, List]) -> List[Dict[str, Any]]:
        """解析JSON内容"""
        if isinstance(content, str):
            data = json.loads(content)
        else:
            data = content
        
        if isinstance(data, dict):
            return [data]
        elif isinstance(data, list):
            return data
        else:
            raise ValueError("JSON内容必须是对象或数组")
    
    async def _parse_csv_content(self, content: str) -> List[Dict[str, Any]]:
        """解析CSV内容"""
        lines = content.strip().split('\n')
        if len(lines) < 2:
            raise ValueError("CSV内容至少需要标题行和一行数据")
        
        reader = csv.DictReader(lines)
        return list(reader)
    
    async def _parse_txt_content(self, content: str) -> List[Dict[str, Any]]:
        """解析文本内容"""
        # 简单的文本解析，每行作为一个知识项的标题
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        items = []
        for i, line in enumerate(lines):
            items.append({
                'title': line,
                'content': line,  # 简单情况下，内容就是标题
                'id': f"txt_item_{i+1}"
            })
        
        return items
    
    async def _parse_markdown_content(self, content: str) -> List[Dict[str, Any]]:
        """解析Markdown内容"""
        # 简单的Markdown解析，以标题为分割点
        sections = re.split(r'^#+\s+(.+)$', content, flags=re.MULTILINE)
        
        items = []
        for i in range(1, len(sections), 2):
            if i + 1 < len(sections):
                title = sections[i].strip()
                content_text = sections[i + 1].strip()
                
                items.append({
                    'title': title,
                    'content': content_text,
                    'id': f"md_item_{i//2 + 1}"
                })
        
        return items
    
    async def _validate_knowledge_items(self, 
                                      items: List[Dict[str, Any]], 
                                      validation_level: ValidationLevel) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """验证知识项
        
        Args:
            items: 知识项列表
            validation_level: 验证级别
            
        Returns:
            Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]: (有效项, 验证错误)
        """
        if validation_level == ValidationLevel.NONE:
            return items, []
        
        valid_items = []
        validation_errors = []
        
        for i, item in enumerate(items):
            try:
                # 基本字段检查
                if not item.get('title'):
                    validation_errors.append({
                        'item_index': i,
                        'error': 'title字段不能为空',
                        'item': item
                    })
                    continue
                
                if not item.get('content'):
                    validation_errors.append({
                        'item_index': i,
                        'error': 'content字段不能为空',
                        'item': item
                    })
                    continue
                
                # 根据验证级别进行不同程度的验证
                if validation_level in [ValidationLevel.MODERATE, ValidationLevel.STRICT]:
                    # 长度检查
                    if len(item['title']) < 5:
                        validation_errors.append({
                            'item_index': i,
                            'error': 'title长度不能少于5个字符',
                            'item': item
                        })
                        continue
                    
                    if len(item['content']) < 10:
                        validation_errors.append({
                            'item_index': i,
                            'error': 'content长度不能少于10个字符',
                            'item': item
                        })
                        continue
                
                if validation_level == ValidationLevel.STRICT:
                    # 严格验证：检查特殊字符、格式等
                    if not re.match(r'^[\w\s\u4e00-\u9fff\-_.,!?()]+$', item['title']):
                        validation_errors.append({
                            'item_index': i,
                            'error': 'title包含不允许的特殊字符',
                            'item': item
                        })
                        continue
                
                valid_items.append(item)
                
            except Exception as e:
                validation_errors.append({
                    'item_index': i,
                    'error': f'验证异常: {str(e)}',
                    'item': item
                })
        
        return valid_items, validation_errors
    
    async def _convert_to_knowledge_items(self, 
                                        items: List[Dict[str, Any]], 
                                        request: ImportRequest) -> List[KnowledgeItem]:
        """转换为KnowledgeItem对象
        
        Args:
            items: 原始知识项列表
            request: 导入请求
            
        Returns:
            List[KnowledgeItem]: KnowledgeItem对象列表
        """
        knowledge_items = []
        
        for item in items:
            try:
                # 生成ID
                if request.auto_generate_id or not item.get('id'):
                    item_id = f"{request.default_knowledge_type.value}_{uuid.uuid4().hex[:8]}"
                else:
                    item_id = item['id']
                
                # 确定知识类型
                knowledge_type = KnowledgeType(item.get('knowledge_type', request.default_knowledge_type.value))
                
                # 合并标签
                tags = list(set(item.get('tags', []) + request.default_tags))
                
                # 提取元数据
                metadata = {k: v for k, v in item.items() 
                          if k not in ['id', 'title', 'content', 'knowledge_type', 'tags', 'created_at', 'updated_at']}
                
                # 创建KnowledgeItem
                knowledge_item = KnowledgeItem(
                    id=item_id,
                    title=item['title'],
                    content=item['content'],
                    knowledge_type=knowledge_type,
                    metadata=metadata,
                    tags=tags,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                
                knowledge_items.append(knowledge_item)
                
            except Exception as e:
                self.logger.error(f"转换知识项失败: {e}, 项目: {item}")
                continue
        
        return knowledge_items
    
    async def _batch_upload_knowledge(self, 
                                    knowledge_items: List[KnowledgeItem], 
                                    batch_size: int) -> Dict[str, Any]:
        """批量上传知识到向量数据库
        
        Args:
            knowledge_items: 知识项列表
            batch_size: 批次大小
            
        Returns:
            Dict[str, Any]: 上传结果
        """
        try:
            # 使用Pinecone服务的批量上传功能
            upload_result = await self.pinecone_service.upload_knowledge(knowledge_items)
            return upload_result
            
        except Exception as e:
            self.logger.error(f"批量上传知识失败: {e}")
            raise
    
    async def create_knowledge_item(self, 
                                  title: str, 
                                  content: str, 
                                  knowledge_type: KnowledgeType,
                                  tags: List[str] = None,
                                  metadata: Dict[str, Any] = None) -> KnowledgeItem:
        """创建单个知识项
        
        Args:
            title: 标题
            content: 内容
            knowledge_type: 知识类型
            tags: 标签列表
            metadata: 元数据
            
        Returns:
            KnowledgeItem: 创建的知识项
        """
        try:
            knowledge_item = KnowledgeItem(
                id=f"{knowledge_type.value}_{uuid.uuid4().hex[:8]}",
                title=title,
                content=content,
                knowledge_type=knowledge_type,
                metadata=metadata or {},
                tags=tags or [],
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            
            # 上传到向量数据库
            await self.pinecone_service.upload_knowledge([knowledge_item])
            
            self.logger.info(f"创建知识项成功: {knowledge_item.id}")
            return knowledge_item
            
        except Exception as e:
            self.logger.error(f"创建知识项失败: {e}")
            raise
    
    async def update_knowledge_item(self, 
                                  knowledge_id: str, 
                                  updates: Dict[str, Any]) -> KnowledgeItem:
        """更新知识项
        
        Args:
            knowledge_id: 知识项ID
            updates: 更新内容
            
        Returns:
            KnowledgeItem: 更新后的知识项
        """
        try:
            # 这里需要先从向量数据库获取现有知识项
            # 由于Pinecone不直接支持按ID获取，我们需要实现一个查询机制
            # 或者维护一个本地索引
            
            # 简化实现：创建新的知识项来替换旧的
            if 'title' in updates and 'content' in updates:
                knowledge_type = KnowledgeType(updates.get('knowledge_type', 'security_rule'))
                
                updated_item = KnowledgeItem(
                    id=knowledge_id,
                    title=updates['title'],
                    content=updates['content'],
                    knowledge_type=knowledge_type,
                    metadata=updates.get('metadata', {}),
                    tags=updates.get('tags', []),
                    created_at=datetime.now(),  # 这里应该保持原创建时间
                    updated_at=datetime.now()
                )
                
                # 上传更新的知识项
                await self.pinecone_service.upload_knowledge([updated_item])
                
                self.logger.info(f"更新知识项成功: {knowledge_id}")
                return updated_item
            else:
                raise ValueError("更新必须包含title和content字段")
                
        except Exception as e:
            self.logger.error(f"更新知识项失败: {e}")
            raise
    
    async def delete_knowledge_items(self, knowledge_ids: List[str]) -> Dict[str, Any]:
        """删除知识项
        
        Args:
            knowledge_ids: 知识项ID列表
            
        Returns:
            Dict[str, Any]: 删除结果
        """
        try:
            result = await self.pinecone_service.delete_knowledge(knowledge_ids)
            self.logger.info(f"删除知识项成功: {len(knowledge_ids)}个")
            return result
            
        except Exception as e:
            self.logger.error(f"删除知识项失败: {e}")
            raise
    
    async def get_knowledge_templates(self) -> Dict[str, KnowledgeTemplate]:
        """获取知识模板
        
        Returns:
            Dict[str, KnowledgeTemplate]: 知识模板字典
        """
        return self.templates
    
    async def _update_import_statistics(self, import_result: ImportResult) -> None:
        """更新导入统计信息
        
        Args:
            import_result: 导入结果
        """
        self.stats['total_imports'] += 1
        self.stats['successful_imports'] += import_result.successful_imports
        self.stats['failed_imports'] += import_result.failed_imports
        self.stats['total_knowledge_items'] += import_result.successful_imports
        
        # 更新平均导入时间
        self.stats['average_import_time'] = (
            (self.stats['average_import_time'] * (self.stats['total_imports'] - 1) + import_result.processing_time) /
            self.stats['total_imports']
        )
        
        self.stats['last_import_time'] = import_result.timestamp.isoformat()
    
    async def get_statistics(self) -> Dict[str, Any]:
        """获取知识管理统计信息"""
        # 获取向量数据库统计信息
        pinecone_stats = await self.pinecone_service.get_statistics()
        
        return {
            'knowledge_manager_stats': self.stats,
            'pinecone_stats': pinecone_stats,
            'templates_count': len(self.templates),
            'available_templates': list(self.templates.keys())
        }
    
    async def export_knowledge(self, 
                             knowledge_types: List[KnowledgeType] = None,
                             format: ImportFormat = ImportFormat.JSON) -> str:
        """导出知识
        
        Args:
            knowledge_types: 要导出的知识类型
            format: 导出格式
            
        Returns:
            str: 导出的内容
        """
        try:
            # 这里需要实现从向量数据库导出的逻辑
            # 由于Pinecone的限制，这可能需要额外的索引或缓存机制
            
            # 简化实现：返回模板示例
            if format == ImportFormat.JSON:
                examples = []
                for template in self.templates.values():
                    if not knowledge_types or template.knowledge_type in knowledge_types:
                        examples.append(template.example)
                
                return json.dumps(examples, indent=2, ensure_ascii=False)
            else:
                raise NotImplementedError(f"暂不支持{format.value}格式的导出")
                
        except Exception as e:
            self.logger.error(f"导出知识失败: {e}")
            raise