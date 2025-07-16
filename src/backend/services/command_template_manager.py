#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS 命令模板管理器

负责将AI分析建议转换为可执行的命令模板:
1. 建议解析和理解
2. 命令模板匹配
3. 参数提取和验证
4. 回滚命令生成
5. 命令优化和组合

支持的命令类型:
- 进程管理 (kill_process, restart_service)
- 网络安全 (block_ip, update_firewall)
- 容器管理 (isolate_container)
- 文件操作 (backup_file, scan_file)
- 系统监控 (check_system_status)
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple, Pattern
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from loguru import logger


class TemplateCategory(Enum):
    """模板分类枚举"""
    PROCESS_MANAGEMENT = "process_management"
    NETWORK_SECURITY = "network_security"
    CONTAINER_MANAGEMENT = "container_management"
    FILE_OPERATIONS = "file_operations"
    SYSTEM_MONITORING = "system_monitoring"
    SECURITY_RESPONSE = "security_response"


@dataclass
class CommandTemplate:
    """命令模板数据结构"""
    name: str
    category: TemplateCategory
    action: str
    description: str
    patterns: List[str]  # 匹配模式
    parameters: Dict[str, Any]  # 参数定义
    command_template: str  # 命令模板
    risk_level: int  # 风险等级 (1-10)
    requires_confirmation: bool
    rollback_template: Optional[str] = None
    estimated_time: float = 10.0  # 预估执行时间（秒）
    dependencies: List[str] = None  # 依赖的其他命令
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


class CommandTemplateManager:
    """命令模板管理器类"""
    
    def __init__(self, templates_config_path: Optional[str] = None):
        """初始化命令模板管理器"""
        self.templates = {}
        self.pattern_cache = {}
        
        # 加载默认模板
        self._load_default_templates()
        
        # 加载用户自定义模板
        if templates_config_path and Path(templates_config_path).exists():
            self._load_custom_templates(templates_config_path)
        
        logger.info(f"Command Template Manager initialized with {len(self.templates)} templates")
    
    def _load_default_templates(self):
        """加载默认命令模板"""
        default_templates = [
            # 进程管理模板
            CommandTemplate(
                name="kill_malicious_process",
                category=TemplateCategory.PROCESS_MANAGEMENT,
                action="kill_process",
                description="Kill a malicious process by PID",
                patterns=[
                    r"kill\s+process\s+(\d+)",
                    r"terminate\s+process\s+(\d+)",
                    r"stop\s+process\s+(?:with\s+)?pid\s+(\d+)",
                    r"end\s+process\s+(\d+)",
                    r"kill\s+pid\s+(\d+)"
                ],
                parameters={
                    "pid": {"type": "int", "required": True, "validation": r"^\d+$"}
                },
                command_template="-TERM {pid}",
                risk_level=6,
                requires_confirmation=True,
                rollback_template=None,  # 进程终止无法回滚
                estimated_time=2.0
            ),
            
            CommandTemplate(
                name="restart_compromised_service",
                category=TemplateCategory.PROCESS_MANAGEMENT,
                action="restart_service",
                description="Restart a compromised system service",
                patterns=[
                    r"restart\s+service\s+(\w+)",
                    r"reload\s+service\s+(\w+)",
                    r"restart\s+(\w+)\s+service",
                    r"bounce\s+service\s+(\w+)"
                ],
                parameters={
                    "service_name": {"type": "str", "required": True, "validation": r"^[a-zA-Z0-9_-]+$"}
                },
                command_template="restart {service_name}",
                risk_level=4,
                requires_confirmation=True,
                rollback_template="stop {service_name}",
                estimated_time=15.0
            ),
            
            # 网络安全模板
            CommandTemplate(
                name="block_malicious_ip",
                category=TemplateCategory.NETWORK_SECURITY,
                action="block_ip",
                description="Block a malicious IP address",
                patterns=[
                    r"block\s+ip\s+([0-9.]+)",
                    r"ban\s+ip\s+([0-9.]+)",
                    r"blacklist\s+ip\s+([0-9.]+)",
                    r"drop\s+traffic\s+from\s+([0-9.]+)",
                    r"firewall\s+block\s+([0-9.]+)"
                ],
                parameters={
                    "ip_address": {"type": "str", "required": True, "validation": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"}
                },
                command_template="-A INPUT -s {ip_address} -j DROP",
                risk_level=3,
                requires_confirmation=False,
                rollback_template="-D INPUT -s {ip_address} -j DROP",
                estimated_time=3.0
            ),
            
            CommandTemplate(
                name="update_firewall_rules",
                category=TemplateCategory.NETWORK_SECURITY,
                action="update_firewall",
                description="Update firewall rules",
                patterns=[
                    r"(?:allow|deny)\s+port\s+(\d+)",
                    r"firewall\s+(allow|deny)\s+(\w+)",
                    r"ufw\s+(allow|deny)\s+(\w+)",
                    r"open\s+port\s+(\d+)",
                    r"close\s+port\s+(\d+)"
                ],
                parameters={
                    "action": {"type": "str", "required": True, "validation": r"^(allow|deny)$"},
                    "target": {"type": "str", "required": True, "validation": r"^\w+$"}
                },
                command_template="{action} {target}",
                risk_level=5,
                requires_confirmation=True,
                rollback_template="deny {target}",  # 默认拒绝
                estimated_time=5.0
            ),
            
            # 容器管理模板
            CommandTemplate(
                name="isolate_container",
                category=TemplateCategory.CONTAINER_MANAGEMENT,
                action="isolate_container",
                description="Isolate a compromised Docker container",
                patterns=[
                    r"isolate\s+container\s+(\w+)",
                    r"disconnect\s+container\s+(\w+)",
                    r"quarantine\s+container\s+(\w+)",
                    r"network\s+isolate\s+(\w+)"
                ],
                parameters={
                    "container_id": {"type": "str", "required": True, "validation": r"^\w+$"},
                    "network": {"type": "str", "required": False, "default": "bridge"}
                },
                command_template="network disconnect {network} {container_id}",
                risk_level=7,
                requires_confirmation=True,
                rollback_template="network connect {network} {container_id}",
                estimated_time=8.0
            ),
            
            # 文件操作模板
            CommandTemplate(
                name="backup_suspicious_file",
                category=TemplateCategory.FILE_OPERATIONS,
                action="backup_file",
                description="Backup a suspicious file before analysis",
                patterns=[
                    r"backup\s+file\s+([\w/.-]+)",
                    r"copy\s+file\s+([\w/.-]+)\s+to\s+backup",
                    r"preserve\s+file\s+([\w/.-]+)",
                    r"save\s+copy\s+of\s+([\w/.-]+)"
                ],
                parameters={
                    "file_path": {"type": "str", "required": True, "validation": r"^[\w/.-]+$"}
                },
                command_template="{file_path} {file_path}.backup",
                risk_level=2,
                requires_confirmation=False,
                rollback_template="rm {file_path}.backup",
                estimated_time=5.0
            ),
            
            CommandTemplate(
                name="scan_suspicious_file",
                category=TemplateCategory.FILE_OPERATIONS,
                action="scan_file",
                description="Scan a file for malware",
                patterns=[
                    r"scan\s+file\s+([\w/.-]+)",
                    r"check\s+file\s+([\w/.-]+)\s+for\s+malware",
                    r"antivirus\s+scan\s+([\w/.-]+)",
                    r"malware\s+scan\s+([\w/.-]+)"
                ],
                parameters={
                    "file_path": {"type": "str", "required": True, "validation": r"^[\w/.-]+$"}
                },
                command_template="{file_path}",
                risk_level=1,
                requires_confirmation=False,
                rollback_template=None,
                estimated_time=20.0
            ),
            
            # 系统监控模板
            CommandTemplate(
                name="check_service_status",
                category=TemplateCategory.SYSTEM_MONITORING,
                action="check_system_status",
                description="Check the status of a system service",
                patterns=[
                    r"check\s+status\s+of\s+(\w+)",
                    r"status\s+of\s+service\s+(\w+)",
                    r"verify\s+service\s+(\w+)",
                    r"monitor\s+service\s+(\w+)"
                ],
                parameters={
                    "service_name": {"type": "str", "required": True, "validation": r"^[a-zA-Z0-9_-]+$"}
                },
                command_template="status {service_name}",
                risk_level=1,
                requires_confirmation=False,
                rollback_template=None,
                estimated_time=3.0
            )
        ]
        
        # 注册模板
        for template in default_templates:
            self.templates[template.name] = template
            
            # 编译正则表达式并缓存
            self.pattern_cache[template.name] = [
                re.compile(pattern, re.IGNORECASE) for pattern in template.patterns
            ]
    
    def _load_custom_templates(self, config_path: str):
        """加载用户自定义模板"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                custom_config = json.load(f)
            
            for template_data in custom_config.get('templates', []):
                template = CommandTemplate(**template_data)
                self.templates[template.name] = template
                
                # 编译正则表达式
                self.pattern_cache[template.name] = [
                    re.compile(pattern, re.IGNORECASE) for pattern in template.patterns
                ]
            
            logger.info(f"Loaded {len(custom_config.get('templates', []))} custom templates")
            
        except Exception as e:
            logger.error(f"Failed to load custom templates from {config_path}: {e}")
    
    def parse_recommendation(self, recommendation: str) -> Optional[Dict[str, Any]]:
        """解析推荐建议，提取命令信息"""
        recommendation = recommendation.strip()
        
        logger.debug(f"Parsing recommendation: {recommendation}")
        
        # 遍历所有模板，尝试匹配
        for template_name, template in self.templates.items():
            patterns = self.pattern_cache[template_name]
            
            for pattern in patterns:
                match = pattern.search(recommendation)
                if match:
                    logger.debug(f"Matched template '{template_name}' with pattern '{pattern.pattern}'")
                    
                    # 提取参数
                    try:
                        params = self._extract_parameters(template, match, recommendation)
                        if params is None:
                            continue
                        
                        # 构建命令信息
                        command_info = {
                            'template_name': template_name,
                            'action': template.action,
                            'category': template.category.value,
                            'description': template.description,
                            'parameters': params,
                            'args': self._build_command_args(template, params),
                            'risk_level': template.risk_level,
                            'requires_confirmation': template.requires_confirmation,
                            'estimated_time': template.estimated_time,
                            'original_recommendation': recommendation
                        }
                        
                        logger.info(f"Successfully parsed recommendation to command: {template.action}")
                        return command_info
                        
                    except Exception as e:
                        logger.warning(f"Failed to extract parameters for template '{template_name}': {e}")
                        continue
        
        logger.warning(f"No matching template found for recommendation: {recommendation}")
        return None
    
    def _extract_parameters(self, template: CommandTemplate, match: re.Match, recommendation: str) -> Optional[Dict[str, Any]]:
        """从匹配结果中提取参数"""
        params = {}
        
        # 从正则匹配组中提取参数
        groups = match.groups()
        param_names = list(template.parameters.keys())
        
        # 映射匹配组到参数
        for i, group_value in enumerate(groups):
            if i < len(param_names):
                param_name = param_names[i]
                param_config = template.parameters[param_name]
                
                # 验证参数
                if not self._validate_parameter(group_value, param_config):
                    logger.warning(f"Parameter '{param_name}' validation failed: {group_value}")
                    return None
                
                # 类型转换
                try:
                    if param_config['type'] == 'int':
                        params[param_name] = int(group_value)
                    elif param_config['type'] == 'float':
                        params[param_name] = float(group_value)
                    else:
                        params[param_name] = group_value
                except ValueError as e:
                    logger.warning(f"Parameter type conversion failed for '{param_name}': {e}")
                    return None
        
        # 添加默认参数
        for param_name, param_config in template.parameters.items():
            if param_name not in params and 'default' in param_config:
                params[param_name] = param_config['default']
        
        # 检查必需参数
        for param_name, param_config in template.parameters.items():
            if param_config.get('required', False) and param_name not in params:
                logger.warning(f"Required parameter '{param_name}' not found")
                return None
        
        return params
    
    def _validate_parameter(self, value: str, param_config: Dict[str, Any]) -> bool:
        """验证参数值"""
        if 'validation' in param_config:
            pattern = re.compile(param_config['validation'])
            if not pattern.match(value):
                return False
        
        return True
    
    def _build_command_args(self, template: CommandTemplate, params: Dict[str, Any]) -> str:
        """构建命令参数"""
        try:
            return template.command_template.format(**params)
        except KeyError as e:
            logger.error(f"Missing parameter for template '{template.name}': {e}")
            raise
    
    def generate_rollback_command(self, command_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """生成回滚命令"""
        template_name = command_info.get('template_name')
        if not template_name or template_name not in self.templates:
            return None
        
        template = self.templates[template_name]
        if not template.rollback_template:
            return None
        
        try:
            params = command_info['parameters']
            rollback_args = template.rollback_template.format(**params)
            
            rollback_command = {
                'template_name': f"{template_name}_rollback",
                'action': f"rollback_{template.action}",
                'category': template.category.value,
                'description': f"Rollback for {template.description}",
                'parameters': params,
                'args': rollback_args,
                'risk_level': max(1, template.risk_level - 2),  # 回滚风险较低
                'requires_confirmation': False,
                'estimated_time': template.estimated_time * 0.5,
                'is_rollback': True
            }
            
            return rollback_command
            
        except Exception as e:
            logger.error(f"Failed to generate rollback command for '{template_name}': {e}")
            return None
    
    def get_template_by_name(self, name: str) -> Optional[CommandTemplate]:
        """根据名称获取模板"""
        return self.templates.get(name)
    
    def get_templates_by_category(self, category: TemplateCategory) -> List[CommandTemplate]:
        """根据分类获取模板"""
        return [template for template in self.templates.values() if template.category == category]
    
    def get_all_templates(self) -> Dict[str, CommandTemplate]:
        """获取所有模板"""
        return dict(self.templates)
    
    def add_custom_template(self, template: CommandTemplate) -> bool:
        """添加自定义模板"""
        try:
            self.templates[template.name] = template
            
            # 编译正则表达式
            self.pattern_cache[template.name] = [
                re.compile(pattern, re.IGNORECASE) for pattern in template.patterns
            ]
            
            logger.info(f"Added custom template: {template.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add custom template '{template.name}': {e}")
            return False
    
    def remove_template(self, name: str) -> bool:
        """移除模板"""
        if name in self.templates:
            del self.templates[name]
            if name in self.pattern_cache:
                del self.pattern_cache[name]
            logger.info(f"Removed template: {name}")
            return True
        return False
    
    def test_recommendation_parsing(self, recommendations: List[str]) -> List[Dict[str, Any]]:
        """测试推荐建议解析"""
        results = []
        
        for recommendation in recommendations:
            result = {
                'recommendation': recommendation,
                'parsed': self.parse_recommendation(recommendation)
            }
            results.append(result)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        category_counts = {}
        risk_distribution = {}
        
        for template in self.templates.values():
            # 分类统计
            category = template.category.value
            category_counts[category] = category_counts.get(category, 0) + 1
            
            # 风险等级分布
            risk_level = template.risk_level
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
        
        return {
            'total_templates': len(self.templates),
            'category_distribution': category_counts,
            'risk_distribution': risk_distribution,
            'templates_with_rollback': sum(1 for t in self.templates.values() if t.rollback_template)
        }


# 创建全局命令模板管理器实例
command_template_manager = CommandTemplateManager()


# 便捷函数
def parse_recommendations(recommendations: List[str]) -> List[Dict[str, Any]]:
    """解析推荐建议列表"""
    results = []
    
    for recommendation in recommendations:
        parsed = command_template_manager.parse_recommendation(recommendation)
        if parsed:
            results.append(parsed)
    
    return results


def get_template_info(template_name: str) -> Optional[Dict[str, Any]]:
    """获取模板信息"""
    template = command_template_manager.get_template_by_name(template_name)
    if template:
        return {
            'name': template.name,
            'category': template.category.value,
            'action': template.action,
            'description': template.description,
            'risk_level': template.risk_level,
            'requires_confirmation': template.requires_confirmation,
            'estimated_time': template.estimated_time,
            'has_rollback': template.rollback_template is not None
        }
    return None