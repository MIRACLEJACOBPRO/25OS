#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Falco日志解析模块
实现Falco日志的实时读取、解析和标准化处理

功能:
1. 实时监控Falco日志文件
2. 解析JSON格式的Falco事件
3. 提取三元组抽象(主体-动作-客体)
4. 事件标准化和验证
5. 错误处理和日志轮转支持
"""

import json
import re
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum

from loguru import logger
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import aiofiles


class EventPriority(Enum):
    """事件优先级枚举"""
    CRITICAL = 1    # 安全威胁
    ERROR = 2       # 错误事件
    HIGH = 3        # 异常行为
    MEDIUM = 4      # 可疑活动
    LOW = 5         # 正常事件
    DEBUG = 6       # 调试信息
    NOTICE = 7      # 通知信息
    INFO = 5        # 信息事件，映射到 LOW
    WARNING = 3     # 警告事件，映射到 HIGH


class ActionType(Enum):
    """动作类型枚举"""
    PROCESS_EXEC = "process_exec"        # 进程执行
    FILE_ACCESS = "file_access"          # 文件访问
    FILE_WRITE = "file_write"            # 文件写入
    FILE_READ = "file_read"              # 文件读取
    NETWORK_CONN = "network_conn"        # 网络连接
    SYSCALL = "syscall"                  # 系统调用
    CONTAINER_OP = "container_op"        # 容器操作
    USER_AUTH = "user_auth"              # 用户认证
    PRIVILEGE_ESC = "privilege_esc"      # 权限提升
    UNKNOWN = "unknown"                  # 未知类型


@dataclass
class TripleExtraction:
    """三元组抽象数据结构"""
    subject: str        # 主体(谁)
    action: str         # 动作(做什么)
    object: str         # 客体(对什么)
    subject_type: str   # 主体类型(process/user/container)
    action_type: ActionType  # 动作类型
    object_type: str    # 客体类型(file/network/process)
    confidence: float   # 置信度(0.0-1.0)


@dataclass
class StandardizedEvent:
    """标准化事件数据结构"""
    event_id: str                    # 事件唯一ID
    timestamp: datetime              # 事件时间戳
    priority: EventPriority          # 事件优先级
    rule_name: str                   # 触发的Falco规则名
    message: str                     # 事件描述
    triple: TripleExtraction         # 三元组抽象
    raw_data: Dict[str, Any]         # 原始Falco数据
    host_info: Dict[str, str]        # 主机信息
    process_info: Dict[str, Any]     # 进程信息
    file_info: Optional[Dict[str, str]] = None      # 文件信息
    network_info: Optional[Dict[str, str]] = None   # 网络信息
    container_info: Optional[Dict[str, str]] = None # 容器信息
    user_info: Optional[Dict[str, str]] = None      # 用户信息
    tags: List[str] = None           # 事件标签
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class FalcoLogParser:
    """Falco日志解析器主类"""
    
    def __init__(self, log_file_path: str, callback=None):
        """
        初始化日志解析器
        
        Args:
            log_file_path: Falco日志文件路径
            callback: 事件处理回调函数
        """
        self.log_file_path = Path(log_file_path)
        self.callback = callback
        self.observer = None
        self.file_position = 0
        self.processed_events = set()  # 防止重复处理
        
        # 规则优先级映射
        self.rule_priority_map = {
            # 高危规则
            "Terminal shell in container": EventPriority.CRITICAL,
            "Write below binary dir": EventPriority.CRITICAL,
            "Write below etc": EventPriority.HIGH,
            "Read sensitive file trusted after startup": EventPriority.HIGH,
            "Modify binary dirs": EventPriority.CRITICAL,
            "Mkdir binary dirs": EventPriority.CRITICAL,
            "Change thread namespace": EventPriority.HIGH,
            "Netcat Remote Code Execution in Container": EventPriority.CRITICAL,
            "Launch Suspicious Network Tool in Container": EventPriority.HIGH,
            "Suspicious process opening a sensitive file": EventPriority.HIGH,
            # 中等风险规则
            "File Open by Executable not in /usr/bin": EventPriority.MEDIUM,
            "Non sudo setuid": EventPriority.MEDIUM,
            "Create files below dev": EventPriority.MEDIUM,
            # 低风险规则
            "File below a known binary directory opened for writing": EventPriority.LOW,
        }
        
        # 动作类型识别模式
        self.action_patterns = {
            ActionType.PROCESS_EXEC: [
                r"exec", r"execve", r"spawn", r"launch", r"run", r"execute"
            ],
            ActionType.FILE_ACCESS: [
                r"open", r"read", r"write", r"create", r"delete", r"modify", r"access"
            ],
            ActionType.NETWORK_CONN: [
                r"connect", r"bind", r"listen", r"socket", r"network"
            ],
            ActionType.SYSCALL: [
                r"syscall", r"system call"
            ],
            ActionType.CONTAINER_OP: [
                r"container", r"docker", r"pod", r"namespace"
            ],
            ActionType.USER_AUTH: [
                r"login", r"auth", r"sudo", r"su", r"setuid"
            ],
            ActionType.PRIVILEGE_ESC: [
                r"privilege", r"escalat", r"setuid", r"setgid", r"capabilities"
            ]
        }
        
        logger.info(f"FalcoLogParser initialized for {self.log_file_path}")
    
    def generate_event_id(self, event_data: Dict[str, Any]) -> str:
        """生成事件唯一ID"""
        # 使用时间戳、规则名和关键字段生成唯一ID
        key_fields = [
            str(event_data.get('time', '')),
            event_data.get('rule', ''),
            event_data.get('output', ''),
            str(event_data.get('output_fields', {}).get('proc.pid', '')),
            str(event_data.get('output_fields', {}).get('fd.name', ''))
        ]
        key_string = '|'.join(key_fields)
        return hashlib.md5(key_string.encode()).hexdigest()[:16]
    
    def extract_triple(self, event_data: Dict[str, Any]) -> TripleExtraction:
        """从Falco事件中提取三元组抽象"""
        output_fields = event_data.get('output_fields', {})
        rule_name = event_data.get('rule', '')
        output_msg = event_data.get('output', '')
        
        # 提取主体信息
        subject = self._extract_subject(output_fields)
        subject_type = self._determine_subject_type(output_fields)
        
        # 提取动作信息
        action = self._extract_action(rule_name, output_msg, output_fields)
        action_type = self._determine_action_type(rule_name, output_msg)
        
        # 提取客体信息
        obj = self._extract_object(output_fields, action_type)
        object_type = self._determine_object_type(output_fields, action_type)
        
        # 计算置信度
        confidence = self._calculate_confidence(output_fields, rule_name)
        
        return TripleExtraction(
            subject=subject,
            action=action,
            object=obj,
            subject_type=subject_type,
            action_type=action_type,
            object_type=object_type,
            confidence=confidence
        )
    
    def _extract_subject(self, output_fields: Dict[str, Any]) -> str:
        """提取主体(谁在执行操作)"""
        # 优先级: 进程名 > 用户名 > 容器名
        if 'proc.name' in output_fields:
            proc_name = output_fields['proc.name']
            if 'proc.pid' in output_fields:
                return f"{proc_name}[{output_fields['proc.pid']}]"
            return proc_name
        
        if 'user.name' in output_fields:
            return f"user:{output_fields['user.name']}"
        
        if 'container.name' in output_fields:
            return f"container:{output_fields['container.name']}"
        
        return "unknown_subject"
    
    def _determine_subject_type(self, output_fields: Dict[str, Any]) -> str:
        """确定主体类型"""
        if 'proc.name' in output_fields:
            return "process"
        elif 'container.name' in output_fields:
            return "container"
        elif 'user.name' in output_fields:
            return "user"
        else:
            return "unknown"
    
    def _extract_action(self, rule_name: str, output_msg: str, output_fields: Dict[str, Any]) -> str:
        """提取动作(做什么操作)"""
        # 从规则名中提取动作
        rule_lower = rule_name.lower()
        
        if "write" in rule_lower or "modify" in rule_lower:
            return "write"
        elif "read" in rule_lower or "open" in rule_lower:
            return "read"
        elif "exec" in rule_lower or "launch" in rule_lower:
            return "execute"
        elif "connect" in rule_lower or "network" in rule_lower:
            return "connect"
        elif "create" in rule_lower or "mkdir" in rule_lower:
            return "create"
        elif "delete" in rule_lower or "remove" in rule_lower:
            return "delete"
        
        # 从输出消息中提取动作
        output_lower = output_msg.lower()
        action_keywords = [
            "opened", "wrote", "read", "executed", "created", "deleted",
            "connected", "bound", "listened", "modified", "accessed"
        ]
        
        for keyword in action_keywords:
            if keyword in output_lower:
                return keyword.rstrip('d')  # 去掉过去式后缀
        
        return "unknown_action"
    
    def _determine_action_type(self, rule_name: str, output_msg: str) -> ActionType:
        """确定动作类型"""
        text = f"{rule_name} {output_msg}".lower()
        
        for action_type, patterns in self.action_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text):
                    return action_type
        
        return ActionType.UNKNOWN
    
    def _extract_object(self, output_fields: Dict[str, Any], action_type: ActionType) -> str:
        """提取客体(操作的目标)"""
        # 根据动作类型选择合适的客体
        if action_type in [ActionType.FILE_ACCESS]:
            if 'fd.name' in output_fields:
                return output_fields['fd.name']
            elif 'fs.path.name' in output_fields:
                return output_fields['fs.path.name']
        
        elif action_type == ActionType.NETWORK_CONN:
            if 'fd.rip' in output_fields and 'fd.rport' in output_fields:
                return f"{output_fields['fd.rip']}:{output_fields['fd.rport']}"
            elif 'fd.lip' in output_fields and 'fd.lport' in output_fields:
                return f"{output_fields['fd.lip']}:{output_fields['fd.lport']}"
        
        elif action_type == ActionType.PROCESS_EXEC:
            if 'proc.cmdline' in output_fields:
                return output_fields['proc.cmdline']
            elif 'proc.exepath' in output_fields:
                return output_fields['proc.exepath']
        
        # 通用客体提取
        for field in ['fd.name', 'fs.path.name', 'proc.name', 'container.name']:
            if field in output_fields:
                return output_fields[field]
        
        return "unknown_object"
    
    def _determine_object_type(self, output_fields: Dict[str, Any], action_type: ActionType) -> str:
        """确定客体类型"""
        if action_type == ActionType.FILE_ACCESS:
            return "file"
        elif action_type == ActionType.NETWORK_CONN:
            return "network"
        elif action_type == ActionType.PROCESS_EXEC:
            return "process"
        elif action_type == ActionType.CONTAINER_OP:
            return "container"
        else:
            # 根据字段推断
            if any(field in output_fields for field in ['fd.name', 'fs.path.name']):
                return "file"
            elif any(field in output_fields for field in ['fd.rip', 'fd.lip']):
                return "network"
            elif 'proc.name' in output_fields:
                return "process"
            else:
                return "unknown"
    
    def _calculate_confidence(self, output_fields: Dict[str, Any], rule_name: str) -> float:
        """计算三元组提取的置信度"""
        confidence = 0.5  # 基础置信度
        
        # 根据可用字段数量调整置信度
        available_fields = len([f for f in output_fields.keys() if output_fields[f]])
        confidence += min(available_fields * 0.05, 0.3)
        
        # 根据规则名的明确性调整
        if any(keyword in rule_name.lower() for keyword in 
               ['write', 'read', 'exec', 'create', 'delete', 'connect']):
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def parse_event(self, raw_line: str) -> Optional[StandardizedEvent]:
        """解析单个Falco事件"""
        try:
            # 解析JSON
            event_data = json.loads(raw_line.strip())
            
            # 生成事件ID
            event_id = self.generate_event_id(event_data)
            
            # 防止重复处理
            if event_id in self.processed_events:
                return None
            self.processed_events.add(event_id)
            
            # 解析时间戳
            timestamp = self._parse_timestamp(event_data.get('time'))
            
            # 确定事件优先级
            rule_name = event_data.get('rule', '')
            priority = self.rule_priority_map.get(rule_name, EventPriority.MEDIUM)
            
            # 提取三元组
            triple = self.extract_triple(event_data)
            
            # 提取各类信息
            output_fields = event_data.get('output_fields', {})
            
            # 构建标准化事件
            standardized_event = StandardizedEvent(
                event_id=event_id,
                timestamp=timestamp,
                priority=priority,
                rule_name=rule_name,
                message=event_data.get('output', ''),
                triple=triple,
                raw_data=event_data,
                host_info=self._extract_host_info(output_fields),
                process_info=self._extract_process_info(output_fields),
                file_info=self._extract_file_info(output_fields),
                network_info=self._extract_network_info(output_fields),
                container_info=self._extract_container_info(output_fields),
                user_info=self._extract_user_info(output_fields),
                tags=self._generate_tags(rule_name, triple)
            )
            
            logger.debug(f"Parsed event {event_id}: {rule_name}")
            return standardized_event
            
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON line: {e}")
            return None
        except Exception as e:
            logger.error(f"Error parsing event: {e}")
            return None
    
    def parse_log_entry(self, event_data: Dict[str, Any]) -> Optional[StandardizedEvent]:
        """解析Falco日志条目（字典格式）"""
        try:
            # 生成事件ID
            event_id = self.generate_event_id(event_data)
            
            # 防止重复处理
            if event_id in self.processed_events:
                return None
            self.processed_events.add(event_id)
            
            # 解析时间戳
            timestamp = self._parse_timestamp(event_data.get('time'))
            
            # 确定事件优先级
            rule_name = event_data.get('rule', '')
            priority_str = event_data.get('priority', 'Medium')
            
            # 映射优先级字符串到枚举
            priority_map = {
                'Emergency': EventPriority.CRITICAL,
                'Alert': EventPriority.CRITICAL,
                'Critical': EventPriority.CRITICAL,
                'Error': EventPriority.HIGH,
                'Warning': EventPriority.HIGH,
                'Notice': EventPriority.MEDIUM,
                'Informational': EventPriority.LOW,
                'Debug': EventPriority.DEBUG,
                'High': EventPriority.HIGH,
                'Medium': EventPriority.MEDIUM,
                'Low': EventPriority.LOW
            }
            
            priority = priority_map.get(priority_str, EventPriority.MEDIUM)
            
            # 提取三元组
            triple = self.extract_triple(event_data)
            
            # 提取各类信息
            output_fields = event_data.get('output_fields', {})
            
            # 构建标准化事件
            standardized_event = StandardizedEvent(
                event_id=event_id,
                timestamp=timestamp,
                priority=priority,
                rule_name=rule_name,
                message=event_data.get('output', ''),
                triple=triple,
                raw_data=event_data,
                host_info=self._extract_host_info(output_fields),
                process_info=self._extract_process_info(output_fields),
                file_info=self._extract_file_info(output_fields),
                network_info=self._extract_network_info(output_fields),
                container_info=self._extract_container_info(output_fields),
                user_info=self._extract_user_info(output_fields),
                tags=self._generate_tags(rule_name, triple)
            )
            
            logger.debug(f"Parsed log entry {event_id}: {rule_name}")
            return standardized_event
            
        except Exception as e:
            logger.error(f"Error parsing log entry: {e}")
            return None
    
    def _parse_timestamp(self, time_str: str) -> datetime:
        """解析时间戳"""
        try:
            # Falco时间格式: 2025-01-14T10:30:45.123456789Z
            if time_str.endswith('Z'):
                time_str = time_str[:-1] + '+00:00'
            
            # 处理纳秒精度
            if '.' in time_str:
                main_part, frac_part = time_str.split('.')
                if '+' in frac_part:
                    frac, tz = frac_part.split('+')
                    frac = frac[:6]  # 只保留微秒精度
                    time_str = f"{main_part}.{frac}+{tz}"
            
            return datetime.fromisoformat(time_str)
        except Exception:
            logger.warning(f"Failed to parse timestamp: {time_str}")
            return datetime.now(timezone.utc)
    
    def _extract_host_info(self, output_fields: Dict[str, Any]) -> Dict[str, str]:
        """提取主机信息"""
        return {
            'hostname': output_fields.get('proc.aname[1]', 'unknown'),
            'kernel_version': output_fields.get('ka.version', ''),
        }
    
    def _extract_process_info(self, output_fields: Dict[str, Any]) -> Dict[str, Any]:
        """提取进程信息"""
        return {
            'pid': output_fields.get('proc.pid'),
            'ppid': output_fields.get('proc.ppid'),
            'name': output_fields.get('proc.name'),
            'cmdline': output_fields.get('proc.cmdline'),
            'exe_path': output_fields.get('proc.exepath'),
            'cwd': output_fields.get('proc.cwd'),
            'tty': output_fields.get('proc.tty'),
            'sid': output_fields.get('proc.sid'),
            'vpid': output_fields.get('proc.vpid'),
        }
    
    def _extract_file_info(self, output_fields: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """提取文件信息"""
        file_fields = ['fd.name', 'fs.path.name', 'fd.directory', 'fd.filename']
        if not any(field in output_fields for field in file_fields):
            return None
        
        return {
            'path': output_fields.get('fd.name') or output_fields.get('fs.path.name'),
            'directory': output_fields.get('fd.directory'),
            'filename': output_fields.get('fd.filename'),
            'type': output_fields.get('fd.type'),
            'typechar': output_fields.get('fd.typechar'),
        }
    
    def _extract_network_info(self, output_fields: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """提取网络信息"""
        network_fields = ['fd.rip', 'fd.lip', 'fd.rport', 'fd.lport']
        if not any(field in output_fields for field in network_fields):
            return None
        
        return {
            'remote_ip': output_fields.get('fd.rip'),
            'local_ip': output_fields.get('fd.lip'),
            'remote_port': str(output_fields.get('fd.rport', '')),
            'local_port': str(output_fields.get('fd.lport', '')),
            'protocol': output_fields.get('fd.l4proto'),
        }
    
    def _extract_container_info(self, output_fields: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """提取容器信息"""
        container_fields = ['container.id', 'container.name', 'container.image']
        if not any(field in output_fields for field in container_fields):
            return None
        
        return {
            'id': output_fields.get('container.id'),
            'name': output_fields.get('container.name'),
            'image': output_fields.get('container.image.repository'),
            'image_tag': output_fields.get('container.image.tag'),
        }
    
    def _extract_user_info(self, output_fields: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """提取用户信息"""
        user_fields = ['user.uid', 'user.name', 'user.gid']
        if not any(field in output_fields for field in user_fields):
            return None
        
        return {
            'uid': str(output_fields.get('user.uid', '')),
            'name': output_fields.get('user.name'),
            'gid': str(output_fields.get('user.gid', '')),
            'loginuid': str(output_fields.get('user.loginuid', '')),
        }
    
    def _generate_tags(self, rule_name: str, triple: TripleExtraction) -> List[str]:
        """生成事件标签"""
        tags = []
        
        # 基于规则名的标签
        if "container" in rule_name.lower():
            tags.append("container")
        if "network" in rule_name.lower():
            tags.append("network")
        if "file" in rule_name.lower():
            tags.append("file")
        if "process" in rule_name.lower():
            tags.append("process")
        
        # 基于动作类型的标签
        tags.append(triple.action_type.value)
        
        # 基于主体类型的标签
        tags.append(f"subject_{triple.subject_type}")
        
        # 基于客体类型的标签
        tags.append(f"object_{triple.object_type}")
        
        return list(set(tags))  # 去重
    
    async def process_existing_logs(self) -> List[StandardizedEvent]:
        """处理现有的日志文件"""
        events = []
        
        if not self.log_file_path.exists():
            logger.warning(f"Log file does not exist: {self.log_file_path}")
            return events
        
        try:
            async with aiofiles.open(self.log_file_path, 'r', encoding='utf-8') as f:
                async for line in f:
                    if line.strip():
                        event = self.parse_event(line)
                        if event:
                            events.append(event)
                            if self.callback:
                                await self.callback(event)
            
            logger.info(f"Processed {len(events)} existing events from {self.log_file_path}")
            
        except Exception as e:
            logger.error(f"Error processing existing logs: {e}")
        
        return events
    
    def start_monitoring(self):
        """开始实时监控日志文件"""
        if not self.log_file_path.exists():
            logger.warning(f"Log file does not exist: {self.log_file_path}")
            return
        
        # 记录当前文件位置
        self.file_position = self.log_file_path.stat().st_size
        
        # 创建文件监控器
        event_handler = FalcoLogFileHandler(self)
        self.observer = Observer()
        self.observer.schedule(event_handler, str(self.log_file_path.parent), recursive=False)
        self.observer.start()
        
        logger.info(f"Started monitoring {self.log_file_path}")
    
    def stop_monitoring(self):
        """停止监控"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logger.info("Stopped log monitoring")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取解析统计信息"""
        return {
            'processed_events_count': len(self.processed_events),
            'log_file_path': str(self.log_file_path),
            'file_exists': self.log_file_path.exists(),
            'file_size': self.log_file_path.stat().st_size if self.log_file_path.exists() else 0,
            'current_position': self.file_position,
        }


class FalcoLogFileHandler(FileSystemEventHandler):
    """Falco日志文件变化处理器"""
    
    def __init__(self, parser: FalcoLogParser):
        self.parser = parser
        super().__init__()
    
    def on_modified(self, event):
        """文件修改事件处理"""
        if event.is_directory:
            return
        
        if Path(event.src_path) == self.parser.log_file_path:
            self._process_new_lines()
    
    def _process_new_lines(self):
        """处理新增的日志行"""
        try:
            with open(self.parser.log_file_path, 'r', encoding='utf-8') as f:
                f.seek(self.parser.file_position)
                
                for line in f:
                    if line.strip():
                        event = self.parser.parse_event(line)
                        if event and self.parser.callback:
                            # 异步调用回调函数
                            import asyncio
                            try:
                                loop = asyncio.get_event_loop()
                                if loop.is_running():
                                    loop.create_task(self.parser.callback(event))
                                else:
                                    asyncio.run(self.parser.callback(event))
                            except Exception as e:
                                logger.error(f"Error in callback: {e}")
                
                self.parser.file_position = f.tell()
                
        except Exception as e:
            logger.error(f"Error processing new log lines: {e}")


# 工具函数
def create_parser(log_file_path: str, callback=None) -> FalcoLogParser:
    """创建Falco日志解析器实例"""
    return FalcoLogParser(log_file_path, callback)


def event_to_dict(event: StandardizedEvent) -> Dict[str, Any]:
    """将标准化事件转换为字典"""
    result = asdict(event)
    # 处理特殊字段
    result['timestamp'] = event.timestamp.isoformat()
    result['priority'] = event.priority.value
    result['triple']['action_type'] = event.triple.action_type.value
    return result


if __name__ == "__main__":
    # 测试代码
    import asyncio
    
    async def test_callback(event: StandardizedEvent):
        print(f"Event: {event.rule_name} - {event.triple.subject} {event.triple.action} {event.triple.object}")
    
    async def main():
        parser = create_parser("/home/xzj/01_Project/B_25OS/logs/falco_events.log", test_callback)
        
        # 处理现有日志
        events = await parser.process_existing_logs()
        print(f"Processed {len(events)} events")
        
        # 开始实时监控
        parser.start_monitoring()
        
        try:
            # 保持运行
            await asyncio.sleep(60)
        finally:
            parser.stop_monitoring()
    
    asyncio.run(main())