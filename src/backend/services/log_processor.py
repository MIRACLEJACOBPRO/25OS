#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS Log Processing Service
Falco日志处理服务
"""

import json
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from loguru import logger
import aiofiles

from core.config import settings
from services.graph_builder import GraphBuilder
from services.log_volume_controller import LogVolumeController, LogVolumeConfig

class FalcoLogHandler(FileSystemEventHandler):
    """Falco日志文件监控处理器"""
    
    def __init__(self, processor: 'LogProcessor'):
        self.processor = processor
        self.last_position = 0
        self._setup_initial_position()
    
    def _setup_initial_position(self):
        """设置初始读取位置"""
        try:
            log_file = Path(settings.falco_log_path)
            if log_file.exists():
                self.last_position = log_file.stat().st_size
                logger.info(f"Starting from position {self.last_position} in {settings.falco_log_path}")
        except Exception as e:
            logger.error(f"Failed to setup initial position: {e}")
            self.last_position = 0
    
    def on_modified(self, event):
        """文件修改事件处理"""
        if not event.is_directory and event.src_path == settings.falco_log_path:
            # 使用线程安全的方式调用异步方法
            import threading
            import asyncio
            
            def run_async():
                try:
                    # 创建新的事件循环
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(self.processor.process_new_logs())
                    loop.close()
                except Exception as e:
                    logger.error(f"Error processing new logs: {e}")
            
            # 在新线程中运行异步方法
            thread = threading.Thread(target=run_async, daemon=True)
            thread.start()

class LogProcessor:
    """日志处理器主类"""
    
    def __init__(self, graph_builder: GraphBuilder):
        self.graph_builder = graph_builder
        self.observer = Observer()
        self.handler = FalcoLogHandler(self)
        self.is_running = False
        self.processed_events = set()  # 防止重复处理
        
        # 初始化日志量控制器
        if settings.log_volume_control_enabled:
            volume_config = LogVolumeConfig(
                max_file_size=settings.max_log_file_size,
                max_files=settings.max_log_files,
                enable_compression=settings.log_compression_enabled,
                compression_delay=settings.log_compression_delay,
                base_sampling_rate=settings.base_sampling_rate,
                max_events_per_second=settings.max_events_per_second,
                sampling_window=settings.sampling_window,
                archive_directory=settings.log_archive_directory
            )
            self.volume_controller = LogVolumeController(volume_config)
        else:
            self.volume_controller = None
        
    async def start_monitoring(self):
        """开始监控日志文件"""
        try:
            log_path = Path(settings.falco_log_path)
            if not log_path.exists():
                logger.warning(f"Log file {settings.falco_log_path} does not exist, creating...")
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.touch()
            
            # 启动日志量控制器
            if self.volume_controller:
                await self.volume_controller.start()
                logger.info("Log volume controller started")
            
            # 设置文件监控
            self.observer.schedule(
                self.handler,
                path=str(log_path.parent),
                recursive=False
            )
            
            self.observer.start()
            self.is_running = True
            logger.info(f"Started monitoring {settings.falco_log_path}")
            
            # 处理现有日志
            await self.process_existing_logs()
            
        except Exception as e:
            logger.error(f"Failed to start log monitoring: {e}")
            raise
    
    async def stop_monitoring(self):
        """停止监控"""
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
        
        # 停止日志量控制器
        if self.volume_controller:
            await self.volume_controller.stop()
            logger.info("Log volume controller stopped")
        
        self.is_running = False
        logger.info("Log monitoring stopped")
    
    async def process_existing_logs(self):
        """处理现有的日志文件"""
        try:
            log_file = Path(settings.falco_log_path)
            if not log_file.exists():
                return
            
            async with aiofiles.open(log_file, 'r', encoding='utf-8') as f:
                await f.seek(self.handler.last_position)
                
                batch = []
                async for line in f:
                    line = line.strip()
                    if line:
                        event = await self.parse_log_line(line)
                        if event:
                            batch.append(event)
                            
                            # 批量处理
                            if len(batch) >= settings.batch_size:
                                await self.process_event_batch(batch)
                                batch = []
                
                # 处理剩余事件
                if batch:
                    await self.process_event_batch(batch)
                
                # 更新位置
                self.handler.last_position = await f.tell()
                
        except Exception as e:
            logger.error(f"Failed to process existing logs: {e}")
    
    async def process_new_logs(self):
        """处理新增的日志"""
        await self.process_existing_logs()
    
    async def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """解析单行日志"""
        try:
            # Falco输出JSON格式的日志
            event_data = json.loads(line)
            
            # 基础事件信息提取
            event = {
                'id': self._generate_event_id(event_data),
                'timestamp': self._parse_timestamp(event_data.get('time')),
                'rule': event_data.get('rule', 'Unknown'),
                'priority': event_data.get('priority', 'Notice'),
                'message': event_data.get('output', ''),
                'source': 'falco',
                'raw_data': event_data
            }
            
            # 提取详细字段
            output_fields = event_data.get('output_fields', {})
            
            # 检查是否为网络连接事件
            is_network_event = any(output_fields.get(k) for k in ['fd.sip', 'fd.cip', 'fd.rip', 'fd.rport'])
            
            # 提取网络连接信息
            network_connection = None
            if is_network_event:
                # 对于网络事件，fd.name 可能包含连接信息而不是文件路径
                fd_name = output_fields.get('fd.name', '')
                network_connection = {
                    'src_ip': output_fields.get('fd.sip') or output_fields.get('fd.lip'),
                    'dst_ip': output_fields.get('fd.cip') or output_fields.get('fd.rip'),
                    'src_port': output_fields.get('fd.sport') or output_fields.get('fd.lport'),
                    'dst_port': output_fields.get('fd.cport') or output_fields.get('fd.rport'),
                    'protocol': output_fields.get('fd.l4proto'),
                    'connection_info': fd_name  # 保存原始连接信息
                }
            
            # 确定文件路径（只有在非网络事件时才使用 fd.name）
            file_path = None
            if not is_network_event:
                fd_name = output_fields.get('fd.name')
                # 进一步验证是否为真实文件路径
                if fd_name and not self._looks_like_network_connection(fd_name):
                    file_path = fd_name
            
            event.update({
                'process_name': output_fields.get('proc.name'),
                'process_pid': output_fields.get('proc.pid'),
                'process_ppid': output_fields.get('proc.ppid'),
                'user_name': output_fields.get('user.name'),
                'user_uid': output_fields.get('user.uid'),
                'file_path': file_path,
                'file_type': output_fields.get('fd.type'),
                'container_id': output_fields.get('container.id'),
                'container_name': output_fields.get('container.name'),
                'command_line': output_fields.get('proc.cmdline'),
                'parent_process': output_fields.get('proc.pname'),
                'syscall': output_fields.get('evt.type'),
                'network_connection': network_connection
            })
            
            # 检查是否已处理过
            if event['id'] in self.processed_events:
                return None
            
            # 日志量控制采样
            if self.volume_controller:
                if not self.volume_controller.should_sample_event(event):
                    return None
            
            self.processed_events.add(event['id'])
            
            # 限制已处理事件集合大小
            if len(self.processed_events) > 10000:
                # 移除最旧的一半
                old_events = list(self.processed_events)[:5000]
                for old_id in old_events:
                    self.processed_events.discard(old_id)
            
            return event
            
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse JSON log line: {line[:100]}...")
            return None
        except Exception as e:
            logger.error(f"Error parsing log line: {e}")
            return None
    
    def _generate_event_id(self, event_data: Dict[str, Any]) -> str:
        """生成事件唯一ID"""
        # 使用时间戳、规则和输出字段的哈希来生成唯一ID
        import hashlib
        
        key_fields = [
            event_data.get('time', ''),
            event_data.get('rule', ''),
            event_data.get('output', ''),
            str(event_data.get('output_fields', {}).get('proc.pid', '')),
            str(event_data.get('output_fields', {}).get('user.uid', ''))
        ]
        
        content = '|'.join(str(field) for field in key_fields)
        return hashlib.md5(content.encode()).hexdigest()
    
    def _looks_like_network_connection(self, fd_name: str) -> bool:
        """检查字符串是否看起来像网络连接信息"""
        if not fd_name:
            return False
        
        import re
        
        # 检查是否包含 IP:端口 格式
        ip_port_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+'
        if re.search(ip_port_pattern, fd_name):
            return True
        
        # 检查是否包含域名:端口格式
        domain_port_pattern = r'[a-zA-Z0-9.-]+:\d+'
        if re.search(domain_port_pattern, fd_name) and not fd_name.startswith('/'):
            return True
        
        # 检查是否包含网络协议标识
        network_indicators = ['tcp:', 'udp:', 'http:', 'https:', 'ftp:']
        if any(indicator in fd_name.lower() for indicator in network_indicators):
            return True
        
        return False
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> datetime:
        """解析时间戳"""
        if not timestamp_str:
            return datetime.utcnow()
        
        try:
            # Falco时间戳格式: 2024-01-01T12:00:00.000000000Z
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            
            # 处理纳秒精度
            if '.' in timestamp_str and len(timestamp_str.split('.')[1].split('+')[0]) > 6:
                parts = timestamp_str.split('.')
                microseconds = parts[1][:6]
                timezone = parts[1][9:] if len(parts[1]) > 9 else '+00:00'
                timestamp_str = f"{parts[0]}.{microseconds}{timezone}"
            
            return datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.warning(f"Failed to parse timestamp {timestamp_str}: {e}")
            return datetime.utcnow()
    
    async def process_event_batch(self, events: List[Dict[str, Any]]):
        """批量处理事件"""
        try:
            logger.info(f"Processing batch of {len(events)} events")
            
            # 构建知识图谱
            await self.graph_builder.build_graph_from_events(events)
            
            # 记录处理统计
            for event in events:
                logger.debug(f"Processed event: {event['rule']} - {event['message'][:100]}...")
            
        except Exception as e:
            logger.error(f"Failed to process event batch: {e}")
    
    async def get_processing_stats(self) -> Dict[str, Any]:
        """获取处理统计信息"""
        stats = {
            'is_running': self.is_running,
            'processed_events_count': len(self.processed_events),
            'last_position': self.handler.last_position,
            'log_file_exists': Path(settings.falco_log_path).exists(),
            'log_file_size': Path(settings.falco_log_path).stat().st_size if Path(settings.falco_log_path).exists() else 0
        }
        
        # 添加日志量控制统计
        if self.volume_controller:
            volume_stats = self.volume_controller.get_stats()
            stats['volume_control'] = volume_stats
        
        return stats
    
    async def manual_process_file(self, file_path: str) -> int:
        """手动处理指定日志文件"""
        try:
            processed_count = 0
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                batch = []
                async for line in f:
                    line = line.strip()
                    if line:
                        event = await self.parse_log_line(line)
                        if event:
                            batch.append(event)
                            processed_count += 1
                            
                            if len(batch) >= settings.batch_size:
                                await self.process_event_batch(batch)
                                batch = []
                
                if batch:
                    await self.process_event_batch(batch)
            
            logger.info(f"Manually processed {processed_count} events from {file_path}")
            return processed_count
            
        except Exception as e:
            logger.error(f"Failed to manually process file {file_path}: {e}")
            raise