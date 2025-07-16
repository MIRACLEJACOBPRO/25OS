#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS 命令执行器模块

负责安全地执行AI决策代理生成的命令:
1. 命令验证和权限检查
2. 安全执行环境
3. 执行状态监控
4. 结果收集和报告
5. 错误处理和恢复

安全特性:
- 命令白名单验证
- 参数安全检查
- 执行超时控制
- 权限最小化原则
- 执行日志记录
"""

import asyncio
import subprocess
import time
import json
import os
import signal
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import shlex
import tempfile

from loguru import logger


class ExecutionStatus(Enum):
    """执行状态枚举"""
    PENDING = "pending"        # 等待执行
    RUNNING = "running"        # 正在执行
    SUCCESS = "success"        # 执行成功
    FAILED = "failed"          # 执行失败
    TIMEOUT = "timeout"        # 执行超时
    CANCELLED = "cancelled"    # 执行取消
    SKIPPED = "skipped"        # 跳过执行


class CommandType(Enum):
    """命令类型枚举"""
    SYSTEM = "system"          # 系统命令
    DOCKER = "docker"          # Docker命令
    NETWORK = "network"        # 网络命令
    FILE = "file"              # 文件操作
    SERVICE = "service"        # 服务管理
    SECURITY = "security"      # 安全操作
    CUSTOM = "custom"          # 自定义命令


@dataclass
class ExecutionResult:
    """执行结果数据结构"""
    command_id: str
    command: Dict[str, Any]
    status: ExecutionStatus
    return_code: Optional[int]
    stdout: str
    stderr: str
    execution_time: float
    start_time: datetime
    end_time: Optional[datetime]
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = asdict(self)
        result['status'] = self.status.value
        result['start_time'] = self.start_time.isoformat()
        result['end_time'] = self.end_time.isoformat() if self.end_time else None
        return result


class CommandValidator:
    """命令验证器"""
    
    def __init__(self):
        # 允许的命令白名单
        self.allowed_commands = {
            'kill_process': {
                'command': 'kill',
                'args_pattern': r'^-\d+\s+\d+$',
                'description': 'Kill a process by PID'
            },
            'restart_service': {
                'command': 'systemctl',
                'args_pattern': r'^restart\s+[a-zA-Z0-9_-]+$',
                'description': 'Restart a system service'
            },
            'block_ip': {
                'command': 'iptables',
                'args_pattern': r'^-A\s+INPUT\s+-s\s+[0-9.]+\s+-j\s+DROP$',
                'description': 'Block an IP address'
            },
            'isolate_container': {
                'command': 'docker',
                'args_pattern': r'^network\s+disconnect\s+\w+\s+\w+$',
                'description': 'Isolate a Docker container'
            },
            'backup_file': {
                'command': 'cp',
                'args_pattern': r'^[\w/.-]+\s+[\w/.-]+\.backup$',
                'description': 'Backup a file'
            },
            'scan_file': {
                'command': 'clamscan',
                'args_pattern': r'^[\w/.-]+$',
                'description': 'Scan a file for malware'
            },
            'update_firewall': {
                'command': 'ufw',
                'args_pattern': r'^(allow|deny)\s+\w+$',
                'description': 'Update firewall rules'
            },
            'check_system_status': {
                'command': 'systemctl',
                'args_pattern': r'^status\s+[a-zA-Z0-9_-]+$',
                'description': 'Check system service status'
            }
        }
        
        # 危险命令黑名单
        self.dangerous_commands = {
            'rm', 'rmdir', 'dd', 'mkfs', 'fdisk', 'parted',
            'shutdown', 'reboot', 'halt', 'poweroff',
            'passwd', 'chpasswd', 'usermod', 'userdel',
            'chmod', 'chown', 'chgrp', 'mount', 'umount'
        }
        
        # 危险参数模式
        self.dangerous_patterns = [
            r'rm\s+-rf\s+/',
            r'dd\s+.*of=/dev/',
            r'mkfs\s+/dev/',
            r'\|\s*sh',
            r'\|\s*bash',
            r'&&\s*rm',
            r';\s*rm',
            r'`.*`',
            r'\$\(.*\)'
        ]
    
    def validate_command(self, command: Dict[str, Any]) -> tuple[bool, str]:
        """验证命令是否安全"""
        try:
            action = command.get('action', '')
            
            # 检查是否在白名单中
            if action not in self.allowed_commands:
                return False, f"Command '{action}' not in whitelist"
            
            # 获取实际命令
            cmd_info = self.allowed_commands[action]
            actual_command = cmd_info['command']
            
            # 检查是否在黑名单中
            if actual_command in self.dangerous_commands:
                return False, f"Command '{actual_command}' is in dangerous commands list"
            
            # 验证参数格式
            args = command.get('args', '')
            import re
            if not re.match(cmd_info['args_pattern'], args):
                return False, f"Command arguments don't match expected pattern"
            
            # 检查危险模式
            full_command = f"{actual_command} {args}"
            for pattern in self.dangerous_patterns:
                if re.search(pattern, full_command):
                    return False, f"Command contains dangerous pattern: {pattern}"
            
            return True, "Command validation passed"
            
        except Exception as e:
            return False, f"Validation error: {e}"


class CommandExecutor:
    """命令执行器类"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化命令执行器"""
        self.config = config or {
            'max_execution_time': 300,  # 5分钟
            'max_concurrent_executions': 3,
            'enable_dry_run': True,
            'log_commands': True,
            'working_directory': '/tmp/neuronos_executor'
        }
        
        self.validator = CommandValidator()
        self.running_processes = {}
        self.execution_count = 0
        
        # 创建工作目录
        self.working_dir = Path(self.config['working_directory'])
        self.working_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Command Executor initialized")
    
    def _generate_command_id(self) -> str:
        """生成命令ID"""
        self.execution_count += 1
        timestamp = int(time.time() * 1000)
        return f"cmd_{self.execution_count}_{timestamp}"
    
    def _build_system_command(self, command: Dict[str, Any]) -> List[str]:
        """构建系统命令"""
        action = command['action']
        args = command.get('args', '')
        
        # 从白名单获取实际命令
        cmd_info = self.validator.allowed_commands.get(action)
        if not cmd_info:
            raise ValueError(f"Unknown command action: {action}")
        
        base_command = cmd_info['command']
        
        # 构建完整命令
        if args:
            full_command = f"{base_command} {args}"
        else:
            full_command = base_command
        
        # 使用shlex安全解析命令
        return shlex.split(full_command)
    
    async def _execute_system_command(self, 
                                     command_parts: List[str], 
                                     timeout: int,
                                     working_dir: Optional[str] = None) -> tuple[int, str, str]:
        """执行系统命令"""
        try:
            # 设置环境变量
            env = os.environ.copy()
            env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
            
            # 创建进程
            process = await asyncio.create_subprocess_exec(
                *command_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=working_dir or str(self.working_dir)
            )
            
            # 等待执行完成或超时
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=timeout
                )
                return_code = process.returncode
                
            except asyncio.TimeoutError:
                # 超时处理
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                
                raise asyncio.TimeoutError("Command execution timeout")
            
            return return_code, stdout.decode('utf-8'), stderr.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to execute command {command_parts}: {e}")
            raise
    
    async def execute_command(self, command: Dict[str, Any]) -> ExecutionResult:
        """执行单个命令"""
        command_id = self._generate_command_id()
        start_time = datetime.now()
        
        logger.info(f"Executing command {command_id}: {command.get('action', 'unknown')}")
        
        # 验证命令
        is_valid, validation_message = self.validator.validate_command(command)
        if not is_valid:
            logger.error(f"Command validation failed: {validation_message}")
            return ExecutionResult(
                command_id=command_id,
                command=command,
                status=ExecutionStatus.FAILED,
                return_code=None,
                stdout="",
                stderr=validation_message,
                execution_time=0.0,
                start_time=start_time,
                end_time=datetime.now(),
                error_message=validation_message
            )
        
        # 检查是否为干运行模式
        if command.get('dry_run', False) or self.config.get('enable_dry_run', False):
            logger.info(f"Dry run mode: {command}")
            return ExecutionResult(
                command_id=command_id,
                command=command,
                status=ExecutionStatus.SUCCESS,
                return_code=0,
                stdout=f"DRY RUN: Would execute {command['action']}",
                stderr="",
                execution_time=0.1,
                start_time=start_time,
                end_time=datetime.now(),
                metadata={'dry_run': True}
            )
        
        try:
            # 构建命令
            command_parts = self._build_system_command(command)
            
            # 获取超时设置
            timeout = command.get('timeout', self.config['max_execution_time'])
            
            # 执行命令
            execution_start = time.time()
            return_code, stdout, stderr = await self._execute_system_command(
                command_parts, timeout, command.get('working_dir')
            )
            execution_time = time.time() - execution_start
            
            # 确定执行状态
            if return_code == 0:
                status = ExecutionStatus.SUCCESS
                error_message = None
            else:
                status = ExecutionStatus.FAILED
                error_message = f"Command failed with return code {return_code}"
            
            result = ExecutionResult(
                command_id=command_id,
                command=command,
                status=status,
                return_code=return_code,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                start_time=start_time,
                end_time=datetime.now(),
                error_message=error_message
            )
            
            logger.info(
                f"Command {command_id} completed: {status.value}, "
                f"return_code={return_code}, time={execution_time:.2f}s"
            )
            
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"Command {command_id} timed out")
            return ExecutionResult(
                command_id=command_id,
                command=command,
                status=ExecutionStatus.TIMEOUT,
                return_code=None,
                stdout="",
                stderr="Command execution timeout",
                execution_time=timeout,
                start_time=start_time,
                end_time=datetime.now(),
                error_message="Execution timeout"
            )
            
        except Exception as e:
            logger.error(f"Command {command_id} execution error: {e}")
            return ExecutionResult(
                command_id=command_id,
                command=command,
                status=ExecutionStatus.FAILED,
                return_code=None,
                stdout="",
                stderr=str(e),
                execution_time=time.time() - execution_start if 'execution_start' in locals() else 0.0,
                start_time=start_time,
                end_time=datetime.now(),
                error_message=str(e)
            )
    
    async def execute_batch(self, commands: List[Dict[str, Any]]) -> List[ExecutionResult]:
        """批量执行命令"""
        logger.info(f"Executing batch of {len(commands)} commands")
        
        # 检查并发限制
        max_concurrent = self.config['max_concurrent_executions']
        
        results = []
        
        # 分批执行
        for i in range(0, len(commands), max_concurrent):
            batch = commands[i:i + max_concurrent]
            
            # 并发执行当前批次
            batch_tasks = [self.execute_command(cmd) for cmd in batch]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            # 处理结果
            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    # 处理异常
                    error_result = ExecutionResult(
                        command_id=f"error_{i+j}",
                        command=batch[j],
                        status=ExecutionStatus.FAILED,
                        return_code=None,
                        stdout="",
                        stderr=str(result),
                        execution_time=0.0,
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                        error_message=str(result)
                    )
                    results.append(error_result)
                else:
                    results.append(result)
        
        logger.info(f"Batch execution completed: {len(results)} results")
        return results
    
    def get_running_processes(self) -> Dict[str, Any]:
        """获取正在运行的进程信息"""
        return dict(self.running_processes)
    
    def cancel_command(self, command_id: str) -> bool:
        """取消正在执行的命令"""
        if command_id in self.running_processes:
            try:
                process = self.running_processes[command_id]
                process.terminate()
                del self.running_processes[command_id]
                logger.info(f"Command {command_id} cancelled")
                return True
            except Exception as e:
                logger.error(f"Failed to cancel command {command_id}: {e}")
                return False
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取执行统计信息"""
        return {
            'total_executions': self.execution_count,
            'running_processes': len(self.running_processes),
            'max_concurrent': self.config['max_concurrent_executions'],
            'working_directory': str(self.working_dir)
        }


# 创建全局命令执行器实例
command_executor = CommandExecutor()


# 便捷函数
async def execute_single_command(action: str, 
                                args: str = "", 
                                timeout: int = 300,
                                dry_run: bool = False) -> ExecutionResult:
    """执行单个命令的便捷函数"""
    command = {
        'action': action,
        'args': args,
        'timeout': timeout,
        'dry_run': dry_run
    }
    
    return await command_executor.execute_command(command)


async def execute_commands_sequence(commands: List[Dict[str, Any]]) -> List[ExecutionResult]:
    """顺序执行命令列表"""
    results = []
    
    for command in commands:
        result = await command_executor.execute_command(command)
        results.append(result)
        
        # 如果命令失败且不允许继续，停止执行
        if result.status == ExecutionStatus.FAILED and not command.get('continue_on_failure', False):
            logger.warning("Command failed, stopping sequence execution")
            break
    
    return results