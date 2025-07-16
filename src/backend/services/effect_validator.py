#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS 效果验证器模块

负责验证命令执行后的效果:
1. 执行结果验证
2. 系统状态检查
3. 安全效果评估
4. 副作用检测
5. 回滚条件判断

验证类型:
- 进程状态验证
- 网络连接验证
- 文件系统验证
- 服务状态验证
- 安全策略验证
"""

import asyncio
import subprocess
import time
import json
import psutil
import socket
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from loguru import logger
from .command_executor import ExecutionResult, ExecutionStatus


class ValidationType(Enum):
    """验证类型枚举"""
    PROCESS_STATUS = "process_status"
    NETWORK_STATUS = "network_status"
    FILE_STATUS = "file_status"
    SERVICE_STATUS = "service_status"
    SECURITY_POLICY = "security_policy"
    SYSTEM_RESOURCE = "system_resource"
    CUSTOM = "custom"


class ValidationResult(Enum):
    """验证结果枚举"""
    VALID = "valid"
    INVALID = "invalid"
    PARTIAL = "partial"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class ValidationCheck:
    """验证检查数据结构"""
    check_id: str
    validation_type: ValidationType
    description: str
    expected_result: Any
    actual_result: Any
    result: ValidationResult
    confidence: float
    message: str
    timestamp: datetime
    execution_time: float
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'check_id': self.check_id,
            'validation_type': self.validation_type.value,
            'description': self.description,
            'expected_result': self.expected_result,
            'actual_result': self.actual_result,
            'result': self.result.value,
            'confidence': self.confidence,
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'execution_time': self.execution_time
        }


@dataclass
class EffectValidationResult:
    """效果验证结果数据结构"""
    validation_id: str
    command_info: Dict[str, Any]
    execution_result: ExecutionResult
    checks: List[ValidationCheck]
    is_valid: bool
    overall_confidence: float
    summary: str
    recommendations: List[str]
    requires_rollback: bool
    timestamp: datetime
    total_validation_time: float
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'validation_id': self.validation_id,
            'command_info': self.command_info,
            'execution_result': self.execution_result.to_dict(),
            'checks': [check.to_dict() for check in self.checks],
            'is_valid': self.is_valid,
            'overall_confidence': self.overall_confidence,
            'summary': self.summary,
            'recommendations': self.recommendations,
            'requires_rollback': self.requires_rollback,
            'timestamp': self.timestamp.isoformat(),
            'total_validation_time': self.total_validation_time
        }


class EffectValidator:
    """效果验证器类"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化效果验证器"""
        self.config = config or {
            'validation_timeout': 30,
            'retry_attempts': 3,
            'retry_delay': 2,
            'confidence_threshold': 0.7,
            'enable_deep_validation': True
        }
        
        self.validation_count = 0
        self.validation_history = []
        
        # 验证器映射
        self.validators = {
            'kill_process': self._validate_process_termination,
            'restart_service': self._validate_service_restart,
            'block_ip': self._validate_ip_blocking,
            'isolate_container': self._validate_container_isolation,
            'backup_file': self._validate_file_backup,
            'scan_file': self._validate_file_scan,
            'update_firewall': self._validate_firewall_update,
            'check_system_status': self._validate_status_check
        }
        
        logger.info("Effect Validator initialized")
    
    def _generate_validation_id(self) -> str:
        """生成验证ID"""
        self.validation_count += 1
        timestamp = int(time.time() * 1000)
        return f"validation_{self.validation_count}_{timestamp}"
    
    async def validate_effect(self, 
                            command_info: Dict[str, Any], 
                            execution_result: ExecutionResult) -> EffectValidationResult:
        """验证命令执行效果"""
        validation_id = self._generate_validation_id()
        start_time = time.time()
        
        logger.info(f"Validating effect for command: {command_info.get('action', 'unknown')}")
        
        # 如果执行失败，直接返回无效结果
        if execution_result.status != ExecutionStatus.SUCCESS:
            return EffectValidationResult(
                validation_id=validation_id,
                command_info=command_info,
                execution_result=execution_result,
                checks=[],
                is_valid=False,
                overall_confidence=1.0,
                summary="Command execution failed, no validation performed",
                recommendations=["Check execution logs", "Verify command parameters"],
                requires_rollback=False,
                timestamp=datetime.now(),
                total_validation_time=time.time() - start_time
            )
        
        # 获取对应的验证器
        action = command_info.get('action', '')
        validator_func = self.validators.get(action)
        
        if not validator_func:
            logger.warning(f"No validator found for action: {action}")
            return self._create_unknown_validation_result(
                validation_id, command_info, execution_result, start_time
            )
        
        try:
            # 执行验证
            checks = await validator_func(command_info, execution_result)
            
            # 分析验证结果
            is_valid, overall_confidence, summary, recommendations, requires_rollback = \
                self._analyze_validation_results(checks)
            
            result = EffectValidationResult(
                validation_id=validation_id,
                command_info=command_info,
                execution_result=execution_result,
                checks=checks,
                is_valid=is_valid,
                overall_confidence=overall_confidence,
                summary=summary,
                recommendations=recommendations,
                requires_rollback=requires_rollback,
                timestamp=datetime.now(),
                total_validation_time=time.time() - start_time
            )
            
            # 记录验证历史
            self.validation_history.append(result)
            
            logger.info(
                f"Validation completed: {validation_id}, Valid: {is_valid}, "
                f"Confidence: {overall_confidence:.2f}, Checks: {len(checks)}"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Validation error for {action}: {e}")
            return self._create_error_validation_result(
                validation_id, command_info, execution_result, str(e), start_time
            )
    
    def _create_unknown_validation_result(self, 
                                        validation_id: str,
                                        command_info: Dict[str, Any],
                                        execution_result: ExecutionResult,
                                        start_time: float) -> EffectValidationResult:
        """创建未知验证结果"""
        return EffectValidationResult(
            validation_id=validation_id,
            command_info=command_info,
            execution_result=execution_result,
            checks=[],
            is_valid=True,  # 假设成功，因为执行成功了
            overall_confidence=0.5,  # 低置信度
            summary="No specific validator available, assuming success based on execution result",
            recommendations=["Implement specific validator for this command type"],
            requires_rollback=False,
            timestamp=datetime.now(),
            total_validation_time=time.time() - start_time
        )
    
    def _create_error_validation_result(self, 
                                      validation_id: str,
                                      command_info: Dict[str, Any],
                                      execution_result: ExecutionResult,
                                      error_message: str,
                                      start_time: float) -> EffectValidationResult:
        """创建错误验证结果"""
        return EffectValidationResult(
            validation_id=validation_id,
            command_info=command_info,
            execution_result=execution_result,
            checks=[],
            is_valid=False,
            overall_confidence=0.0,
            summary=f"Validation error: {error_message}",
            recommendations=["Check system state", "Review validation logs"],
            requires_rollback=True,
            timestamp=datetime.now(),
            total_validation_time=time.time() - start_time
        )
    
    async def _validate_process_termination(self, 
                                          command_info: Dict[str, Any], 
                                          execution_result: ExecutionResult) -> List[ValidationCheck]:
        """验证进程终止效果"""
        checks = []
        
        try:
            pid = command_info['parameters'].get('pid')
            if not pid:
                return checks
            
            # 检查进程是否仍然存在
            check_start = time.time()
            process_exists = psutil.pid_exists(int(pid))
            
            check = ValidationCheck(
                check_id=f"process_exists_{pid}",
                validation_type=ValidationType.PROCESS_STATUS,
                description=f"Check if process {pid} is terminated",
                expected_result=False,
                actual_result=process_exists,
                result=ValidationResult.VALID if not process_exists else ValidationResult.INVALID,
                confidence=0.95,
                message=f"Process {pid} {'still exists' if process_exists else 'successfully terminated'}",
                timestamp=datetime.now(),
                execution_time=time.time() - check_start
            )
            checks.append(check)
            
            # 如果进程仍然存在，尝试获取更多信息
            if process_exists:
                try:
                    proc = psutil.Process(int(pid))
                    proc_info = {
                        'name': proc.name(),
                        'status': proc.status(),
                        'cpu_percent': proc.cpu_percent()
                    }
                    
                    info_check = ValidationCheck(
                        check_id=f"process_info_{pid}",
                        validation_type=ValidationType.PROCESS_STATUS,
                        description=f"Process {pid} information",
                        expected_result="terminated",
                        actual_result=proc_info,
                        result=ValidationResult.INVALID,
                        confidence=0.9,
                        message=f"Process {pid} is still running: {proc_info}",
                        timestamp=datetime.now(),
                        execution_time=0.1
                    )
                    checks.append(info_check)
                    
                except psutil.NoSuchProcess:
                    # 进程在检查期间被终止
                    pass
            
        except Exception as e:
            error_check = ValidationCheck(
                check_id="process_validation_error",
                validation_type=ValidationType.PROCESS_STATUS,
                description="Process termination validation error",
                expected_result="success",
                actual_result=str(e),
                result=ValidationResult.ERROR,
                confidence=0.0,
                message=f"Validation error: {e}",
                timestamp=datetime.now(),
                execution_time=0.0
            )
            checks.append(error_check)
        
        return checks
    
    async def _validate_service_restart(self, 
                                      command_info: Dict[str, Any], 
                                      execution_result: ExecutionResult) -> List[ValidationCheck]:
        """验证服务重启效果"""
        checks = []
        
        try:
            service_name = command_info['parameters'].get('service_name')
            if not service_name:
                return checks
            
            # 等待服务重启完成
            await asyncio.sleep(2)
            
            # 检查服务状态
            check_start = time.time()
            
            try:
                # 使用systemctl检查服务状态
                result = await asyncio.create_subprocess_exec(
                    'systemctl', 'is-active', service_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                
                service_status = stdout.decode().strip()
                is_active = service_status == 'active'
                
                status_check = ValidationCheck(
                    check_id=f"service_status_{service_name}",
                    validation_type=ValidationType.SERVICE_STATUS,
                    description=f"Check if service {service_name} is active",
                    expected_result="active",
                    actual_result=service_status,
                    result=ValidationResult.VALID if is_active else ValidationResult.INVALID,
                    confidence=0.9,
                    message=f"Service {service_name} status: {service_status}",
                    timestamp=datetime.now(),
                    execution_time=time.time() - check_start
                )
                checks.append(status_check)
                
            except Exception as e:
                error_check = ValidationCheck(
                    check_id=f"service_check_error_{service_name}",
                    validation_type=ValidationType.SERVICE_STATUS,
                    description=f"Service status check error for {service_name}",
                    expected_result="success",
                    actual_result=str(e),
                    result=ValidationResult.ERROR,
                    confidence=0.0,
                    message=f"Failed to check service status: {e}",
                    timestamp=datetime.now(),
                    execution_time=0.0
                )
                checks.append(error_check)
            
        except Exception as e:
            logger.error(f"Service restart validation error: {e}")
        
        return checks
    
    async def _validate_ip_blocking(self, 
                                  command_info: Dict[str, Any], 
                                  execution_result: ExecutionResult) -> List[ValidationCheck]:
        """验证IP阻断效果"""
        checks = []
        
        try:
            ip_address = command_info['parameters'].get('ip_address')
            if not ip_address:
                return checks
            
            # 检查iptables规则
            check_start = time.time()
            
            try:
                result = await asyncio.create_subprocess_exec(
                    'iptables', '-L', 'INPUT', '-n',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                
                iptables_output = stdout.decode()
                rule_exists = ip_address in iptables_output and 'DROP' in iptables_output
                
                rule_check = ValidationCheck(
                    check_id=f"iptables_rule_{ip_address}",
                    validation_type=ValidationType.SECURITY_POLICY,
                    description=f"Check if IP {ip_address} is blocked in iptables",
                    expected_result=True,
                    actual_result=rule_exists,
                    result=ValidationResult.VALID if rule_exists else ValidationResult.INVALID,
                    confidence=0.85,
                    message=f"IP {ip_address} blocking rule {'found' if rule_exists else 'not found'}",
                    timestamp=datetime.now(),
                    execution_time=time.time() - check_start
                )
                checks.append(rule_check)
                
            except Exception as e:
                error_check = ValidationCheck(
                    check_id=f"iptables_check_error_{ip_address}",
                    validation_type=ValidationType.SECURITY_POLICY,
                    description=f"Iptables rule check error for {ip_address}",
                    expected_result="success",
                    actual_result=str(e),
                    result=ValidationResult.ERROR,
                    confidence=0.0,
                    message=f"Failed to check iptables rules: {e}",
                    timestamp=datetime.now(),
                    execution_time=0.0
                )
                checks.append(error_check)
            
        except Exception as e:
            logger.error(f"IP blocking validation error: {e}")
        
        return checks
    
    async def _validate_container_isolation(self, 
                                          command_info: Dict[str, Any], 
                                          execution_result: ExecutionResult) -> List[ValidationCheck]:
        """验证容器隔离效果"""
        checks = []
        
        try:
            container_id = command_info['parameters'].get('container_id')
            network = command_info['parameters'].get('network', 'bridge')
            
            if not container_id:
                return checks
            
            # 检查容器网络连接
            check_start = time.time()
            
            try:
                result = await asyncio.create_subprocess_exec(
                    'docker', 'inspect', container_id,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                
                if result.returncode == 0:
                    container_info = json.loads(stdout.decode())
                    networks = container_info[0].get('NetworkSettings', {}).get('Networks', {})
                    
                    is_isolated = network not in networks or not networks.get(network, {}).get('IPAddress')
                    
                    isolation_check = ValidationCheck(
                        check_id=f"container_isolation_{container_id}",
                        validation_type=ValidationType.NETWORK_STATUS,
                        description=f"Check if container {container_id} is isolated from {network}",
                        expected_result=True,
                        actual_result=is_isolated,
                        result=ValidationResult.VALID if is_isolated else ValidationResult.INVALID,
                        confidence=0.9,
                        message=f"Container {container_id} {'is isolated' if is_isolated else 'still connected'}",
                        timestamp=datetime.now(),
                        execution_time=time.time() - check_start
                    )
                    checks.append(isolation_check)
                    
                else:
                    error_check = ValidationCheck(
                        check_id=f"container_inspect_error_{container_id}",
                        validation_type=ValidationType.NETWORK_STATUS,
                        description=f"Container inspect error for {container_id}",
                        expected_result="success",
                        actual_result=stderr.decode(),
                        result=ValidationResult.ERROR,
                        confidence=0.0,
                        message=f"Failed to inspect container: {stderr.decode()}",
                        timestamp=datetime.now(),
                        execution_time=time.time() - check_start
                    )
                    checks.append(error_check)
                
            except Exception as e:
                error_check = ValidationCheck(
                    check_id=f"container_validation_error_{container_id}",
                    validation_type=ValidationType.NETWORK_STATUS,
                    description=f"Container isolation validation error",
                    expected_result="success",
                    actual_result=str(e),
                    result=ValidationResult.ERROR,
                    confidence=0.0,
                    message=f"Validation error: {e}",
                    timestamp=datetime.now(),
                    execution_time=0.0
                )
                checks.append(error_check)
            
        except Exception as e:
            logger.error(f"Container isolation validation error: {e}")
        
        return checks
    
    async def _validate_file_backup(self, 
                                  command_info: Dict[str, Any], 
                                  execution_result: ExecutionResult) -> List[ValidationCheck]:
        """验证文件备份效果"""
        checks = []
        
        try:
            file_path = command_info['parameters'].get('file_path')
            if not file_path:
                return checks
            
            backup_path = f"{file_path}.backup"
            
            # 检查备份文件是否存在
            check_start = time.time()
            backup_exists = Path(backup_path).exists()
            
            existence_check = ValidationCheck(
                check_id=f"backup_exists_{file_path}",
                validation_type=ValidationType.FILE_STATUS,
                description=f"Check if backup file exists: {backup_path}",
                expected_result=True,
                actual_result=backup_exists,
                result=ValidationResult.VALID if backup_exists else ValidationResult.INVALID,
                confidence=0.95,
                message=f"Backup file {'exists' if backup_exists else 'not found'}: {backup_path}",
                timestamp=datetime.now(),
                execution_time=time.time() - check_start
            )
            checks.append(existence_check)
            
            # 如果备份文件存在，检查文件大小
            if backup_exists:
                try:
                    original_size = Path(file_path).stat().st_size if Path(file_path).exists() else 0
                    backup_size = Path(backup_path).stat().st_size
                    
                    size_match = original_size == backup_size
                    
                    size_check = ValidationCheck(
                        check_id=f"backup_size_{file_path}",
                        validation_type=ValidationType.FILE_STATUS,
                        description=f"Check if backup file size matches original",
                        expected_result=original_size,
                        actual_result=backup_size,
                        result=ValidationResult.VALID if size_match else ValidationResult.PARTIAL,
                        confidence=0.8,
                        message=f"File sizes: original={original_size}, backup={backup_size}",
                        timestamp=datetime.now(),
                        execution_time=0.1
                    )
                    checks.append(size_check)
                    
                except Exception as e:
                    error_check = ValidationCheck(
                        check_id=f"backup_size_error_{file_path}",
                        validation_type=ValidationType.FILE_STATUS,
                        description=f"Backup size check error",
                        expected_result="success",
                        actual_result=str(e),
                        result=ValidationResult.ERROR,
                        confidence=0.0,
                        message=f"Size check error: {e}",
                        timestamp=datetime.now(),
                        execution_time=0.0
                    )
                    checks.append(error_check)
            
        except Exception as e:
            logger.error(f"File backup validation error: {e}")
        
        return checks
    
    async def _validate_file_scan(self, 
                                command_info: Dict[str, Any], 
                                execution_result: ExecutionResult) -> List[ValidationCheck]:
        """验证文件扫描效果"""
        checks = []
        
        try:
            file_path = command_info['parameters'].get('file_path')
            if not file_path:
                return checks
            
            # 分析扫描输出
            scan_output = execution_result.stdout
            
            # 检查是否有恶意软件发现
            malware_found = 'FOUND' in scan_output.upper() or 'INFECTED' in scan_output.upper()
            scan_completed = 'scanned' in scan_output.lower() or 'scan completed' in scan_output.lower()
            
            completion_check = ValidationCheck(
                check_id=f"scan_completion_{file_path}",
                validation_type=ValidationType.SECURITY_POLICY,
                description=f"Check if file scan completed for {file_path}",
                expected_result=True,
                actual_result=scan_completed,
                result=ValidationResult.VALID if scan_completed else ValidationResult.INVALID,
                confidence=0.9,
                message=f"File scan {'completed' if scan_completed else 'incomplete'}",
                timestamp=datetime.now(),
                execution_time=0.1
            )
            checks.append(completion_check)
            
            if scan_completed:
                malware_check = ValidationCheck(
                    check_id=f"malware_detection_{file_path}",
                    validation_type=ValidationType.SECURITY_POLICY,
                    description=f"Malware detection result for {file_path}",
                    expected_result="no_malware",
                    actual_result="malware_found" if malware_found else "clean",
                    result=ValidationResult.VALID,  # 扫描完成就是有效的
                    confidence=0.85,
                    message=f"Malware {'detected' if malware_found else 'not detected'} in {file_path}",
                    timestamp=datetime.now(),
                    execution_time=0.1
                )
                checks.append(malware_check)
            
        except Exception as e:
            logger.error(f"File scan validation error: {e}")
        
        return checks
    
    async def _validate_firewall_update(self, 
                                       command_info: Dict[str, Any], 
                                       execution_result: ExecutionResult) -> List[ValidationCheck]:
        """验证防火墙更新效果"""
        checks = []
        
        try:
            action = command_info['parameters'].get('action')
            target = command_info['parameters'].get('target')
            
            if not action or not target:
                return checks
            
            # 检查UFW状态
            check_start = time.time()
            
            try:
                result = await asyncio.create_subprocess_exec(
                    'ufw', 'status', 'numbered',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                
                ufw_output = stdout.decode()
                rule_exists = target in ufw_output and action.upper() in ufw_output
                
                rule_check = ValidationCheck(
                    check_id=f"ufw_rule_{action}_{target}",
                    validation_type=ValidationType.SECURITY_POLICY,
                    description=f"Check if UFW rule exists: {action} {target}",
                    expected_result=True,
                    actual_result=rule_exists,
                    result=ValidationResult.VALID if rule_exists else ValidationResult.INVALID,
                    confidence=0.85,
                    message=f"UFW rule {action} {target} {'found' if rule_exists else 'not found'}",
                    timestamp=datetime.now(),
                    execution_time=time.time() - check_start
                )
                checks.append(rule_check)
                
            except Exception as e:
                error_check = ValidationCheck(
                    check_id=f"ufw_check_error_{target}",
                    validation_type=ValidationType.SECURITY_POLICY,
                    description=f"UFW rule check error",
                    expected_result="success",
                    actual_result=str(e),
                    result=ValidationResult.ERROR,
                    confidence=0.0,
                    message=f"Failed to check UFW rules: {e}",
                    timestamp=datetime.now(),
                    execution_time=0.0
                )
                checks.append(error_check)
            
        except Exception as e:
            logger.error(f"Firewall update validation error: {e}")
        
        return checks
    
    async def _validate_status_check(self, 
                                   command_info: Dict[str, Any], 
                                   execution_result: ExecutionResult) -> List[ValidationCheck]:
        """验证状态检查效果"""
        checks = []
        
        try:
            service_name = command_info['parameters'].get('service_name')
            if not service_name:
                return checks
            
            # 分析状态检查输出
            status_output = execution_result.stdout
            
            # 检查是否获得了状态信息
            has_status_info = any(keyword in status_output.lower() for keyword in 
                                ['active', 'inactive', 'failed', 'running', 'stopped'])
            
            status_check = ValidationCheck(
                check_id=f"status_info_{service_name}",
                validation_type=ValidationType.SERVICE_STATUS,
                description=f"Check if status information was retrieved for {service_name}",
                expected_result=True,
                actual_result=has_status_info,
                result=ValidationResult.VALID if has_status_info else ValidationResult.INVALID,
                confidence=0.9,
                message=f"Status information {'retrieved' if has_status_info else 'not available'}",
                timestamp=datetime.now(),
                execution_time=0.1
            )
            checks.append(status_check)
            
        except Exception as e:
            logger.error(f"Status check validation error: {e}")
        
        return checks
    
    def _analyze_validation_results(self, checks: List[ValidationCheck]) -> Tuple[bool, float, str, List[str], bool]:
        """分析验证结果"""
        if not checks:
            return True, 0.5, "No validation checks performed", [], False
        
        # 计算总体结果
        valid_checks = sum(1 for check in checks if check.result == ValidationResult.VALID)
        invalid_checks = sum(1 for check in checks if check.result == ValidationResult.INVALID)
        error_checks = sum(1 for check in checks if check.result == ValidationResult.ERROR)
        
        total_checks = len(checks)
        
        # 计算置信度
        confidence_sum = sum(check.confidence for check in checks)
        overall_confidence = confidence_sum / total_checks if total_checks > 0 else 0.0
        
        # 确定是否有效
        is_valid = (valid_checks > invalid_checks) and (error_checks == 0)
        
        # 生成摘要
        summary = f"Validation completed: {valid_checks} valid, {invalid_checks} invalid, {error_checks} errors"
        
        # 生成建议
        recommendations = []
        if invalid_checks > 0:
            recommendations.append("Review failed validation checks")
        if error_checks > 0:
            recommendations.append("Investigate validation errors")
            recommendations.append("Check system permissions and dependencies")
        if overall_confidence < self.config['confidence_threshold']:
            recommendations.append("Low confidence in validation results")
        
        # 确定是否需要回滚
        requires_rollback = (invalid_checks > valid_checks) or (error_checks > 0)
        
        return is_valid, overall_confidence, summary, recommendations, requires_rollback
    
    def get_validation_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取验证历史"""
        return [result.to_dict() for result in self.validation_history[-limit:]]
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        if not self.validation_history:
            return {
                'total_validations': 0,
                'success_rate': 0.0,
                'average_confidence': 0.0,
                'average_validation_time': 0.0
            }
        
        successful_validations = sum(1 for result in self.validation_history if result.is_valid)
        total_validations = len(self.validation_history)
        
        success_rate = (successful_validations / total_validations) * 100
        average_confidence = sum(result.overall_confidence for result in self.validation_history) / total_validations
        average_validation_time = sum(result.total_validation_time for result in self.validation_history) / total_validations
        
        return {
            'total_validations': total_validations,
            'successful_validations': successful_validations,
            'success_rate': success_rate,
            'average_confidence': average_confidence,
            'average_validation_time': average_validation_time
        }


# 创建全局效果验证器实例
effect_validator = EffectValidator()


# 便捷函数
async def validate_command_effect(command_info: Dict[str, Any], 
                                 execution_result: ExecutionResult) -> EffectValidationResult:
    """验证命令执行效果的便捷函数"""
    return await effect_validator.validate_effect(command_info, execution_result)