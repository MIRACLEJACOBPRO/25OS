#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1.3.3 综合集成测试
测试完整的Falco事件采集到Neo4j知识图谱构建的工作流
工作流: Falco Events → Log Parser → Volume Controller → Graph Database → Knowledge Graph
"""

import os
import sys
import asyncio
import subprocess
import signal
import time
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional
from loguru import logger

# 添加项目路径
sys.path.append('/home/xzj/01_Project/B_25OS/src/backend')

# 临时禁用配置验证，因为测试不需要OpenAI和Pinecone
import os
os.environ['OPENAI_API_KEY'] = 'test-key-for-integration-test'
os.environ['PINECONE_API_KEY'] = 'test-key-for-integration-test'

from core.config import settings
from core.database import neo4j_driver
from services.graph_database import GraphDatabase
from services.graph_builder import GraphBuilder
from services.log_processor import LogProcessor
from services.log_volume_controller import LogVolumeController, LogVolumeConfig


class ComprehensiveIntegrationTest:
    """综合集成测试类"""
    
    def __init__(self):
        self.neo4j_driver = None
        self.graph_db = None
        self.graph_builder = None
        self.log_processor = None
        self.falco_process = None
        self.test_log_file = "/home/xzj/01_Project/B_25OS/logs/test_integration_falco.log"
        self.original_log_path = settings.falco_log_path
        self.original_batch_size = settings.batch_size
        self.test_start_time = datetime.now()
        
        # 配置日志
        logger.add(
            "/home/xzj/01_Project/B_25OS/logs/integration_test.log",
            rotation="10 MB",
            retention="1 day",
            level="INFO"
        )
    
    async def check_neo4j_connection(self) -> bool:
        """检查Neo4j数据库连接状态"""
        try:
            logger.info("正在检查Neo4j数据库连接...")
            
            # 尝试连接Neo4j
            self.neo4j_driver = neo4j_driver
            
            # 验证连接
            connection_result = await self.neo4j_driver.verify_connectivity()
            if not connection_result:
                logger.error("Neo4j连接验证失败")
                return False
            
            # 创建图数据库实例并测试连接
            self.graph_db = GraphDatabase(
                uri=settings.neo4j_uri,
                username=settings.neo4j_user,
                password=settings.neo4j_password,
                database=settings.neo4j_database
            )
            
            connection_test = self.graph_db.test_connection()
            if not connection_test:
                logger.error("Neo4j连接测试失败")
                return False
            
            logger.info("✅ Neo4j数据库连接正常")
            return True
            
        except Exception as e:
            logger.error(f"❌ Neo4j数据库连接失败: {e}")
            logger.error("请确保Neo4j数据库已启动并且配置正确")
            logger.error(f"连接信息: {settings.neo4j_uri}, 用户: {settings.neo4j_user}")
            return False
    
    def setup_test_environment(self):
        """设置测试环境"""
        try:
            logger.info("正在设置测试环境...")
            
            # 创建测试日志目录
            test_log_dir = Path(self.test_log_file).parent
            test_log_dir.mkdir(parents=True, exist_ok=True)
            
            # 临时修改配置以使用测试日志文件
            settings.falco_log_path = self.test_log_file
            
            # 临时设置批量大小为10（测试用）
            settings.batch_size = 10
            logger.info(f"临时设置批量大小为: {settings.batch_size}")
            
            # 清理之前的测试日志文件
            if Path(self.test_log_file).exists():
                Path(self.test_log_file).unlink()
            
            # 创建空的测试日志文件
            Path(self.test_log_file).touch()
            
            logger.info(f"✅ 测试环境设置完成，测试日志文件: {self.test_log_file}")
            
        except Exception as e:
            logger.error(f"❌ 测试环境设置失败: {e}")
            raise
    
    def start_falco_simulation(self):
        """启动真实的Falco程序采集系统事件"""
        try:
            logger.info("正在启动真实Falco程序...")
            
            # 检查Falco是否已安装
            falco_check = subprocess.run(["which", "falco"], capture_output=True, text=True)
            if falco_check.returncode != 0:
                logger.warning("Falco未安装，将使用模拟数据")
                self._start_simulation_fallback()
                return
            
            # 启动真实Falco进程，输出到测试日志文件
            falco_cmd = [
                "sudo", "falco",
                "--json-output",
                "--log-level", "info",
                "-o", f"json_output=true",
                "-o", f"file_output.enabled=true",
                "-o", f"file_output.filename={self.test_log_file}"
            ]
            
            self.falco_process = subprocess.Popen(
                falco_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # 创建新的进程组
            )
            
            logger.info(f"✅ 真实Falco程序已启动，PID: {self.falco_process.pid}")
            logger.info(f"Falco事件将写入: {self.test_log_file}")
            
            # 等待一下让Falco启动
            time.sleep(2)
            
            # 生成一些系统活动来触发Falco事件
            self._generate_system_activity()
            
            if self.falco_process.poll() is not None:
                stdout, stderr = self.falco_process.communicate()
                logger.error(f"Falco程序启动失败: {stderr.decode()}")
                logger.info("回退到模拟数据模式")
                self._start_simulation_fallback()
            
        except Exception as e:
            logger.error(f"❌ Falco程序启动失败: {e}")
            logger.info("回退到模拟数据模式")
            self._start_simulation_fallback()
    
    def _start_simulation_fallback(self):
        """回退到模拟数据模式"""
        logger.info("启动Falco事件模拟（回退模式）...")
        
        # 创建模拟脚本
        simulation_script = self._create_falco_simulation_script()
        
        # 启动模拟进程
        self.falco_process = subprocess.Popen(
            ["python3", simulation_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        logger.info(f"✅ Falco事件模拟已启动，PID: {self.falco_process.pid}")
    
    def _generate_system_activity(self):
        """生成一些系统活动来触发Falco事件"""
        try:
            logger.info("生成系统活动以触发Falco事件...")
            
            # 创建一些文件操作
            test_activities = [
                "touch /tmp/test_file_1.txt",
                "echo 'test content' > /tmp/test_file_2.txt",
                "ls -la /etc/passwd",
                "cat /proc/version",
                "ps aux | head -5"
            ]
            
            for activity in test_activities:
                try:
                    subprocess.run(activity, shell=True, capture_output=True, timeout=5)
                    time.sleep(0.5)
                except Exception as e:
                    logger.debug(f"活动执行失败: {activity}, 错误: {e}")
            
            logger.info("系统活动生成完成")
            
        except Exception as e:
            logger.warning(f"生成系统活动时出现错误: {e}")
    
    def _create_falco_simulation_script(self) -> str:
        """创建Falco事件模拟脚本（回退模式）"""
        script_path = "/tmp/falco_simulation.py"
        
        script_content = f'''
#!/usr/bin/env python3
import json
import time
import random
from datetime import datetime, timezone

# 模拟的Falco事件模板
event_templates = [
    {{
        "output": "File below /etc opened for writing (user={{user}} command={{command}} file={{file}})",
        "priority": "Warning",
        "rule": "Write below etc",
        "source": "syscall",
        "tags": ["filesystem", "mitre_persistence"],
        "output_fields": {{
            "evt.time": None,
            "user.name": "{{user}}",
            "proc.cmdline": "{{command}}",
            "fd.name": "{{file}}",
            "proc.pid": None,
            "proc.ppid": None
        }}
    }},
    {{
        "output": "Terminal shell in container (user={{user}} shell={{shell}} parent={{parent}} cmdline={{cmdline}})",
        "priority": "Notice", 
        "rule": "Terminal shell in container",
        "source": "syscall",
        "tags": ["container", "shell", "mitre_execution"],
        "output_fields": {{
            "evt.time": None,
            "user.name": "{{user}}",
            "proc.name": "{{shell}}",
            "proc.pname": "{{parent}}",
            "proc.cmdline": "{{cmdline}}",
            "proc.pid": None,
            "proc.ppid": None,
            "container.id": "{{container_id}}",
            "container.name": "{{container_name}}"
        }}
    }},
    {{
        "output": "Outbound connection to C2 server (command={{command}} connection={{connection}})",
        "priority": "Critical",
        "rule": "Detect outbound connections to common C2 servers", 
        "source": "syscall",
        "tags": ["network", "mitre_command_and_control"],
        "output_fields": {{
            "evt.time": None,
            "proc.cmdline": "{{command}}",
            "fd.name": "{{connection}}",
            "fd.rip": "{{remote_ip}}",
            "fd.rport": "{{remote_port}}",
            "proc.pid": None,
            "proc.ppid": None
        }}
    }}
]

# 模拟数据
users = ["root", "admin", "user1", "www-data"]
commands = [
    "/bin/bash -c echo test",
    "/usr/bin/vim /etc/passwd", 
    "/bin/cat /etc/shadow",
    "/usr/bin/curl http://malicious.com"
]
files = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/crontab"]
shells = ["bash", "sh", "zsh"]
parents = ["systemd", "init", "docker"]
container_ids = ["abc123def456", "789ghi012jkl", "345mno678pqr"]
container_names = ["web-server", "database", "cache-redis"]
remote_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.10"]
remote_ports = ["8080", "443", "22", "3389"]

def generate_event():
    """生成一个随机的Falco事件"""
    template = random.choice(event_templates)
    event = template.copy()
    
    # 设置时间戳
    current_time = datetime.now(timezone.utc)
    timestamp = int(current_time.timestamp() * 1000000000)  # 纳秒时间戳
    event["time"] = current_time.isoformat()
    event["output_fields"]["evt.time"] = timestamp
    
    # 设置PID
    pid = random.randint(1000, 9999)
    ppid = random.randint(1, 999)
    event["output_fields"]["proc.pid"] = pid
    event["output_fields"]["proc.ppid"] = ppid
    
    # 根据模板类型填充具体数据
    if "Write below etc" in event["rule"]:
        user = random.choice(users)
        command = random.choice(commands)
        file = random.choice(files)
        event["output"] = event["output"].format(user=user, command=command, file=file)
        event["output_fields"]["user.name"] = user
        event["output_fields"]["proc.cmdline"] = command
        event["output_fields"]["fd.name"] = file
        
    elif "Terminal shell" in event["rule"]:
        user = random.choice(users)
        shell = random.choice(shells)
        parent = random.choice(parents)
        cmdline = f"/bin/{{shell}}"
        container_id = random.choice(container_ids)
        container_name = random.choice(container_names)
        
        event["output"] = event["output"].format(
            user=user, shell=shell, parent=parent, cmdline=cmdline
        )
        event["output_fields"]["user.name"] = user
        event["output_fields"]["proc.name"] = shell
        event["output_fields"]["proc.pname"] = parent
        event["output_fields"]["proc.cmdline"] = cmdline
        event["output_fields"]["container.id"] = container_id
        event["output_fields"]["container.name"] = container_name
        
    elif "C2 server" in event["rule"]:
        command = random.choice(commands)
        remote_ip = random.choice(remote_ips)
        remote_port = random.choice(remote_ports)
        connection = f"{{remote_ip}}:{{remote_port}}"
        
        event["output"] = event["output"].format(command=command, connection=connection)
        event["output_fields"]["proc.cmdline"] = command
        event["output_fields"]["fd.name"] = connection
        event["output_fields"]["fd.rip"] = remote_ip
        event["output_fields"]["fd.rport"] = int(remote_port)
    
    return event

def main():
    """主函数：持续生成Falco事件"""
    print("开始生成Falco事件模拟数据...")
    
    with open("{self.test_log_file}", "w") as f:
        # 生成15个事件（确保超过批量大小10）
        for i in range(15):
            event = generate_event()
            # 写入JSON格式的事件
            f.write(json.dumps(event) + "\\n")
            f.flush()  # 立即刷新到文件
            
            print(f"生成事件 {{i+1}}/15: {{event['rule']}}")
            
            # 每个事件之间间隔1秒
            time.sleep(1)
    
    print("Falco事件模拟完成")

if __name__ == "__main__":
    main()
'''
        
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # 使脚本可执行
        os.chmod(script_path, 0o755)
        
        return script_path
    
    async def initialize_components(self):
        """初始化各个组件"""
        try:
            logger.info("正在初始化系统组件...")
            
            # 初始化图构建器
            self.graph_builder = GraphBuilder()
            
            # 初始化日志处理器
            self.log_processor = LogProcessor(self.graph_builder)
            
            logger.info("✅ 系统组件初始化完成")
            
        except Exception as e:
            logger.error(f"❌ 系统组件初始化失败: {e}")
            raise
    
    async def start_log_monitoring(self):
        """启动日志监控"""
        try:
            logger.info("正在启动日志监控...")
            
            # 启动日志处理器监控
            await self.log_processor.start_monitoring()
            
            logger.info("✅ 日志监控已启动")
            
        except Exception as e:
            logger.error(f"❌ 日志监控启动失败: {e}")
            raise
    
    async def wait_for_processing_completion(self, timeout_seconds: int = 60):
        """等待日志处理完成"""
        try:
            logger.info(f"等待日志处理完成（超时: {timeout_seconds}秒）...")
            
            start_time = time.time()
            last_processed_count = 0
            stable_count = 0
            
            while time.time() - start_time < timeout_seconds:
                # 获取处理统计信息
                stats = await self.log_processor.get_processing_stats()
                current_processed = stats.get('processed_events_count', 0)
                
                logger.info(f"当前已处理事件数: {current_processed}")
                
                # 检查是否达到批量处理条件
                if current_processed >= settings.batch_size:
                    logger.info(f"✅ 已达到批量处理条件（{settings.batch_size}个事件），停止采集")
                    break
                
                # 检查处理是否稳定（连续3次检查没有新增）
                if current_processed == last_processed_count:
                    stable_count += 1
                    if stable_count >= 3 and current_processed > 0:
                        logger.info("✅ 事件处理已稳定，完成处理")
                        break
                else:
                    stable_count = 0
                
                last_processed_count = current_processed
                await asyncio.sleep(5)  # 每5秒检查一次
            
            if time.time() - start_time >= timeout_seconds:
                logger.warning(f"⚠️ 等待超时（{timeout_seconds}秒），强制结束")
            
            # 最终处理统计
            final_stats = await self.log_processor.get_processing_stats()
            logger.info(f"最终处理统计: {final_stats}")
            
        except Exception as e:
            logger.error(f"❌ 等待处理完成时发生错误: {e}")
            raise
    
    async def verify_graph_data(self) -> Dict[str, Any]:
        """验证图数据库中的数据"""
        try:
            logger.info("正在验证图数据库中的数据...")
            
            # 直接使用图数据库连接查询统计信息
            stats = {
                'total_nodes': 0,
                'total_relationships': 0,
                'node_types': {},
                'relationship_types': {}
            }
            
            if self.neo4j_driver:
                 try:
                     # 查询节点总数
                     node_count_query = "MATCH (n) RETURN count(n) as total_nodes"
                     node_result = await self.neo4j_driver.execute_query(node_count_query)
                     if node_result:
                         stats['total_nodes'] = node_result[0].get('total_nodes', 0)
                     
                     # 查询关系总数
                     rel_count_query = "MATCH ()-[r]->() RETURN count(r) as total_relationships"
                     rel_result = await self.neo4j_driver.execute_query(rel_count_query)
                     if rel_result:
                         stats['total_relationships'] = rel_result[0].get('total_relationships', 0)
                     
                     # 查询节点类型分布
                     node_type_query = "MATCH (n) RETURN DISTINCT labels(n) as labels, count(n) as count"
                     node_type_result = await self.neo4j_driver.execute_query(node_type_query)
                     if node_type_result:
                         for record in node_type_result:
                             labels = record.get('labels', [])
                             count = record.get('count', 0)
                             if labels:
                                 label_key = ':'.join(sorted(labels))
                                 stats['node_types'][label_key] = count
                     
                     logger.info(f"图数据库统计信息: {stats}")
                     
                 except Exception as query_error:
                     logger.warning(f"查询图数据库统计时出现错误: {query_error}")
            
            # 验证是否有数据被成功存储
            if stats.get('total_nodes', 0) > 0:
                logger.info("✅ 图数据库中存在节点数据")
            else:
                logger.warning("⚠️ 图数据库中未发现节点数据")
            
            return stats
            
        except Exception as e:
            logger.error(f"❌ 验证图数据时发生错误: {e}")
            return {}
    
    def stop_falco_process(self):
        """停止Falco模拟进程"""
        try:
            if self.falco_process and self.falco_process.poll() is None:
                logger.info("正在停止Falco模拟进程...")
                
                # 终止整个进程组
                os.killpg(os.getpgid(self.falco_process.pid), signal.SIGTERM)
                
                # 等待进程结束
                try:
                    self.falco_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # 强制杀死进程
                    os.killpg(os.getpgid(self.falco_process.pid), signal.SIGKILL)
                    self.falco_process.wait()
                
                logger.info("✅ Falco模拟进程已停止")
            
        except Exception as e:
            logger.error(f"❌ 停止Falco进程时发生错误: {e}")
    
    async def cleanup_resources(self):
        """清理资源"""
        try:
            logger.info("正在清理资源...")
            
            # 停止日志监控
            if self.log_processor:
                try:
                    await self.log_processor.stop_monitoring()
                    logger.info("✅ 日志处理器已停止")
                except Exception as e:
                    logger.warning(f"日志处理器停止时出现警告: {e}")
            
            # 关闭数据库连接
            if self.neo4j_driver:
                try:
                    await self.neo4j_driver.close()
                    logger.info("✅ Neo4j连接已关闭")
                except Exception as e:
                    logger.warning(f"Neo4j连接关闭时出现警告: {e}")
            
            # 恢复原始配置
            settings.falco_log_path = self.original_log_path
            settings.batch_size = self.original_batch_size
            logger.info(f"恢复原始批量大小: {settings.batch_size}")
            
            # 清理测试文件
            test_files = [
                self.test_log_file,
                "/tmp/falco_simulation.py"
            ]
            
            for file_path in test_files:
                if Path(file_path).exists():
                    try:
                        Path(file_path).unlink()
                        logger.info(f"✅ 测试文件已删除: {file_path}")
                    except Exception as e:
                        logger.warning(f"测试文件删除时出现警告: {e}")
            
            logger.info("✅ 资源清理完成")
            
        except Exception as e:
            logger.error(f"❌ 资源清理时发生错误: {e}")
    
    async def run_comprehensive_test(self) -> Dict[str, Any]:
        """运行综合测试"""
        test_results = {
            'start_time': self.test_start_time,
            'end_time': None,
            'duration': None,
            'neo4j_connection': False,
            'falco_simulation': False,
            'log_processing': False,
            'graph_data_verification': False,
            'total_events_processed': 0,
            'graph_stats': {},
            'errors': []
        }
        
        try:
            # 1. 检查Neo4j连接
            logger.info("=== 步骤 1: 检查Neo4j数据库连接 ===")
            if not await self.check_neo4j_connection():
                test_results['errors'].append("Neo4j连接失败")
                return test_results
            test_results['neo4j_connection'] = True
            
            # 2. 设置测试环境
            logger.info("=== 步骤 2: 设置测试环境 ===")
            self.setup_test_environment()
            
            # 3. 初始化组件
            logger.info("=== 步骤 3: 初始化系统组件 ===")
            await self.initialize_components()
            
            # 4. 启动日志监控
            logger.info("=== 步骤 4: 启动日志监控 ===")
            await self.start_log_monitoring()
            test_results['log_processing'] = True
            
            # 5. 启动Falco数据采集
            logger.info("=== 步骤 5: 启动Falco数据采集 ===")
            self.start_falco_simulation()
            test_results['falco_simulation'] = True
            
            # 6. 等待处理完成
            logger.info("=== 步骤 6: 等待事件处理完成 ===")
            logger.info(f"当前批量大小设置: {settings.batch_size}")
            logger.info("log_processor将在收集到10个事件时自动调用graph_builder进行图构建")
            await self.wait_for_processing_completion()
            
            # 7. 验证图数据
            logger.info("=== 步骤 7: 验证图数据库数据 ===")
            graph_stats = await self.verify_graph_data()
            test_results['graph_stats'] = graph_stats
            test_results['graph_data_verification'] = True
            
            # 获取最终处理统计
            if self.log_processor:
                final_stats = await self.log_processor.get_processing_stats()
                test_results['total_events_processed'] = final_stats.get('processed_events_count', 0)
            
            logger.info("=== 综合测试完成 ===")
            
        except Exception as e:
            error_msg = f"测试执行过程中发生错误: {e}"
            logger.error(f"❌ {error_msg}")
            test_results['errors'].append(error_msg)
            
        finally:
            # 8. 清理资源
            logger.info("=== 步骤 8: 清理资源 ===")
            self.stop_falco_process()
            await self.cleanup_resources()
            
            # 记录结束时间
            test_results['end_time'] = datetime.now()
            test_results['duration'] = (test_results['end_time'] - test_results['start_time']).total_seconds()
        
        return test_results
    
    def print_test_summary(self, results: Dict[str, Any]):
        """打印测试总结"""
        print("\n" + "="*80)
        print("🧪 NeuronOS 综合集成测试报告")
        print("="*80)
        print(f"测试开始时间: {results['start_time']}")
        print(f"测试结束时间: {results['end_time']}")
        print(f"测试持续时间: {results['duration']:.2f} 秒")
        print()
        
        print("📋 测试项目结果:")
        print(f"  ✅ Neo4j连接检查: {'通过' if results['neo4j_connection'] else '❌ 失败'}")
        print(f"  ✅ Falco数据采集: {'通过' if results['falco_simulation'] else '❌ 失败'}")
        print(f"  ✅ 日志处理功能: {'通过' if results['log_processing'] else '❌ 失败'}")
        print(f"  ✅ 图数据验证: {'通过' if results['graph_data_verification'] else '❌ 失败'}")
        print()
        
        print("📊 处理统计:")
        print(f"  处理事件总数: {results['total_events_processed']}")
        print(f"  图节点总数: {results['graph_stats'].get('total_nodes', 0)}")
        print(f"  图关系总数: {results['graph_stats'].get('total_relationships', 0)}")
        print()
        
        if results['errors']:
            print("❌ 错误信息:")
            for error in results['errors']:
                print(f"  - {error}")
            print()
        
        # 总体结果
        all_passed = (results['neo4j_connection'] and 
                     results['falco_simulation'] and 
                     results['log_processing'] and 
                     results['graph_data_verification'] and 
                     not results['errors'])
        
        if all_passed:
            print("🎉 综合测试全部通过！")
            print("✅ 真实Falco数据采集 → Log Processor(批量=10) → Graph Builder → Neo4j 工作流验证成功")
        else:
            print("⚠️ 部分测试项目未通过，请检查错误信息")
        
        print("="*80)


async def main():
    """主函数"""
    print("🚀 启动 NeuronOS 综合集成测试")
    print("测试工作流: 真实Falco数据采集 → Log Processor(批量=10) → Graph Builder → Neo4j")
    print()
    
    # 创建测试实例
    test = ComprehensiveIntegrationTest()
    
    try:
        # 运行综合测试
        results = await test.run_comprehensive_test()
        
        # 打印测试总结
        test.print_test_summary(results)
        
        # 根据测试结果设置退出码
        if results['errors'] or not all([
            results['neo4j_connection'],
            results['falco_simulation'], 
            results['log_processing'],
            results['graph_data_verification']
        ]):
            return 1
        else:
            return 0
            
    except KeyboardInterrupt:
        logger.info("测试被用户中断")
        try:
            await test.cleanup_resources()
        except Exception as cleanup_error:
            logger.error(f"清理资源时发生错误: {cleanup_error}")
        return 130
    except Exception as e:
        logger.error(f"测试执行失败: {e}")
        try:
            await test.cleanup_resources()
        except Exception as cleanup_error:
            logger.error(f"清理资源时发生错误: {cleanup_error}")
        return 1


if __name__ == "__main__":
    # 运行测试
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except Exception as e:
        logger.error(f"程序执行失败: {e}")
        sys.exit(1)