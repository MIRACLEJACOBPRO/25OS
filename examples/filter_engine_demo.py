#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NeuronOS 本地过滤引擎演示脚本

演示功能:
1. 引擎初始化和配置
2. 事件处理流程
3. 白名单管理
4. 统计信息查看
5. 动态配置更新
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any

# 添加项目路径
sys.path.append('/home/xzj/01_Project/B_25OS/src/backend')

from services.local_filter_engine import (
    LocalFilterEngine, FilterEngineConfig, create_filter_engine
)
from services.interfaces import EventPriority

# 模拟StandardizedEvent
@dataclass
class StandardizedEvent:
    event_id: str
    timestamp: datetime
    priority: EventPriority
    rule_name: str
    message: str
    fields: Dict[str, Any]
    triple: Dict[str, str]


class FilterEngineDemo:
    """过滤引擎演示类"""
    
    def __init__(self):
        self.engine = None
        self.demo_events = self._create_demo_events()
    
    def _create_demo_events(self):
        """创建演示事件"""
        base_time = datetime.now()
        
        return [
            # 高优先级安全事件
            StandardizedEvent(
                event_id="demo_001",
                timestamp=base_time,
                priority=EventPriority.CRITICAL,
                rule_name="Suspicious Process Execution",
                message="Process /tmp/malware executed with suspicious arguments",
                fields={
                    "process_name": "/tmp/malware",
                    "user": "root",
                    "pid": "12345"
                },
                triple={
                    "source": "192.168.1.100",
                    "target": "192.168.1.1",
                    "action": "execute"
                }
            ),
            
            # 白名单IP事件
            StandardizedEvent(
                event_id="demo_002",
                timestamp=base_time,
                priority=EventPriority.MEDIUM,
                rule_name="Network Connection",
                message="Connection established from localhost",
                fields={
                    "protocol": "tcp",
                    "port": "22"
                },
                triple={
                    "source": "127.0.0.1",
                    "target": "192.168.1.1",
                    "action": "connect"
                }
            ),
            
            # 低优先级事件
            StandardizedEvent(
                event_id="demo_003",
                timestamp=base_time,
                priority=EventPriority.LOW,
                rule_name="File Access",
                message="File /var/log/syslog accessed",
                fields={
                    "file_path": "/var/log/syslog",
                    "access_type": "read"
                },
                triple={
                    "source": "192.168.1.50",
                    "target": "192.168.1.1",
                    "action": "read"
                }
            ),
            
            # 系统更新事件（应该被白名单）
            StandardizedEvent(
                event_id="demo_004",
                timestamp=base_time,
                priority=EventPriority.MEDIUM,
                rule_name="System Update Process",
                message="System update process started",
                fields={
                    "process_name": "apt-get",
                    "command": "update"
                },
                triple={
                    "source": "192.168.1.10",
                    "target": "archive.ubuntu.com",
                    "action": "download"
                }
            ),
            
            # 恶意软件检测事件
            StandardizedEvent(
                event_id="demo_005",
                timestamp=base_time,
                priority=EventPriority.HIGH,
                rule_name="Malware Detection Rule",
                message="Malware signature detected in file",
                fields={
                    "file_path": "/tmp/suspicious.exe",
                    "signature": "Trojan.Generic"
                },
                triple={
                    "source": "192.168.1.200",
                    "target": "192.168.1.1",
                    "action": "scan"
                }
            )
        ]
    
    async def initialize_engine(self):
        """初始化过滤引擎"""
        print("🚀 初始化本地过滤引擎...")
        
        # 使用配置文件创建引擎
        config_file = "/home/xzj/01_Project/B_25OS/config/filter_engine_config.json"
        
        try:
            self.engine = create_filter_engine(config_file=config_file)
            print(f"✅ 引擎初始化成功，配置文件: {config_file}")
        except Exception as e:
            print(f"❌ 引擎初始化失败: {e}")
            # 使用默认配置
            config = FilterEngineConfig(
                enabled=True,
                max_concurrent_filters=5,
                priority_filter_enabled=True,
                min_priority="MEDIUM",
                frequency_filter_enabled=True,
                max_events_per_minute=10,
                ip_whitelist_enabled=True,
                whitelist_ips=["127.0.0.1", "192.168.1.0/24"],
                pattern_filter_enabled=True,
                block_patterns=[".*malware.*", ".*virus.*"],
                allow_patterns=[".*system.*", ".*update.*"],
                enable_statistics=True,
                statistics_interval=10
            )
            self.engine = LocalFilterEngine(config)
            print("✅ 使用默认配置初始化引擎")
        
        # 启动引擎
        await self.engine.start_engine()
        print("🔄 引擎已启动")
    
    async def demonstrate_event_processing(self):
        """演示事件处理"""
        print("\n📊 开始事件处理演示...")
        print("=" * 60)
        
        for i, event in enumerate(self.demo_events, 1):
            print(f"\n🔍 处理事件 {i}/{len(self.demo_events)}:")
            print(f"   ID: {event.event_id}")
            print(f"   优先级: {event.priority.value}")
            print(f"   规则: {event.rule_name}")
            print(f"   描述: {event.message}")
            print(f"   三元组: {event.triple}")
            
            try:
                # 处理事件
                result = await self.engine.process_event(event)
                
                # 显示结果
                decision = result['decision']
                confidence = result['confidence']
                processing_time = result['processing_time']
                
                # 根据决策显示不同的图标
                decision_icons = {
                    'PASS': '✅',
                    'BLOCK': '🚫',
                    'SUSPICIOUS': '⚠️',
                    'WHITELIST': '✅'
                }
                
                icon = decision_icons.get(decision, '❓')
                print(f"   结果: {icon} {decision} (置信度: {confidence:.2f})")
                print(f"   处理时间: {processing_time:.2f}ms")
                
                if 'anomaly_score' in result:
                    score = result['anomaly_score']
                    print(f"   异常评分: {score['total_score']:.2f} (风险级别: {score['risk_level']})")
                    if score['indicators']:
                        print(f"   风险指标: {', '.join(score['indicators'])}")
                
                if 'filter_results' in result:
                    print(f"   过滤器结果: {len(result['filter_results'])} 个过滤器参与")
                    for filter_result in result['filter_results'][:3]:  # 只显示前3个
                        print(f"     - {filter_result['filter_name']}: {filter_result['result']}")
                
            except Exception as e:
                print(f"   ❌ 处理失败: {e}")
            
            # 短暂延迟，模拟实际处理间隔
            await asyncio.sleep(0.1)
    
    async def demonstrate_whitelist_management(self):
        """演示白名单管理"""
        print("\n🛡️ 白名单管理演示...")
        print("=" * 60)
        
        # 添加白名单规则
        print("\n📝 添加白名单规则:")
        whitelist_rules = [
            {
                "name": "系统进程白名单",
                "rule_name": "System Process",
                "process_name": "systemd"
            },
            {
                "name": "内网IP白名单",
                "source_ip": "192.168.1.0/24",
                "description": "内网IP段白名单"
            },
            {
                "name": "SSH连接白名单",
                "rule_name": "SSH Connection",
                "source_ip": "192.168.1.100",
                "target_port": "22"
            }
        ]
        
        for rule in whitelist_rules:
            try:
                await self.engine.add_whitelist_rule(rule)
                print(f"   ✅ 已添加: {rule['name']}")
            except Exception as e:
                print(f"   ❌ 添加失败: {rule['name']} - {e}")
        
        # 查看当前白名单规则
        print("\n📋 当前白名单规则:")
        try:
            rules = await self.engine.get_whitelist_rules()
            for i, rule in enumerate(rules, 1):
                print(f"   {i}. {rule.get('name', 'Unknown')} (ID: {rule.get('id', 'N/A')})")
                if 'description' in rule:
                    print(f"      描述: {rule['description']}")
        except Exception as e:
            print(f"   ❌ 获取白名单规则失败: {e}")
    
    async def demonstrate_statistics(self):
        """演示统计信息"""
        print("\n📈 统计信息演示...")
        print("=" * 60)
        
        try:
            status = await self.engine.get_engine_status()
            
            # 基本状态
            print(f"\n🔧 引擎状态:")
            print(f"   运行状态: {'🟢 运行中' if status['is_running'] else '🔴 已停止'}")
            print(f"   启动时间: {status['start_time']}")
            print(f"   运行时长: {status['uptime']:.2f} 秒")
            
            # 统计信息
            stats = status['statistics']
            print(f"\n📊 处理统计:")
            print(f"   总处理事件: {stats['total_processed']}")
            print(f"   通过事件: {stats['passed']}")
            print(f"   阻止事件: {stats['blocked']}")
            print(f"   可疑事件: {stats['suspicious']}")
            print(f"   白名单事件: {stats['whitelisted']}")
            print(f"   平均处理时间: {stats['average_processing_time']:.2f}ms")
            
            # 过滤器状态
            pipeline_status = status['pipeline_status']
            print(f"\n🔍 过滤器状态:")
            print(f"   活跃过滤器: {pipeline_status['active_filters']}")
            print(f"   总过滤器: {pipeline_status['total_filters']}")
            
            for filter_info in pipeline_status['filters']:
                enabled_icon = '🟢' if filter_info['enabled'] else '🔴'
                print(f"   {enabled_icon} {filter_info['name']}: {filter_info['processed']} 次处理")
            
            # 配置信息
            config = status['configuration']
            print(f"\n⚙️ 当前配置:")
            print(f"   最大并发过滤器: {config['max_concurrent_filters']}")
            print(f"   关联窗口: {config['correlation_window']} 秒")
            print(f"   最小优先级: {config['min_priority']}")
            print(f"   最大事件频率: {config['max_events_per_minute']}/分钟")
            
        except Exception as e:
            print(f"   ❌ 获取统计信息失败: {e}")
    
    async def demonstrate_configuration_update(self):
        """演示配置更新"""
        print("\n⚙️ 配置更新演示...")
        print("=" * 60)
        
        # 显示当前配置
        print("\n📋 当前配置:")
        try:
            status = await self.engine.get_engine_status()
            config = status['configuration']
            print(f"   最大事件频率: {config['max_events_per_minute']}/分钟")
            print(f"   关联窗口: {config['correlation_window']} 秒")
        except Exception as e:
            print(f"   ❌ 获取配置失败: {e}")
            return
        
        # 更新配置
        print("\n🔄 更新配置:")
        config_updates = {
            'max_events_per_minute': 50,
            'correlation_window': 600,
            'enable_adaptive_filtering': True
        }
        
        try:
            await self.engine.update_configuration(config_updates)
            print("   ✅ 配置更新成功")
            
            # 显示更新后的配置
            status = await self.engine.get_engine_status()
            config = status['configuration']
            print(f"   新的最大事件频率: {config['max_events_per_minute']}/分钟")
            print(f"   新的关联窗口: {config['correlation_window']} 秒")
            
        except Exception as e:
            print(f"   ❌ 配置更新失败: {e}")
    
    async def cleanup(self):
        """清理资源"""
        print("\n🧹 清理资源...")
        if self.engine:
            await self.engine.stop_engine()
            print("✅ 引擎已停止")
    
    async def run_demo(self):
        """运行完整演示"""
        print("🎯 NeuronOS 本地过滤引擎演示")
        print("=" * 60)
        
        try:
            # 初始化引擎
            await self.initialize_engine()
            
            # 演示各项功能
            await self.demonstrate_event_processing()
            await self.demonstrate_whitelist_management()
            await self.demonstrate_statistics()
            await self.demonstrate_configuration_update()
            
            print("\n🎉 演示完成!")
            
        except KeyboardInterrupt:
            print("\n⏹️ 演示被用户中断")
        except Exception as e:
            print(f"\n❌ 演示过程中发生错误: {e}")
        finally:
            await self.cleanup()


async def main():
    """主函数"""
    demo = FilterEngineDemo()
    await demo.run_demo()


if __name__ == '__main__':
    # 运行演示
    asyncio.run(main())