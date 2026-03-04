#!/usr/bin/env python3
"""
XDPGuard XDP Manager

Manages XDP program loading and BPF map interactions.
Uses precompiled XDP object files for maximum compatibility.
"""

import os
import logging
import subprocess
import ipaddress
import struct
import json
import time
from pathlib import Path
from python.event_logger import EventLogger
from python.packet_logger import PacketLogger

logger = logging.getLogger(__name__)


class XDPManager:
    """Manages XDP program and BPF maps"""

    def __init__(self, config):
        self.config = config
        self.interface = config.get('network.interface', 'ens33')
        self.xdp_mode = config.get('network.xdp_mode', 'xdpgeneric')
        self.xdp_obj_path = config.get('xdp.object_path', '/usr/lib/xdpguard/xdp_filter.o')
        self.xdp_loaded = False
        
        # Initialize event logger
        self.event_logger = EventLogger(max_events=1000)
        
        # Initialize packet logger
        max_packets = config.get('logging.max_packets', 10000)
        self.packet_logger = PacketLogger(max_packets=max_packets)
        
        # Track previous stats for delta calculations
        self.prev_stats = {
            'packets_dropped': 0,
            'packets_total': 0,
            'timestamp': time.time()
        }
        
        logger.info(f"XDP Manager initialized for interface {self.interface}")
        self.event_logger.log_event(
            event_type='SYSTEM',
            severity='INFO',
            ip_address='N/A',
            message=f'XDPGuard инициализирован для интерфейса {self.interface}',
            details={'interface': self.interface, 'mode': self.xdp_mode}
        )

    def load_program(self):
        """Load XDP program onto interface using ip link"""
        try:
            if not os.path.exists(self.xdp_obj_path):
                logger.error(f"XDP program not found at {self.xdp_obj_path}")
                self.event_logger.log_event(
                    event_type='SYSTEM',
                    severity='CRITICAL',
                    ip_address='N/A',
                    message=f'XDP программа не найдена: {self.xdp_obj_path}',
                    details={'path': self.xdp_obj_path}
                )
                return False
            
            success = self._load_xdp_with_mode(self.xdp_mode)
            
            if not success and self.xdp_mode != 'xdpgeneric':
                success = self._load_xdp_with_mode('xdpgeneric')
            
            if success:
                self.xdp_loaded = True
                self.event_logger.log_event(
                    event_type='LOAD',
                    severity='INFO',
                    ip_address='N/A',
                    message=f'XDP программа успешно загружена на {self.interface}',
                    details={'interface': self.interface, 'mode': self.xdp_mode}
                )
                return True
            else:
                self.event_logger.log_event(
                    event_type='SYSTEM',
                    severity='CRITICAL',
                    ip_address='N/A',
                    message='Не удалось загрузить XDP программу',
                    details={'interface': self.interface}
                )
                return False
                
        except Exception as e:
            self.event_logger.log_event(
                event_type='SYSTEM',
                severity='CRITICAL',
                ip_address='N/A',
                message=f'Ошибка при загрузке XDP: {str(e)}',
                details={'error': str(e)}
            )
            return False

    def _load_xdp_with_mode(self, mode):
        """Load XDP with specific mode"""
        try:
            cmd = ['sudo', 'ip', 'link', 'set', 'dev', self.interface,
                mode, 'obj', self.xdp_obj_path, 'sec', 'xdp']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False

    def _verify_xdp_loaded(self):
        """Verify XDP is attached to interface"""
        pass

    def unload_program(self):
        """Unload XDP program from interface"""
        try:
            if not self.xdp_loaded:
                return True
            
            cmd = ['ip', 'link', 'set', 'dev', self.interface, 'xdp', 'off']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.xdp_loaded = False
                self.event_logger.log_event(
                    event_type='UNLOAD',
                    severity='INFO',
                    ip_address='N/A',
                    message=f'XDP программа выгружена с {self.interface}',
                    details={'interface': self.interface}
                )
                return True
            return False
        except Exception as e:
            return False

    def get_statistics(self):
        """Get packet statistics from BPF maps"""
        try:
            result = subprocess.run(
                ['sudo', 'bpftool', 'map', 'dump', 'name', 'stats_map'],
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                return {'packets_total': 0, 'packets_dropped': 0, 'packets_passed': 0,
                        'bytes_total': 0, 'bytes_dropped': 0}
            
            total_stats = {'packets_total': 0, 'packets_dropped': 0, 'packets_passed': 0,
                          'bytes_total': 0, 'bytes_dropped': 0}
            
            import re
            for line in result.stdout.split("\n"):
                for key in total_stats.keys():
                    match = re.search(f'"{key}":\s*(\d+)', line)
                    if match:
                        total_stats[key] += int(match.group(1))
            
            return total_stats
        except:
            return {'packets_total': 0, 'packets_dropped': 0, 'packets_passed': 0,
                    'bytes_total': 0, 'bytes_dropped': 0}

    def check_for_attacks(self):
        """Проверить статистику и залогировать подозрительную активность"""
        try:
            stats = self.get_statistics()
            current_time = time.time()
            time_delta = current_time - self.prev_stats['timestamp']
            
            dropped_delta = stats['packets_dropped'] - self.prev_stats['packets_dropped']
            total_delta = stats['packets_total'] - self.prev_stats['packets_total']
            
            if dropped_delta > 0:
                drop_rate = (dropped_delta / total_delta * 100) if total_delta > 0 else 0
                packets_per_sec = dropped_delta / time_delta if time_delta > 0 else 0
                
                self.event_logger.log_event(
                    event_type='DROP',
                    severity='INFO' if dropped_delta < 1000 else 'WARNING',
                    ip_address='N/A',
                    message=f'Заблокировано {dropped_delta} пакетов ({drop_rate:.1f}%)',
                    details={
                        'packets_dropped': dropped_delta,
                        'packets_total': total_delta,
                        'drop_rate': round(drop_rate, 2),
                        'pps': round(packets_per_sec, 2),
                        'time_window': round(time_delta, 2)
                    }
                )
                
                attack_threshold = self.config.get('protection.attack_threshold', 10000)
                if dropped_delta > attack_threshold:
                    self.event_logger.log_event(
                        event_type='ATTACK',
                        severity='CRITICAL',
                        ip_address='N/A',
                        message=f'Обнаружена возможная DDoS атака: {dropped_delta} пакетов заблокировано за {time_delta:.1f}с',
                        details={
                            'packets_dropped': dropped_delta,
                            'packets_total': total_delta,
                            'drop_rate': round(drop_rate, 2),
                            'pps': round(packets_per_sec, 2),
                            'attack_type': 'DDoS',
                            'interface': self.interface
                        }
                    )
            
            self.prev_stats = {
                'packets_dropped': stats['packets_dropped'],
                'packets_total': stats['packets_total'],
                'timestamp': current_time
            }
        except Exception as e:
            logger.error(f"Error in check_for_attacks: {e}")

    def block_ip(self, ip_address, reason='manual', auto=False):
        """Add IP to blacklist map"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            ip_int = int(ip_obj)
            ip_bytes = ip_int.to_bytes(4, byteorder='little')
            key_hex = [f'{b:02x}' for b in ip_bytes]
            
            cmd = ['sudo', 'bpftool', 'map', 'update', 'name', 'blacklist',
                   'key', 'hex'] + key_hex + ['value', 'hex', '01']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                block_message = f'IP адрес {ip_address} заблокирован'
                if auto:
                    block_message += f' (автоматически: {reason})'
                else:
                    block_message += ' (вручную)'
                    
                self.event_logger.log_event(
                    event_type='BLOCK',
                    severity='WARNING',
                    ip_address=ip_address,
                    message=block_message,
                    details={
                        'method': 'auto' if auto else 'manual',
                        'reason': reason,
                        'interface': self.interface
                    }
                )
                return True
            return False
        except Exception as e:
            self.event_logger.log_event(
                event_type='SYSTEM',
                severity='CRITICAL',
                ip_address=ip_address,
                message=f'Ошибка при блокировке IP: {str(e)}',
                details={'error': str(e)}
            )
            return False

    def unblock_ip(self, ip_address):
        """Remove IP from blacklist map"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            ip_int = int(ip_obj)
            ip_bytes = ip_int.to_bytes(4, byteorder='little')
            key_hex = [f'{b:02x}' for b in ip_bytes]
            
            cmd = ['sudo', 'bpftool', 'map', 'delete', 'name', 'blacklist',
                   'key', 'hex'] + key_hex
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.event_logger.log_event(
                    event_type='UNBLOCK',
                    severity='INFO',
                    ip_address=ip_address,
                    message=f'IP адрес {ip_address} разблокирован',
                    details={'method': 'manual', 'interface': self.interface}
                )
                return True
            return True
        except:
            return False

    def get_blocked_ips(self):
        """Get list of blocked IPs from map"""
        try:
            result = subprocess.run(
                ['sudo', 'bpftool', 'map', 'dump', 'name', 'blacklist', '-j'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                ips = []
                for entry in data:
                    formatted = entry.get('formatted', {})
                    key = formatted.get('key') if formatted else entry.get('key')
                    if isinstance(key, int):
                        ip_addr = ipaddress.IPv4Address(key)
                        ips.append(str(ip_addr))
                return ips
            return []
        except:
            return []

    def clear_rate_limits(self):
        """Clear rate limiting counters"""
        try:
            self.event_logger.log_event(
                event_type='SYSTEM',
                severity='INFO',
                ip_address='N/A',
                message='Счетчики rate limit очищены',
                details={}
            )
            return True
        except:
            return False
    
    # ========== EVENT LOGGER METHODS ==========
    
    def get_events(self, limit=100, event_type=None, severity=None):
        """Получить события из event logger"""
        return self.event_logger.get_events(limit, event_type, severity)
    
    def get_event_stats(self):
        """Получить статистику событий"""
        return self.event_logger.get_stats()
    
    def get_events_raw(self, limit=100):
        """Получить события в сыром формате (как они хранятся)"""
        with self.event_logger.lock:
            events = list(self.event_logger.events)
        return list(reversed(events))[:limit]
    
    # ========== PACKET LOGGER METHODS ==========
    
    def get_packet_logs(self, limit=100, action=None, protocol=None):
        """Получить логи пакетов"""
        return self.packet_logger.get_packets(limit, action, protocol)
    
    def get_packet_stats(self):
        """Получить статистику логов пакетов"""
        return self.packet_logger.get_stats()
    
    def simulate_packet_logs(self):
        """
        Симуляция логов пакетов для тестирования.
        Удалить после интеграции с реальным eBPF.
        """
        import random
        
        protocols = ['TCP', 'UDP', 'ICMP']
        actions = ['PASS', 'DROP']
        
        # Генерируем 10 случайных пакетов
        for _ in range(10):
            src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            dst_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            protocol = random.choice(protocols)
            action = random.choice(actions)
            
            self.packet_logger.log_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=random.randint(1024, 65535) if protocol != 'ICMP' else None,
                dst_port=random.randint(1, 1024) if protocol != 'ICMP' else None,
                size=random.randint(64, 1500),
                action=action,
                reason='rate_limit' if action == 'DROP' else None
            )
            
            time.sleep(0.1)
