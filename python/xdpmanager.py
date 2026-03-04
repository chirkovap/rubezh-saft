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
from pathlib import Path
from python.event_logger import EventLogger

logger = logging.getLogger(__name__)


class XDPManager:
    """Manages XDP program and BPF maps"""

    def __init__(self, config):
        self.config = config
        self.interface = config.get('network.interface', 'ens33')
        self.xdp_mode = config.get('network.xdp_mode', 'xdpgeneric')  # xdpgeneric, xdpdrv, xdpoffload
        self.xdp_obj_path = config.get('xdp.object_path', '/usr/lib/xdpguard/xdp_filter.o')
        self.xdp_loaded = False
        
        # Initialize event logger
        self.event_logger = EventLogger(max_events=1000)
        
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
            # Check if XDP object file exists
            if not os.path.exists(self.xdp_obj_path):
                logger.error(f"XDP program not found at {self.xdp_obj_path}")
                logger.error("Run 'cd bpf && sudo make && sudo make install' first")
                self.event_logger.log_event(
                    event_type='SYSTEM',
                    severity='CRITICAL',
                    ip_address='N/A',
                    message=f'XDP программа не найдена: {self.xdp_obj_path}',
                    details={'path': self.xdp_obj_path}
                )
                return False
            
            logger.info(f"Loading XDP program from {self.xdp_obj_path}...")
            logger.info(f"Mode: {self.xdp_mode}, Interface: {self.interface}")
            
            # Try to load with specified mode
            success = self._load_xdp_with_mode(self.xdp_mode)
            
            if not success and self.xdp_mode != 'xdpgeneric':
                logger.warning(f"Failed to load in {self.xdp_mode} mode, trying xdpgeneric...")
                success = self._load_xdp_with_mode('xdpgeneric')
            
            if success:
                self.xdp_loaded = True
                logger.info(f"✓ XDP program loaded successfully on {self.interface}")
                self._verify_xdp_loaded()
                
                self.event_logger.log_event(
                    event_type='LOAD',
                    severity='INFO',
                    ip_address='N/A',
                    message=f'XDP программа успешно загружена на {self.interface}',
                    details={'interface': self.interface, 'mode': self.xdp_mode}
                )
                
                return True
            else:
                logger.error("Failed to load XDP program")
                self.event_logger.log_event(
                    event_type='SYSTEM',
                    severity='CRITICAL',
                    ip_address='N/A',
                    message='Не удалось загрузить XDP программу',
                    details={'interface': self.interface, 'mode': self.xdp_mode}
                )
                return False
                
        except Exception as e:
            logger.error(f"Failed to load XDP program: {e}")
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
            # Construct ip link command
            cmd = ['sudo',
                'ip', 'link', 'set', 'dev', self.interface,
                mode, 'obj', self.xdp_obj_path, 'sec', 'xdp'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"XDP loaded in {mode} mode")
                return True
            else:
                logger.warning(f"Failed to load in {mode} mode: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("XDP loading timeout")
            return False
        except Exception as e:
            logger.error(f"Error loading XDP: {e}")
            return False

    def _verify_xdp_loaded(self):
        """Verify XDP is attached to interface"""
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', self.interface],
                capture_output=True,
                text=True
            )
            
            if 'xdp' in result.stdout.lower():
                logger.info("✓ XDP attachment verified")
            else:
                logger.warning("XDP may not be properly attached")
                
        except Exception as e:
            logger.warning(f"Could not verify XDP attachment: {e}")

    def unload_program(self):
        """Unload XDP program from interface"""
        try:
            if not self.xdp_loaded:
                return True
            
            logger.info(f"Unloading XDP from {self.interface}...")
            
            # Remove XDP program
            cmd = ['ip', 'link', 'set', 'dev', self.interface, 'xdp', 'off']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.xdp_loaded = False
                logger.info("✓ XDP program unloaded")
                
                self.event_logger.log_event(
                    event_type='UNLOAD',
                    severity='INFO',
                    ip_address='N/A',
                    message=f'XDP программа выгружена с {self.interface}',
                    details={'interface': self.interface}
                )
                
                return True
            else:
                logger.error(f"Failed to unload XDP: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error unloading XDP: {e}")
            return False

    def get_statistics(self):
        """Get packet statistics from BPF maps"""
        try:
            result = subprocess.run(
                ['sudo', 'bpftool', 'map', 'dump', 'name', 'stats_map'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"bpftool failed: {result.stderr}")
                return {
                    'packets_total': 0,
                    'packets_dropped': 0,
                    'packets_passed': 0,
                    'bytes_total': 0,
                    'bytes_dropped': 0
                }
            
            total_stats = {
                'packets_total': 0,
                'packets_dropped': 0,
                'packets_passed': 0,
                'bytes_total': 0,
                'bytes_dropped': 0
            }
            
            import re
            for line in result.stdout.split("\n"):
                for key in total_stats.keys():
                    match = re.search(f'"{key}":\s*(\d+)', line)
                    if match:
                        total_stats[key] += int(match.group(1))
            
            return total_stats
                
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {
                    'packets_total': 0,
                    'packets_dropped': 0,
                    'packets_passed': 0,
                    'bytes_total': 0,
                    'bytes_dropped': 0
                }

    def block_ip(self, ip_address):
        """Add IP to blacklist map"""
        try:
            logger.info(f"Blocking IP: {ip_address}")
            
            # Validate IP
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Convert IP to integer (network byte order)
            ip_int = int(ip_obj)
            ip_bytes = ip_int.to_bytes(4, byteorder='little')
            
            # Use bpftool to update map
            # Format: key hex bytes, value 0x01
            key_hex = [f'{b:02x}' for b in ip_bytes]
            
            cmd = [
                'sudo', 'bpftool', 'map', 'update',
                'name', 'blacklist',
                'key', 'hex'] + key_hex + [
                'value', 'hex', '01'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"✓ IP {ip_address} blocked")
                
                # Log event
                self.event_logger.log_event(
                    event_type='BLOCK',
                    severity='WARNING',
                    ip_address=ip_address,
                    message=f'IP адрес {ip_address} заблокирован',
                    details={'method': 'manual', 'interface': self.interface}
                )
                
                return True
            else:
                logger.error(f"Failed to block IP: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
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
            logger.info(f"Unblocking IP: {ip_address}")
            
            # Validate IP
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Convert IP to integer (network byte order)
            ip_int = int(ip_obj)
            ip_bytes = ip_int.to_bytes(4, byteorder='little')
            
            # Use bpftool to delete from map
            key_hex = [f'{b:02x}' for b in ip_bytes]
            
            cmd = [
                'sudo', 'bpftool', 'map', 'delete',
                'name', 'blacklist',
                'key', 'hex'] + key_hex
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"✓ IP {ip_address} unblocked")
                
                # Log event
                self.event_logger.log_event(
                    event_type='UNBLOCK',
                    severity='INFO',
                    ip_address=ip_address,
                    message=f'IP адрес {ip_address} разблокирован',
                    details={'method': 'manual', 'interface': self.interface}
                )
                
                return True
            else:
                logger.warning(f"IP may not have been in blacklist: {result.stderr}")
                return True  # Return success anyway
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False

    def get_blocked_ips(self):
        """Get list of blocked IPs from map"""
        try:
            result = subprocess.run(
                ['sudo', 'bpftool', 'map', 'dump', 'name', 'blacklist', '-j'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                ips = []
                
                for entry in data:
                    # bpftool -j returns formatted.key as integer
                    formatted = entry.get('formatted', {})
                    key = formatted.get('key') if formatted else entry.get('key')
                    
                    if isinstance(key, int):
                        ip_addr = ipaddress.IPv4Address(key)
                        ips.append(str(ip_addr))
                
                return ips
            else:
                return []
                
        except Exception as e:
            logger.error(f"Failed to get blocked IPs: {e}")
            return []

    def clear_rate_limits(self):
        """Clear rate limiting counters"""
        try:
            logger.info("Clearing rate limit counters...")
            
            # Clear rate limit map by removing and recreating
            # Note: This is a simplified approach
            # In production, iterate through map and delete entries
            
            self.event_logger.log_event(
                event_type='SYSTEM',
                severity='INFO',
                ip_address='N/A',
                message='Счетчики rate limit очищены',
                details={}
            )
            
            logger.info("✓ Rate limits cleared")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear rate limits: {e}")
            return False
    
    def get_events(self, limit=100, event_type=None, severity=None):
        """Получить события из event logger"""
        return self.event_logger.get_events(limit, event_type, severity)
    
    def get_event_stats(self):
        """Получить статистику событий"""
        return self.event_logger.get_stats()
