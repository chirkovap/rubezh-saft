#!/usr/bin/env python3
"""
XDP-менеджер САФТ Рубеж

Управляет загрузкой XDP-программы и взаимодействием с BPF-картами.
Использует предварительно скомпилированные объектные файлы XDP.
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
from python.packet_capture import PacketCapture
from python.config_sync import ConfigSync

logger = logging.getLogger(__name__)


class XDPManager:
    """Управляет XDP-программой и BPF-картами"""

    def __init__(self, config):
        self.config = config
        self.interface = config.get('network.interface', 'ens33')
        self.xdp_mode = config.get('network.xdp_mode', 'xdpgeneric')
        self.xdp_obj_path = config.get('xdp.object_path', '/usr/lib/rubezh-saft/xdp_filter.o')
        self.xdp_loaded = False

        # Инициализация синхронизатора конфигурации
        self.config_sync = ConfigSync()

        # Инициализация журнала событий
        self.event_logger = EventLogger(max_events=1000)

        # Инициализация журнала пакетов
        max_packets = config.get('logging.max_packets', 10000)
        self.packet_logger = PacketLogger(max_packets=max_packets)

        # Инициализация захвата пакетов (если включено)
        self.packet_capture = None
        if config.get('logging.enable_packet_logging', False):
            self.packet_capture = PacketCapture(
                packet_logger=self.packet_logger,
                interface=self.interface
            )
            logger.info("PacketCapture инициализирован, будет запущен после загрузки XDP")

        # Хранение предыдущей статистики для расчёта дельты
        self.prev_stats = {
            'packets_dropped': 0,
            'packets_total': 0,
            'timestamp': time.time()
        }

        logger.info(f"XDP-менеджер инициализирован для интерфейса {self.interface}")
        self.event_logger.log_event(
            event_type='SYSTEM',
            severity='INFO',
            ip_address='N/A',
            message=f'САФТ Рубеж инициализирован для интерфейса {self.interface}',
            details={'interface': self.interface, 'mode': self.xdp_mode}
        )

    def load_program(self):
        """Загрузить XDP-программу на интерфейс через ip link"""
        try:
            if not os.path.exists(self.xdp_obj_path):
                logger.error(f"XDP-программа не найдена по пути {self.xdp_obj_path}")
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

                # CRITICAL: Sync config to XDP immediately after loading
                logger.info("Синхронизация конфигурации с XDP...")
                if self.config_sync.sync_config_to_xdp(self.config):
                    logger.info("✓ Конфигурация применена к XDP")

                    # Verify sync
                    if self.config_sync.verify_sync(self.config):
                        logger.info("✓ Конфигурация проверена и корректна")
                    else:
                        logger.warning("⚠ Конфигурация может быть применена неполностью")
                else:
                    logger.warning("⚠ Не удалось синхронизировать конфигурацию с XDP")

                # Start packet capture if enabled
                if self.packet_capture:
                    try:
                        self.packet_capture.start()
                        logger.info("✓ Захват пакетов запущен")
                        self.event_logger.log_event(
                            event_type='SYSTEM',
                            severity='INFO',
                            ip_address='N/A',
                            message='Захват пакетов запущен',
                            details={'interface': self.interface}
                        )
                    except Exception as e:
                        logger.error(f"Не удалось запустить захват пакетов: {e}")
                        self.event_logger.log_event(
                            event_type='SYSTEM',
                            severity='WARNING',
                            ip_address='N/A',
                            message=f'Не удалось запустить захват пакетов: {str(e)}',
                            details={'error': str(e)}
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
        """Загрузить XDP в указанном режиме"""
        try:
            cmd = ['sudo', 'ip', 'link', 'set', 'dev', self.interface,
                mode, 'obj', self.xdp_obj_path, 'sec', 'xdp']

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def reload_config(self):
        """Reload configuration and sync to XDP (without recompiling)"""
        try:
            logger.info("Перезагрузка конфигурации...")

            # Reload config from file
            self.config.reload()

            # Sync to XDP
            if self.config_sync.sync_config_to_xdp(self.config):
                self.event_logger.log_event(
                    event_type='SYSTEM',
                    severity='INFO',
                    ip_address='N/A',
                    message='Конфигурация перезагружена и применена',
                    details={}
                )
                return True
            return False

        except Exception as e:
            logger.error(f"Не удалось перезагрузить конфигурацию: {e}")
            return False

    def unload_program(self):
        """Выгрузить XDP-программу с интерфейса"""
        try:
            # Сначала остановить захват пакетов
            if self.packet_capture:
                try:
                    self.packet_capture.stop()
                    logger.info("Захват пакетов остановлен")
                except Exception:
                    pass

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
        except Exception:
            return False

    def get_statistics(self):
        """Получить статистику пакетов из BPF-карт"""
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
                    match = re.search(rf'"{key}":\s*(\d+)', line)
                    if match:
                        total_stats[key] += int(match.group(1))

            return total_stats
        except Exception:
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
            logger.error(f"Ошибка при проверке атак: {e}")

    def block_ip(self, ip_address, reason='manual', auto=False):
        """Добавить IP в карту чёрного списка"""
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
        """Удалить IP из карты чёрного списка"""
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
        except Exception:
            return False

    def get_blocked_ips(self):
        """Получить список заблокированных IP из карты"""
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
        except Exception:
            return []

    def clear_rate_limits(self):
        """Очистить счётчики rate limit"""
        try:
            self.event_logger.log_event(
                event_type='SYSTEM',
                severity='INFO',
                ip_address='N/A',
                message='Счетчики rate limit очищены',
                details={}
            )
            return True
        except Exception:
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
