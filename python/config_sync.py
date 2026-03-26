#!/usr/bin/env python3
"""
Модуль синхронизации конфигурации

Синхронизирует значения config.yaml с XDP BPF maps в реальном времени.
Позволяет динамически изменять лимиты трафика без перекомпиляции XDP.
"""

import logging
import subprocess
import struct
import ipaddress

logger = logging.getLogger(__name__)

# Ключи карты конфигурации (должны совпадать с xdp_filter.c)
CFG_SYN_RATE  = 0
CFG_UDP_RATE  = 1
CFG_ICMP_RATE = 2
CFG_ENABLED   = 3


class ConfigSync:
    """Синхронизирует YAML-конфигурацию с XDP BPF maps"""

    def __init__(self):
        logger.info("ConfigSync инициализирован")

    def sync_config_to_xdp(self, config):
        """
        Синхронизировать значения config.yaml с XDP config_map.
        Обновляет BPF maps без перекомпиляции или перезагрузки программы.
        """
        try:
            syn_rate  = config.get('protection.syn_rate',  1000)
            udp_rate  = config.get('protection.udp_rate',  500)
            icmp_rate = config.get('protection.icmp_rate', 100)
            enabled   = 1 if config.get('protection.enabled', True) else 0

            logger.info(f"Синхронизация конфигурации: SYN={syn_rate}, UDP={udp_rate}, ICMP={icmp_rate}, Включено={enabled}")

            success  = True
            success &= self._update_config_value(CFG_SYN_RATE,  syn_rate)
            success &= self._update_config_value(CFG_UDP_RATE,  udp_rate)
            success &= self._update_config_value(CFG_ICMP_RATE, icmp_rate)
            success &= self._update_config_value(CFG_ENABLED,   enabled)

            if success:
                logger.info("\u2713 Лимиты успешно синхронизированы с XDP")
            else:
                logger.warning("\u26a0 Некоторые значения конфигурации не удалось синхронизировать")

            if self._sync_whitelist(config):
                logger.info("\u2713 Белый список синхронизирован с XDP")
            else:
                logger.warning("\u26a0 Синхронизация белого списка не удалась")

            return success

        except Exception as e:
            logger.error(f"Не удалось синхронизировать конфигурацию с XDP: {e}")
            return False

    def _update_config_value(self, key, value):
        """Обновить одну запись в config_map через bpftool."""
        try:
            # Преобразовать ключ в hex
            key_hex = [f'{b:02x}' for b in struct.pack('I', key)]
            # Преобразовать значение в 64-битное беззнаковое (little-endian)
            value_bytes = struct.pack('<Q', int(value))
            value_hex   = [f'{b:02x}' for b in value_bytes]

            cmd = (['sudo', 'bpftool', 'map', 'update', 'name', 'config_map',
                    'key', 'hex'] + key_hex + ['value', 'hex'] + value_hex)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                logger.debug(f"Ключ конфигурации {key} = {value} обновлён")
                return True
            else:
                logger.error(f"Не удалось обновить ключ {key}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Ошибка при обновлении ключа {key}: {e}")
            return False

    def _sync_whitelist(self, config):
        """Синхронизировать IP-адреса белого списка с картой XDP whitelist."""
        try:
            whitelist_ips = config.get('whitelist_ips', [])
            if not whitelist_ips:
                logger.info("IP-адреса для белого списка отсутствуют")
                return True

            success_count = 0
            for ip_str in whitelist_ips:
                try:
                    if '/' in ip_str:
                        # Обработать CIDR-нотацию
                        network = ipaddress.ip_network(ip_str, strict=False)
                        if network.num_addresses > 256:
                            logger.warning(f"Сеть {ip_str} слишком большая, пропускается")
                            continue
                        for ip in network.hosts():
                            if self._add_whitelist_ip(str(ip)):
                                success_count += 1
                    else:
                        if self._add_whitelist_ip(ip_str):
                            success_count += 1
                except Exception as e:
                    logger.error(f"Не удалось обработать IP белого списка {ip_str}: {e}")
                    continue

            logger.info(f"Добавлено {success_count} IP-адресов в белый список")
            return success_count > 0
        except Exception as e:
            logger.error(f"Не удалось синхронизировать белый список: {e}")
            return False

    def _add_whitelist_ip(self, ip_address):
        """Добавить один IP-адрес в карту белого списка."""
        try:
            ip_obj   = ipaddress.ip_address(ip_address)
            ip_bytes = int(ip_obj).to_bytes(4, byteorder='little')
            key_hex  = [f'{b:02x}' for b in ip_bytes]

            cmd = (['sudo', 'bpftool', 'map', 'update', 'name', 'whitelist',
                    'key', 'hex'] + key_hex + ['value', 'hex', '01'])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                logger.debug(f"IP добавлен в белый список: {ip_address}")
                return True
            return False
        except Exception as e:
            logger.error(f"Не удалось добавить IP в белый список {ip_address}: {e}")
            return False

    def verify_sync(self, config):
        """Проверить соответствие значений конфигурации и XDP map."""
        try:
            result = subprocess.run(
                ['sudo', 'bpftool', 'map', 'dump', 'name', 'config_map', '-j'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                logger.warning("Не удалось проверить синхронизацию конфигурации")
                return False

            import json
            map_data = json.loads(result.stdout)

            expected = {
                CFG_SYN_RATE:  config.get('protection.syn_rate',  1000),
                CFG_UDP_RATE:  config.get('protection.udp_rate',  500),
                CFG_ICMP_RATE: config.get('protection.icmp_rate', 100),
                CFG_ENABLED:   1 if config.get('protection.enabled', True) else 0
            }

            for entry in map_data:
                key   = entry.get('key')
                value = entry.get('value')
                if isinstance(key, list) and len(key) == 4:
                    key_int = struct.unpack('I', bytes(key))[0]
                    if key_int in expected:
                        if isinstance(value, list) and len(value) == 8:
                            value_int = struct.unpack('<Q', bytes(value))[0]
                            if value_int != expected[key_int]:
                                logger.warning(
                                    f"Несоответствие конфигурации: ключ={key_int}, "
                                    f"ожидалось={expected[key_int]}, получено={value_int}"
                                )
                                return False

            logger.info("\u2713 Проверка конфигурации пройдена")
            return True
        except Exception as e:
            logger.error(f"Проверка конфигурации завершилась с ошибкой: {e}")
            return False

    def clear_whitelist(self):
        """Очистить все записи в карте белого списка."""
        try:
            result = subprocess.run(
                ['sudo', 'bpftool', 'map', 'dump', 'name', 'whitelist', '-j'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return False

            import json
            map_data = json.loads(result.stdout)

            for entry in map_data:
                key = entry.get('key')
                if isinstance(key, list) and len(key) == 4:
                    key_hex = [f'{b:02x}' for b in key]
                    cmd = (['sudo', 'bpftool', 'map', 'delete', 'name', 'whitelist',
                            'key', 'hex'] + key_hex)
                    subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            logger.info("Белый список очищен")
            return True
        except Exception as e:
            logger.error(f"Не удалось очистить белый список: {e}")
            return False
