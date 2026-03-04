#!/usr/bin/env python3
"""
BPF Config Loader

Loads configuration from config.yaml into BPF maps.
This allows XDP program to read rate limits dynamically without recompilation.
"""

import logging
import subprocess
import ipaddress
import struct

logger = logging.getLogger(__name__)

# Configuration map keys (must match C code)
CFG_SYN_RATE = 0
CFG_UDP_RATE = 1
CFG_ICMP_RATE = 2
CFG_ENABLED = 3


def update_bpf_map_value(map_name, key, value):
    """Обновить значение в BPF map"""
    try:
        # Convert key and value to hex
        key_bytes = struct.pack('I', key)
        value_bytes = struct.pack('Q', value)
        
        key_hex = [f'{b:02x}' for b in key_bytes]
        value_hex = [f'{b:02x}' for b in value_bytes]
        
        cmd = ['sudo', 'bpftool', 'map', 'update', 'name', map_name,
               'key', 'hex'] + key_hex + ['value', 'hex'] + value_hex
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.debug(f"Updated {map_name}[{key}] = {value}")
            return True
        else:
            logger.error(f"Failed to update {map_name}: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error updating BPF map {map_name}: {e}")
        return False


def add_ip_to_whitelist(ip_address):
    """Добавить IP в whitelist map"""
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        ip_int = int(ip_obj)
        ip_bytes = ip_int.to_bytes(4, byteorder='little')
        key_hex = [f'{b:02x}' for b in ip_bytes]
        
        cmd = ['sudo', 'bpftool', 'map', 'update', 'name', 'whitelist',
               'key', 'hex'] + key_hex + ['value', 'hex', '01']
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"Added {ip_address} to whitelist")
            return True
        return False
    except Exception as e:
        logger.error(f"Error adding {ip_address} to whitelist: {e}")
        return False


def add_subnet_to_whitelist(subnet_str):
    """Добавить все IP из подсети в whitelist"""
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
        
        # For large subnets, only add first/last or use CIDR logic in XDP
        # For now, add up to 256 IPs max to avoid overloading
        count = 0
        max_ips = 256
        
        for ip in network.hosts():
            if count >= max_ips:
                logger.warning(f"Whitelist limit reached for {subnet_str}, added {count} IPs")
                break
            add_ip_to_whitelist(str(ip))
            count += 1
        
        # Also add network and broadcast addresses
        add_ip_to_whitelist(str(network.network_address))
        add_ip_to_whitelist(str(network.broadcast_address))
        
        logger.info(f"Added {count + 2} IPs from {subnet_str} to whitelist")
        return True
    except Exception as e:
        logger.error(f"Error adding subnet {subnet_str} to whitelist: {e}")
        return False


def load_config_to_bpf(config):
    """Загрузить rate limits из config.yaml в BPF config_map"""
    try:
        logger.info("Загрузка конфигурации в BPF maps...")
        
        # Get rate limits from config
        syn_rate = config.get('protection.syn_rate', 1000)
        udp_rate = config.get('protection.udp_rate', 500)
        icmp_rate = config.get('protection.icmp_rate', 100)
        enabled = 1 if config.get('protection.enabled', True) else 0
        
        # Update config_map
        success = True
        success &= update_bpf_map_value('config_map', CFG_SYN_RATE, syn_rate)
        success &= update_bpf_map_value('config_map', CFG_UDP_RATE, udp_rate)
        success &= update_bpf_map_value('config_map', CFG_ICMP_RATE, icmp_rate)
        success &= update_bpf_map_value('config_map', CFG_ENABLED, enabled)
        
        if success:
            logger.info(f"✓ Конфигурация загружена: SYN={syn_rate}, UDP={udp_rate}, ICMP={icmp_rate}, enabled={enabled}")
        else:
            logger.error("Ошибка при загрузке конфигурации в BPF")
        
        return success
    except Exception as e:
        logger.error(f"Ошибка при загрузке конфига в BPF: {e}")
        return False


def load_whitelist_to_bpf(config):
    """Загрузить whitelist из config.yaml в BPF whitelist_map"""
    try:
        logger.info("Загрузка whitelist в BPF map...")
        
        whitelist_ips = config.get('whitelist_ips', [])
        if not whitelist_ips:
            logger.warning("Whitelist пуст, никакие IP не защищены")
            return True
        
        count = 0
        for ip_str in whitelist_ips:
            ip_str = ip_str.strip()
            
            # Check if CIDR notation (subnet)
            if '/' in ip_str:
                if add_subnet_to_whitelist(ip_str):
                    count += 1
            else:
                # Single IP
                if add_ip_to_whitelist(ip_str):
                    count += 1
        
        logger.info(f"✓ Загружено {count} записей в whitelist")
        return True
    except Exception as e:
        logger.error(f"Ошибка при загрузке whitelist в BPF: {e}")
        return False


def update_bpf_config(config):
    """
    Обновить все BPF maps из конфигурации.
    Вызывать после загрузки XDP программы.
    """
    try:
        logger.info("="*60)
        logger.info("Обновление BPF конфигурации из config.yaml...")
        logger.info("="*60)
        
        # Load rate limits
        config_success = load_config_to_bpf(config)
        
        # Load whitelist
        whitelist_success = load_whitelist_to_bpf(config)
        
        if config_success and whitelist_success:
            logger.info("="*60)
            logger.info("✓ BPF конфигурация успешно обновлена")
            logger.info("="*60)
            return True
        else:
            logger.error("Не удалось полностью обновить BPF конфигурацию")
            return False
    except Exception as e:
        logger.error(f"Критическая ошибка при обновлении BPF конфига: {e}")
        return False
