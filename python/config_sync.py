#!/usr/bin/env python3
"""
Configuration Synchronization Module

Syncs config.yaml values to XDP BPF maps in real-time.
This allows dynamic rate limit changes without XDP recompilation.
"""

import logging
import subprocess
import struct
import ipaddress

logger = logging.getLogger(__name__)

# Config map keys (must match xdp_filter.c)
CFG_SYN_RATE = 0
CFG_UDP_RATE = 1
CFG_ICMP_RATE = 2
CFG_ENABLED = 3


class ConfigSync:
    """Synchronizes YAML config to XDP BPF maps"""
    
    def __init__(self):
        logger.info("ConfigSync initialized")
    
    def sync_config_to_xdp(self, config):
        """
        Synchronize config.yaml values to XDP config_map
        
        This updates BPF maps so XDP uses new rate limits immediately
        without requiring recompilation or reload.
        """
        try:
            # Get rate limits from config
            syn_rate = config.get('protection.syn_rate', 1000)
            udp_rate = config.get('protection.udp_rate', 500)
            icmp_rate = config.get('protection.icmp_rate', 100)
            enabled = 1 if config.get('protection.enabled', True) else 0
            
            logger.info(f"Syncing config: SYN={syn_rate}, UDP={udp_rate}, ICMP={icmp_rate}, Enabled={enabled}")
            
            # Update config_map with new values
            success = True
            success &= self._update_config_value(CFG_SYN_RATE, syn_rate)
            success &= self._update_config_value(CFG_UDP_RATE, udp_rate)
            success &= self._update_config_value(CFG_ICMP_RATE, icmp_rate)
            success &= self._update_config_value(CFG_ENABLED, enabled)
            
            if success:
                logger.info("✓ Rate limits synced to XDP successfully")
            else:
                logger.warning("⚠ Some config values failed to sync")
            
            # Sync whitelist
            if self._sync_whitelist(config):
                logger.info("✓ Whitelist synced to XDP")
            else:
                logger.warning("⚠ Whitelist sync failed")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to sync config to XDP: {e}")
            return False
    
    def _update_config_value(self, key, value):
        """
        Update a single config_map entry using bpftool
        
        Args:
            key: Config map key (0-3)
            value: Value to set (integer)
        """
        try:
            # Convert key to hex
            key_hex = [f'{b:02x}' for b in struct.pack('I', key)]
            
            # Convert value to 64-bit unsigned integer (little endian)
            value_bytes = struct.pack('<Q', int(value))
            value_hex = [f'{b:02x}' for b in value_bytes]
            
            # Update map using bpftool
            cmd = ['sudo', 'bpftool', 'map', 'update', 'name', 'config_map',
                   'key', 'hex'] + key_hex + ['value', 'hex'] + value_hex
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                logger.debug(f"Config key {key} = {value} updated")
                return True
            else:
                logger.error(f"Failed to update config key {key}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating config key {key}: {e}")
            return False
    
    def _sync_whitelist(self, config):
        """
        Sync whitelist IPs from config to XDP whitelist map
        """
        try:
            whitelist_ips = config.get('whitelist_ips', [])
            
            if not whitelist_ips:
                logger.info("No whitelist IPs to sync")
                return True
            
            success_count = 0
            for ip_str in whitelist_ips:
                try:
                    # Handle CIDR notation
                    if '/' in ip_str:
                        network = ipaddress.ip_network(ip_str, strict=False)
                        # Add all IPs in network (limited to reasonable size)
                        if network.num_addresses > 256:
                            logger.warning(f"Network {ip_str} too large, skipping")
                            continue
                        
                        for ip in network.hosts():
                            if self._add_whitelist_ip(str(ip)):
                                success_count += 1
                    else:
                        # Single IP
                        if self._add_whitelist_ip(ip_str):
                            success_count += 1
                            
                except Exception as e:
                    logger.error(f"Failed to parse whitelist IP {ip_str}: {e}")
                    continue
            
            logger.info(f"Added {success_count} IPs to whitelist")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Failed to sync whitelist: {e}")
            return False
    
    def _add_whitelist_ip(self, ip_address):
        """
        Add a single IP to whitelist map
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            ip_int = int(ip_obj)
            ip_bytes = ip_int.to_bytes(4, byteorder='little')
            key_hex = [f'{b:02x}' for b in ip_bytes]
            
            cmd = ['sudo', 'bpftool', 'map', 'update', 'name', 'whitelist',
                   'key', 'hex'] + key_hex + ['value', 'hex', '01']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                logger.debug(f"Whitelisted IP: {ip_address}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to whitelist IP {ip_address}: {e}")
            return False
    
    def verify_sync(self, config):
        """
        Verify that config values match XDP map values
        """
        try:
            # Dump config_map
            result = subprocess.run(
                ['sudo', 'bpftool', 'map', 'dump', 'name', 'config_map', '-j'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode != 0:
                logger.warning("Could not verify config sync")
                return False
            
            import json
            map_data = json.loads(result.stdout)
            
            # Check each config value
            expected = {
                CFG_SYN_RATE: config.get('protection.syn_rate', 1000),
                CFG_UDP_RATE: config.get('protection.udp_rate', 500),
                CFG_ICMP_RATE: config.get('protection.icmp_rate', 100),
                CFG_ENABLED: 1 if config.get('protection.enabled', True) else 0
            }
            
            for entry in map_data:
                key = entry.get('key')
                value = entry.get('value')
                
                if isinstance(key, list) and len(key) == 4:
                    # Convert key from byte array
                    key_int = struct.unpack('I', bytes(key))[0]
                    
                    if key_int in expected:
                        if isinstance(value, list) and len(value) == 8:
                            # Convert value from byte array (64-bit)
                            value_int = struct.unpack('<Q', bytes(value))[0]
                            
                            if value_int != expected[key_int]:
                                logger.warning(f"Config mismatch: key={key_int}, expected={expected[key_int]}, got={value_int}")
                                return False
            
            logger.info("✓ Config verification passed")
            return True
            
        except Exception as e:
            logger.error(f"Config verification failed: {e}")
            return False
    
    def clear_whitelist(self):
        """
        Clear all entries from whitelist map
        """
        try:
            # Get all keys from whitelist
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
                    cmd = ['sudo', 'bpftool', 'map', 'delete', 'name', 'whitelist',
                           'key', 'hex'] + key_hex
                    subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            logger.info("Whitelist cleared")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear whitelist: {e}")
            return False
