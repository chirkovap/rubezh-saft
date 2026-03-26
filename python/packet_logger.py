#!/usr/bin/env python3
"""
Packet Logger for XDPGuard

Stores detailed information about every packet passing through the system.
"""

import time
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock
import logging
import socket
import struct
from typing import Optional

logger = logging.getLogger(__name__)


class PacketLogger:
    """
    Stores and manages detailed packet logs with filtering capabilities.
    Similar to event_logger but specialized for packet-level data.
    """

    def __init__(self, max_packets: int = 10000) -> None:
        """
        Initialize packet logger.

        Args:
            max_packets: Maximum number of packets to store in memory
        """
        self._packets: deque = deque(maxlen=max_packets)
        self._lock = Lock()
        self.max_packets = max_packets
        logger.info(f"PacketLogger initialized with max_packets={max_packets}")

    def log_packet(self, src_ip: str, dst_ip: str, protocol: str,
                   src_port: Optional[int] = None, dst_port: Optional[int] = None,
                   size: int = 0, action: str = "PASS",
                   reason: Optional[str] = None) -> None:
        """
        Log a single packet.

        Args:
            src_ip: Source IP address (string)
            dst_ip: Destination IP address (string)
            protocol: Protocol name (TCP/UDP/ICMP/OTHER)
            src_port: Source port (optional)
            dst_port: Destination port (optional)
            size: Packet size in bytes
            action: Action taken (PASS/DROP)
            reason: Reason for action (optional)
        """
        packet = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'size': size,
            'action': action,
            'reason': reason
        }

        with self._lock:
            self._packets.append(packet)

    def get_packets(self, limit: int = 100, action: Optional[str] = None,
                    protocol: Optional[str] = None) -> list:
        """
        Get packet logs with optional filtering.

        Args:
            limit: Maximum number of packets to return
            action: Filter by action (PASS/DROP)
            protocol: Filter by protocol (TCP/UDP/ICMP)

        Returns:
            List of packet dictionaries, newest first
        """
        with self._lock:
            # Iterate reversed deque directly — avoids an intermediate list copy
            packets = [
                p for p in reversed(self._packets)
                if (action is None or p['action'] == action)
                and (protocol is None or p['protocol'] == protocol)
            ]

        return packets[:limit]

    def get_stats(self) -> dict:
        """
        Get packet logging statistics.

        Returns:
            Dictionary with statistics
        """
        with self._lock:
            packets = list(self._packets)

        stats = {
            'total': len(packets),
            'by_action': defaultdict(int),
            'by_protocol': defaultdict(int),
            'recent_count': {
                'last_minute': 0,
                'last_hour': 0
            }
        }

        now = datetime.utcnow()
        one_minute_ago = now - timedelta(minutes=1)
        one_hour_ago = now - timedelta(hours=1)

        for packet in packets:
            # Count by action
            stats['by_action'][packet['action']] += 1

            # Count by protocol
            stats['by_protocol'][packet['protocol']] += 1

            # Count recent packets
            try:
                packet_time = datetime.fromisoformat(packet['timestamp'].replace('Z', '+00:00'))
                if packet_time.replace(tzinfo=None) >= one_minute_ago:
                    stats['recent_count']['last_minute'] += 1
                if packet_time.replace(tzinfo=None) >= one_hour_ago:
                    stats['recent_count']['last_hour'] += 1
            except ValueError:
                logger.error(f"Некорректный формат временной метки пакета: {packet.get('timestamp')}")

        # Convert defaultdict to regular dict
        stats['by_action'] = dict(stats['by_action'])
        stats['by_protocol'] = dict(stats['by_protocol'])

        return stats

    def clear(self) -> int:
        """
        Clear all packet logs.

        Returns:
            Number of packets cleared
        """
        with self._lock:
            count = len(self._packets)
            self._packets.clear()

        logger.info(f"Cleared {count} packet logs")
        return count

    def process_bpf_event(self, cpu: int, data: bytes, size: int) -> None:
        """
        Process packet event from BPF perf buffer.

        This is a callback function that will be called by BCC when
        a packet event is received from the eBPF program.

        Args:
            cpu: CPU number
            data: Raw packet data from BPF
            size: Size of data
        """
        try:
            # Parse the packet event structure
            # This structure should match the one defined in the eBPF program
            # Example structure (adjust based on your eBPF code):
            # struct packet_event {
            #     __u32 src_ip;
            #     __u32 dst_ip;
            #     __u16 src_port;
            #     __u16 dst_port;
            #     __u8 protocol;
            #     __u8 action;
            #     __u32 size;
            # };

            # Unpack data (adjust format string based on your structure)
            src_ip_int, dst_ip_int, src_port, dst_port, protocol_num, action_num, pkt_size = \
                struct.unpack('IIHHHBI', data[:20])

            # Convert IP addresses to string format
            src_ip = socket.inet_ntoa(struct.pack('I', src_ip_int))
            dst_ip = socket.inet_ntoa(struct.pack('I', dst_ip_int))

            # Map protocol number to name
            protocol_map = {
                6: 'TCP',
                17: 'UDP',
                1: 'ICMP'
            }
            protocol = protocol_map.get(protocol_num, 'OTHER')

            # Map action number to name
            action = 'PASS' if action_num == 0 else 'DROP'

            # Log the packet
            self.log_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port if src_port > 0 else None,
                dst_port=dst_port if dst_port > 0 else None,
                size=pkt_size,
                action=action
            )

        except Exception as e:
            logger.error(f"Failed to process BPF packet event: {e}")
