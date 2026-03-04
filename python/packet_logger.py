#!/usr/bin/env python3
"""
XDPGuard Packet Logger
Reads packet logs from eBPF ring buffer and stores them in memory
"""

import os
import sys
import time
import struct
import socket
import threading
from collections import deque
from datetime import datetime
from ctypes import *
import logging

logger = logging.getLogger(__name__)

# Protocol numbers
PROTOCOL_NAMES = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}

# XDP actions
ACTION_NAMES = {
    1: 'DROP',
    2: 'PASS',
}

# Drop reasons
REASON_NAMES = {
    0: 'normal',
    1: 'blacklist',
    2: 'rate_limit',
    3: 'syn_flood',
}

# TCP flags
TCP_FLAGS = {
    0x01: 'FIN',
    0x02: 'SYN',
    0x04: 'RST',
    0x08: 'PSH',
    0x10: 'ACK',
    0x20: 'URG',
}

class PacketLog:
    """Represents a single packet log entry"""
    
    def __init__(self, data):
        # Parse binary data from ring buffer
        # struct packet_log format:
        # __u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port,
        # __u8 protocol, __u8 action, __u8 reason, __u8 flags,
        # __u32 packet_size, __u64 timestamp
        
        if len(data) < 32:
            raise ValueError("Invalid packet log data size")
        
        # Unpack: 2 uint32, 2 uint16, 4 uint8, 1 uint32, 1 uint64
        unpacked = struct.unpack('=IIHH BBBB IQ', data[:32])
        
        self.src_ip = self._int_to_ip(unpacked[0])
        self.dst_ip = self._int_to_ip(unpacked[1])
        self.src_port = unpacked[2]
        self.dst_port = unpacked[3]
        self.protocol = unpacked[4]
        self.action = unpacked[5]
        self.reason = unpacked[6]
        self.flags = unpacked[7]
        self.packet_size = unpacked[8]
        self.timestamp_ns = unpacked[9]
        
        # Convert timestamp from nanoseconds to datetime
        self.timestamp = datetime.fromtimestamp(self.timestamp_ns / 1_000_000_000)
    
    @staticmethod
    def _int_to_ip(ip_int):
        """Convert integer IP to string format"""
        return socket.inet_ntoa(struct.pack('I', ip_int))
    
    def get_protocol_name(self):
        return PROTOCOL_NAMES.get(self.protocol, f'Unknown({self.protocol})')
    
    def get_action_name(self):
        return ACTION_NAMES.get(self.action, f'Unknown({self.action})')
    
    def get_reason_name(self):
        return REASON_NAMES.get(self.reason, f'Unknown({self.reason})')
    
    def get_tcp_flags_str(self):
        """Get human-readable TCP flags"""
        if self.protocol != 6:  # Not TCP
            return ''
        
        flags = []
        for bit, name in TCP_FLAGS.items():
            if self.flags & bit:
                flags.append(name)
        return ','.join(flags) if flags else '-'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.get_protocol_name(),
            'action': self.get_action_name(),
            'reason': self.get_reason_name(),
            'flags': self.get_tcp_flags_str(),
            'size': self.packet_size,
        }
    
    def __str__(self):
        flags_str = f" [{self.get_tcp_flags_str()}]" if self.protocol == 6 else ""
        return (f"{self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} | "
                f"{self.get_action_name():4s} | {self.src_ip:15s}:{self.src_port:<5d} -> "
                f"{self.dst_ip:15s}:{self.dst_port:<5d} | {self.get_protocol_name():4s}{flags_str} | "
                f"{self.packet_size:4d}B | {self.get_reason_name()}")


class PacketLogReader:
    """Reads packet logs from eBPF ring buffer"""
    
    def __init__(self, max_logs=10000):
        self.max_logs = max_logs
        self.logs = deque(maxlen=max_logs)
        self.stats = {
            'total': 0,
            'by_action': {'PASS': 0, 'DROP': 0},
            'by_protocol': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0},
            'by_reason': {'normal': 0, 'blacklist': 0, 'rate_limit': 0, 'syn_flood': 0},
        }
        self.running = False
        self.reader_thread = None
        self.bpf = None
        
        # Try to import BCC
        try:
            from bcc import BPF
            self.BPF = BPF
        except ImportError:
            logger.warning("BCC not available - packet logging disabled")
            self.BPF = None
    
    def start(self, xdp_prog_fd=None):
        """Start reading logs from ring buffer"""
        if self.BPF is None:
            logger.warning("Cannot start packet logger - BCC not available")
            return False
        
        self.running = True
        self.reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self.reader_thread.start()
        logger.info("Packet logger started")
        return True
    
    def stop(self):
        """Stop reading logs"""
        self.running = False
        if self.reader_thread:
            self.reader_thread.join(timeout=2)
        logger.info("Packet logger stopped")
    
    def _read_loop(self):
        """Main loop for reading from ring buffer"""
        # This is a simplified implementation
        # In production, we would use BCC's ring buffer API
        
        logger.info("Packet log reader loop started")
        
        # Simulated reading - in real implementation we'd use:
        # self.bpf["packet_logs"].open_ring_buffer(self._handle_packet)
        # self.bpf.ring_buffer_poll()
        
        while self.running:
            try:
                # In real implementation: poll ring buffer
                # For now, sleep to prevent busy loop
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error in packet log reader: {e}")
                time.sleep(1)
    
    def _handle_packet(self, cpu, data, size):
        """Callback for handling packet log from ring buffer"""
        try:
            log = PacketLog(data)
            self.add_log(log)
        except Exception as e:
            logger.error(f"Error parsing packet log: {e}")
    
    def add_log(self, log):
        """Add a packet log entry"""
        self.logs.append(log)
        
        # Update statistics
        self.stats['total'] += 1
        
        action = log.get_action_name()
        if action in self.stats['by_action']:
            self.stats['by_action'][action] += 1
        
        protocol = log.get_protocol_name()
        if protocol in self.stats['by_protocol']:
            self.stats['by_protocol'][protocol] += 1
        else:
            self.stats['by_protocol']['Other'] += 1
        
        reason = log.get_reason_name()
        if reason in self.stats['by_reason']:
            self.stats['by_reason'][reason] += 1
    
    def add_log_from_dict(self, log_dict):
        """Add a log entry from dictionary (for testing/manual addition)"""
        # Convert dict to binary format and create PacketLog
        # This is a helper for testing
        pass
    
    def get_logs(self, limit=100, filters=None):
        """Get recent logs with optional filtering"""
        logs = list(self.logs)
        
        # Apply filters
        if filters:
            if 'action' in filters:
                logs = [l for l in logs if l.get_action_name() == filters['action']]
            if 'protocol' in filters:
                logs = [l for l in logs if l.get_protocol_name() == filters['protocol']]
            if 'reason' in filters:
                logs = [l for l in logs if l.get_reason_name() == filters['reason']]
            if 'src_ip' in filters:
                logs = [l for l in logs if filters['src_ip'] in l.src_ip]
            if 'dst_ip' in filters:
                logs = [l for l in logs if filters['dst_ip'] in l.dst_ip]
        
        # Return most recent first, limited
        return [l.to_dict() for l in reversed(logs[-limit:])]
    
    def get_stats(self):
        """Get logging statistics"""
        return self.stats.copy()
    
    def clear(self):
        """Clear all logs"""
        self.logs.clear()
        self.stats = {
            'total': 0,
            'by_action': {'PASS': 0, 'DROP': 0},
            'by_protocol': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0},
            'by_reason': {'normal': 0, 'blacklist': 0, 'rate_limit': 0, 'syn_flood': 0},
        }
        logger.info("Packet logs cleared")


# Global instance
_packet_logger = None

def get_packet_logger():
    """Get global packet logger instance"""
    global _packet_logger
    if _packet_logger is None:
        _packet_logger = PacketLogReader()
    return _packet_logger


if __name__ == '__main__':
    # Test
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    reader = PacketLogReader()
    reader.start()
    
    # Simulate some logs for testing
    import random
    for i in range(20):
        # Create fake binary data
        src_ip = random.randint(0, 0xFFFFFFFF)
        dst_ip = random.randint(0, 0xFFFFFFFF)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 3389])
        protocol = random.choice([6, 17, 1])
        action = random.choice([1, 2])
        reason = random.choice([0, 1, 2])
        flags = random.randint(0, 0x3F) if protocol == 6 else 0
        size = random.randint(60, 1500)
        timestamp = int(time.time() * 1_000_000_000)
        
        data = struct.pack('=IIHH BBBB IQ',
                          src_ip, dst_ip, src_port, dst_port,
                          protocol, action, reason, flags,
                          size, timestamp)
        
        log = PacketLog(data)
        reader.add_log(log)
        print(log)
        time.sleep(0.1)
    
    print("\n" + "="*80)
    print("Statistics:")
    print(reader.get_stats())
    print(f"\nTotal logs: {len(reader.logs)}")
    
    reader.stop()
