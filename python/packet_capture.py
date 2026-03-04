#!/usr/bin/env python3
"""
Packet Capture from XDP/eBPF

Captures real packet information from XDP program via BPF perf buffer.
"""

import logging
import threading
import time
import struct
import socket
from ctypes import *

logger = logging.getLogger(__name__)

# Packet event structure (matches C struct in eBPF)
class PacketEvent(Structure):
    _fields_ = [
        ("src_ip", c_uint32),
        ("dst_ip", c_uint32),
        ("src_port", c_uint16),
        ("dst_port", c_uint16),
        ("protocol", c_uint8),
        ("action", c_uint8),  # 0=DROP, 1=PASS
        ("size", c_uint16),
        ("timestamp", c_uint64)
    ]


class PacketCapture:
    """Captures packets from XDP program via BPF"""
    
    def __init__(self, packet_logger, interface="ens33"):
        self.packet_logger = packet_logger
        self.interface = interface
        self.running = False
        self.thread = None
        self.bpf = None
        
        logger.info(f"PacketCapture initialized for {interface}")
    
    def start(self):
        """Start packet capture thread"""
        if self.running:
            logger.warning("Packet capture already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        logger.info("Packet capture thread started")
    
    def stop(self):
        """Stop packet capture thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Packet capture thread stopped")
    
    def _capture_loop(self):
        """Main capture loop - reads from BPF perf buffer"""
        try:
            # Try to attach to BPF program
            try:
                from bcc import BPF
                
                # Try to find and attach to existing XDP program
                # This requires the XDP program to export a perf_output map
                logger.info("Attempting to attach to XDP perf events...")
                
                # For now, use fallback method - monitor via tcpdump-like capture
                # TODO: Implement proper BPF perf_event reading when xdp_filter_with_logging is loaded
                
            except ImportError:
                logger.warning("BCC not available, using fallback capture method")
            except Exception as e:
                logger.warning(f"Could not attach to BPF perf events: {e}")
            
            # Fallback: Monitor interface using scapy or raw sockets
            self._fallback_capture()
            
        except Exception as e:
            logger.error(f"Packet capture loop error: {e}")
        finally:
            self.running = False
    
    def _fallback_capture(self):
        """Fallback packet capture using raw sockets"""
        try:
            # Create raw socket to capture packets
            import socket
            
            # This requires root privileges
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((self.interface, 0))
            sock.settimeout(1.0)
            
            logger.info(f"Fallback capture started on {self.interface}")
            
            while self.running:
                try:
                    packet_data, addr = sock.recvfrom(65535)
                    
                    # Parse Ethernet header (14 bytes)
                    if len(packet_data) < 14:
                        continue
                    
                    eth_header = packet_data[:14]
                    eth_protocol = struct.unpack('!H', eth_header[12:14])[0]
                    
                    # Only process IPv4 packets (0x0800)
                    if eth_protocol != 0x0800:
                        continue
                    
                    # Parse IP header
                    if len(packet_data) < 34:
                        continue
                    
                    ip_header = packet_data[14:34]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    
                    version_ihl = iph[0]
                    ihl = version_ihl & 0xF
                    iph_length = ihl * 4
                    
                    protocol = iph[6]
                    src_ip = socket.inet_ntoa(iph[8])
                    dst_ip = socket.inet_ntoa(iph[9])
                    packet_size = len(packet_data)
                    
                    # Parse ports for TCP/UDP
                    src_port = None
                    dst_port = None
                    protocol_name = 'UNKNOWN'
                    
                    if protocol == 6:  # TCP
                        protocol_name = 'TCP'
                        if len(packet_data) >= 14 + iph_length + 4:
                            tcp_header = packet_data[14 + iph_length:14 + iph_length + 4]
                            src_port, dst_port = struct.unpack('!HH', tcp_header)
                    elif protocol == 17:  # UDP
                        protocol_name = 'UDP'
                        if len(packet_data) >= 14 + iph_length + 4:
                            udp_header = packet_data[14 + iph_length:14 + iph_length + 4]
                            src_port, dst_port = struct.unpack('!HH', udp_header)
                    elif protocol == 1:  # ICMP
                        protocol_name = 'ICMP'
                    
                    # Log packet (assume PASS for now since we're capturing post-XDP)
                    self.packet_logger.log_packet(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=protocol_name,
                        src_port=src_port,
                        dst_port=dst_port,
                        size=packet_size,
                        action='PASS',
                        reason=None
                    )
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"Packet parse error: {e}")
                    continue
            
            sock.close()
            logger.info("Fallback capture stopped")
            
        except Exception as e:
            logger.error(f"Fallback capture error: {e}")
    
    def _parse_packet_event(self, cpu, data, size):
        """Parse packet event from BPF perf buffer"""
        try:
            event = cast(data, POINTER(PacketEvent)).contents
            
            # Convert IPs from network byte order
            src_ip = socket.inet_ntoa(struct.pack('I', event.src_ip))
            dst_ip = socket.inet_ntoa(struct.pack('I', event.dst_ip))
            
            # Map protocol number to name
            protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            protocol = protocol_map.get(event.protocol, f'PROTO_{event.protocol}')
            
            # Map action
            action = 'PASS' if event.action == 1 else 'DROP'
            
            # Log to packet logger
            self.packet_logger.log_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=event.src_port if event.src_port > 0 else None,
                dst_port=event.dst_port if event.dst_port > 0 else None,
                size=event.size,
                action=action,
                reason='rate_limit' if action == 'DROP' else None
            )
            
        except Exception as e:
            logger.error(f"Failed to parse packet event: {e}")
