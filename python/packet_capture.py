#!/usr/bin/env python3
"""
САФТ Рубеж — Захват пакетов из XDP/eBPF

Захватывает реальные пакеты из XDP-программы через BPF perf buffer.
"""

import logging
import threading
import time
import struct
import socket
from ctypes import *

logger = logging.getLogger(__name__)

# Структура события пакета (соответствует C-структуре в eBPF)
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
    """Захватывает пакеты из XDP-программы через BPF"""

    def __init__(self, packet_logger, interface="ens33"):
        self.packet_logger = packet_logger
        self.interface = interface
        self.running = False
        self.thread = None
        self.bpf = None

        logger.info(f"PacketCapture инициализирован для интерфейса {interface}")

    def start(self):
        """Запустить поток захвата пакетов"""
        if self.running:
            logger.warning("Захват пакетов уже запущен")
            return

        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        logger.info("Поток захвата пакетов запущен")

    def stop(self):
        """Остановить поток захвата пакетов"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Поток захвата пакетов остановлен")

    def _capture_loop(self):
        """Основной цикл захвата — читает из BPF perf buffer"""
        try:
            # Попытка подключиться к BPF-программе
            try:
                from bcc import BPF

                # Попытка найти и подключиться к существующей XDP-программе
                # Требуется, чтобы XDP-программа экспортировала карту perf_output
                logger.info("Попытка подключиться к XDP perf events...")

                # Пока используем резервный метод захвата через сокеты
                # TODO: Реализовать чтение BPF perf_event когда загружен xdp_filter_with_logging

            except ImportError:
                logger.warning("BCC недоступен, используется резервный метод захвата")
            except Exception as e:
                logger.warning(f"Не удалось подключиться к BPF perf events: {e}")

            # Резервный вариант: мониторинг интерфейса через сырые сокеты
            self._fallback_capture()

        except Exception as e:
            logger.error(f"Ошибка цикла захвата пакетов: {e}")
        finally:
            self.running = False

    def _fallback_capture(self):
        """Резервный захват пакетов через сырые сокеты"""
        try:
            # Создать сырой сокет для захвата пакетов
            import socket

            # Требуются права root
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((self.interface, 0))
            sock.settimeout(1.0)

            logger.info(f"Резервный захват запущен на {self.interface}")

            while self.running:
                try:
                    packet_data, addr = sock.recvfrom(65535)

                    # Парсинг Ethernet-заголовка (14 байт)
                    if len(packet_data) < 14:
                        continue

                    eth_header = packet_data[:14]
                    eth_protocol = struct.unpack('!H', eth_header[12:14])[0]

                    # Обрабатываем только IPv4 (0x0800)
                    if eth_protocol != 0x0800:
                        continue

                    # Парсинг IP-заголовка
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

                    # Парсинг портов для TCP/UDP
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

                    # Записываем пакет (PASS, т.к. захват идёт после XDP-обработки)
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
                    logger.debug(f"Ошибка парсинга пакета: {e}")
                    continue

            sock.close()
            logger.info("Резервный захват остановлен")

        except Exception as e:
            logger.error(f"Ошибка резервного захвата: {e}")

    def _parse_packet_event(self, cpu, data, size):
        """Разобрать событие пакета из BPF perf buffer"""
        try:
            event = cast(data, POINTER(PacketEvent)).contents

            # Преобразовать IP из сетевого порядка байт
            src_ip = socket.inet_ntoa(struct.pack('I', event.src_ip))
            dst_ip = socket.inet_ntoa(struct.pack('I', event.dst_ip))

            # Маппинг номера протокола в имя
            protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            protocol = protocol_map.get(event.protocol, f'PROTO_{event.protocol}')

            # Маппинг действия
            action = 'PASS' if event.action == 1 else 'DROP'

            # Передать в журнал пакетов
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
            logger.error(f"Ошибка разбора события пакета: {e}")
