#!/usr/bin/env python3
"""
САФТ Рубеж — Журнал пакетов

Хранит подробную информацию о каждом пакете, проходящем через систему.
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
    Хранит и управляет детальными логами пакетов с возможностью фильтрации.
    Аналогично event_logger, но специализирован для данных уровня пакетов.
    """

    def __init__(self, max_packets: int = 10000) -> None:
        """
        Инициализировать журнал пакетов.

        Args:
            max_packets: Максимальное количество пакетов в памяти
        """
        self._packets: deque = deque(maxlen=max_packets)
        self._lock = Lock()
        self.max_packets = max_packets
        logger.info(f"PacketLogger инициализирован (max_packets={max_packets})")

    def log_packet(self, src_ip: str, dst_ip: str, protocol: str,
                   src_port: Optional[int] = None, dst_port: Optional[int] = None,
                   size: int = 0, action: str = "PASS",
                   reason: Optional[str] = None) -> None:
        """
        Записать один пакет в журнал.

        Args:
            src_ip: IP-адрес источника (строка)
            dst_ip: IP-адрес назначения (строка)
            protocol: Имя протокола (TCP/UDP/ICMP/OTHER)
            src_port: Порт источника (опционально)
            dst_port: Порт назначения (опционально)
            size: Размер пакета в байтах
            action: Выполненное действие (PASS/DROP)
            reason: Причина действия (опционально)
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
        Получить логи пакетов с опциональной фильтрацией.

        Args:
            limit: Максимальное количество возвращаемых пакетов
            action: Фильтр по действию (PASS/DROP)
            protocol: Фильтр по протоколу (TCP/UDP/ICMP)

        Returns:
            Список словарей пакетов, новые первыми
        """
        with self._lock:
            # Итерация по перевёрнутой deque — избегаем промежуточной копии
            packets = [
                p for p in reversed(self._packets)
                if (action is None or p['action'] == action)
                and (protocol is None or p['protocol'] == protocol)
            ]

        return packets[:limit]

    def get_stats(self) -> dict:
        """
        Получить статистику журнала пакетов.

        Returns:
            Словарь со статистикой
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
            # Подсчёт по действию
            stats['by_action'][packet['action']] += 1

            # Подсчёт по протоколу
            stats['by_protocol'][packet['protocol']] += 1

            # Подсчёт недавних пакетов
            try:
                packet_time = datetime.fromisoformat(packet['timestamp'].replace('Z', '+00:00'))
                if packet_time.replace(tzinfo=None) >= one_minute_ago:
                    stats['recent_count']['last_minute'] += 1
                if packet_time.replace(tzinfo=None) >= one_hour_ago:
                    stats['recent_count']['last_hour'] += 1
            except ValueError:
                logger.error(f"Некорректный формат временной метки пакета: {packet.get('timestamp')}")

        # Преобразовать defaultdict в обычный dict
        stats['by_action'] = dict(stats['by_action'])
        stats['by_protocol'] = dict(stats['by_protocol'])

        return stats

    def clear(self) -> int:
        """
        Очистить все логи пакетов.

        Returns:
            Количество удалённых записей
        """
        with self._lock:
            count = len(self._packets)
            self._packets.clear()

        logger.info(f"Очищено {count} записей в журнале пакетов")
        return count

    def process_bpf_event(self, cpu: int, data: bytes, size: int) -> None:
        """
        Обработать событие пакета из BPF perf buffer.

        Функция обратного вызова, вызываемая BCC при получении
        события пакета из eBPF-программы.

        Args:
            cpu: Номер CPU
            data: Сырые данные пакета из BPF
            size: Размер данных
        """
        try:
            # Структура события пакета (соответствует C-структуре в eBPF):
            # struct packet_event {
            #     __u32 src_ip;
            #     __u32 dst_ip;
            #     __u16 src_port;
            #     __u16 dst_port;
            #     __u8 protocol;
            #     __u8 action;
            #     __u32 size;
            # };

            # Распаковать данные (формат соответствует структуре eBPF-программы)
            src_ip_int, dst_ip_int, src_port, dst_port, protocol_num, action_num, pkt_size = \
                struct.unpack('IIHHHBI', data[:20])

            # Преобразовать IP из сетевого порядка байт
            src_ip = socket.inet_ntoa(struct.pack('I', src_ip_int))
            dst_ip = socket.inet_ntoa(struct.pack('I', dst_ip_int))

            # Маппинг номера протокола в имя
            protocol_map = {
                6: 'TCP',
                17: 'UDP',
                1: 'ICMP'
            }
            protocol = protocol_map.get(protocol_num, 'OTHER')

            # Маппинг действия
            action = 'PASS' if action_num == 0 else 'DROP'

            # Передать в журнал пакетов
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
            logger.error(f"Ошибка обработки BPF-события пакета: {e}")
