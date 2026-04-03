#!/usr/bin/env python3
"""
САФТ Рубеж — Журнал событий безопасности

Хранит события в памяти для отображения в веб-интерфейсе (SIEM-подобный).
"""

import logging
from datetime import datetime
from collections import deque
from threading import Lock

logger = logging.getLogger(__name__)


class EventLogger:
    """Хранит события XDP для SIEM-подобного интерфейса"""

    def __init__(self, max_events=1000):
        self.max_events = max_events
        self.events = deque(maxlen=max_events)
        self.lock = Lock()
        logger.info(f"EventLogger инициализирован (max_events={max_events})")

    def log_event(self, event_type, severity, ip_address, message, details=None):
        """
        Добавить событие в лог

        Args:
            event_type: 'BLOCK', 'UNBLOCK', 'DROP', 'ATTACK', 'SYSTEM', 'LOAD', 'UNLOAD'
            severity: 'INFO', 'WARNING', 'CRITICAL'
            ip_address: IP адрес или 'N/A' для системных событий
            message: Описание события
            details: Дополнительная информация (dict)
        """
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'severity': severity,
            'ip': ip_address,
            'message': message,
            'details': details or {}
        }

        with self.lock:
            self.events.append(event)

        # Логируем в системный журнал
        log_msg = f"[{event_type}] {ip_address}: {message}"
        if severity == 'CRITICAL':
            logger.error(log_msg)
        elif severity == 'WARNING':
            logger.warning(log_msg)
        else:
            logger.info(log_msg)

    def get_events(self, limit=100, event_type=None, severity=None):
        """
        Получить последние события с фильтрацией

        Args:
            limit: Максимальное количество событий
            event_type: Фильтр по типу события
            severity: Фильтр по уровню серьезности

        Returns:
            List of events (newest first)
        """
        with self.lock:
            filtered = list(self.events)

        # Фильтрация
        if event_type:
            filtered = [e for e in filtered if e['type'] == event_type]
        if severity:
            filtered = [e for e in filtered if e['severity'] == severity]

        # Вернуть последние N событий (новые первыми)
        return list(reversed(filtered))[:limit]

    def get_stats(self):
        """Статистика событий"""
        with self.lock:
            events_list = list(self.events)

        stats = {
            'total': len(events_list),
            'by_type': {},
            'by_severity': {},
            'recent_count': {
                'last_hour': 0,
                'last_day': 0
            }
        }

        now = datetime.now()

        for event in events_list:
            # По типу
            etype = event['type']
            stats['by_type'][etype] = stats['by_type'].get(etype, 0) + 1

            # По серьезности
            severity = event['severity']
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

            # Временная статистика
            event_time = datetime.fromisoformat(event['timestamp'])
            time_diff = (now - event_time).total_seconds()

            if time_diff <= 3600:  # 1 час
                stats['recent_count']['last_hour'] += 1
            if time_diff <= 86400:  # 24 часа
                stats['recent_count']['last_day'] += 1

        return stats

    def clear(self):
        """Очистить все события"""
        with self.lock:
            count = len(self.events)
            self.events.clear()

        logger.info(f"EventLogger очищен ({count} событий удалено)")
        return count
