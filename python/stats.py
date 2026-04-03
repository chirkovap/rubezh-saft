"""Сбор и хранение статистики САФТ Рубеж"""

import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class StatsCollector:
    """Сбор и хранение статистики атак в SQLite"""

    def __init__(self, db_path="/var/lib/rubezh-saft/stats.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def init_db(self):
        """Инициализировать схему базы данных SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Таблица заблокированных IP
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                reason TEXT,
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                unblocked_at TIMESTAMP,
                packets_dropped INTEGER DEFAULT 0
            )
        """)

        # Таблица статистики трафика
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                packets_in INTEGER,
                packets_out INTEGER,
                packets_dropped INTEGER,
                connections_active INTEGER,
                bandwidth_in INTEGER,
                bandwidth_out INTEGER
            )
        """)

        # Таблица событий атак
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attack_type TEXT,
                source_ip TEXT,
                target_port INTEGER,
                packets_count INTEGER,
                duration INTEGER,
                mitigated BOOLEAN
            )
        """)

        conn.commit()
        conn.close()
        logger.info(f"База данных инициализирована: {self.db_path}")

    def log_blocked_ip(self, ip: str, reason: str = "rate_limit"):
        """Записать заблокированный IP-адрес"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO blocked_ips (ip, reason) VALUES (?, ?)",
            (ip, reason)
        )

        conn.commit()
        conn.close()
        logger.info(f"Заблокирован IP: {ip} (причина: {reason})")

    def log_unblocked_ip(self, ip: str):
        """Записать разблокированный IP-адрес"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE blocked_ips SET unblocked_at = CURRENT_TIMESTAMP WHERE ip = ? AND unblocked_at IS NULL",
            (ip,)
        )

        conn.commit()
        conn.close()
        logger.info(f"Разблокирован IP: {ip}")

    def log_traffic(self, packets_in, packets_out, packets_dropped, connections, bandwidth_in=0, bandwidth_out=0):
        """Записать статистику трафика"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """INSERT INTO traffic_stats
               (packets_in, packets_out, packets_dropped, connections_active, bandwidth_in, bandwidth_out)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (packets_in, packets_out, packets_dropped, connections, bandwidth_in, bandwidth_out)
        )

        conn.commit()
        conn.close()

    def log_attack_event(self, attack_type: str, source_ip: str, target_port: int,
                        packets_count: int, duration: int, mitigated: bool = True):
        """Записать событие атаки"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """INSERT INTO attack_events
               (attack_type, source_ip, target_port, packets_count, duration, mitigated)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (attack_type, source_ip, target_port, packets_count, duration, mitigated)
        )

        conn.commit()
        conn.close()
        logger.warning(f"Событие атаки: {attack_type} от {source_ip}:{target_port}")

    def get_recent_blocks(self, limit: int = 100) -> List[Dict]:
        """Получить последние заблокированные IP"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """SELECT ip, reason, blocked_at, packets_dropped
               FROM blocked_ips
               ORDER BY blocked_at DESC
               LIMIT ?""",
            (limit,)
        )

        results = cursor.fetchall()
        conn.close()

        return [
            {
                'ip': row[0],
                'reason': row[1],
                'blocked_at': row[2],
                'packets_dropped': row[3]
            }
            for row in results
        ]

    def get_traffic_history(self, hours: int = 24) -> List[Dict]:
        """Получить историю трафика за последние N часов"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """SELECT timestamp, packets_in, packets_out, packets_dropped,
                      connections_active, bandwidth_in, bandwidth_out
               FROM traffic_stats
               WHERE timestamp >= datetime('now', '-' || ? || ' hours')
               ORDER BY timestamp ASC""",
            (hours,)
        )

        results = cursor.fetchall()
        conn.close()

        return [
            {
                'timestamp': row[0],
                'packets_in': row[1],
                'packets_out': row[2],
                'packets_dropped': row[3],
                'connections': row[4],
                'bandwidth_in': row[5],
                'bandwidth_out': row[6]
            }
            for row in results
        ]

    def get_attack_events(self, hours: int = 24) -> List[Dict]:
        """Получить события атак за последние N часов"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """SELECT timestamp, attack_type, source_ip, target_port,
                      packets_count, duration, mitigated
               FROM attack_events
               WHERE timestamp >= datetime('now', '-' || ? || ' hours')
               ORDER BY timestamp DESC""",
            (hours,)
        )

        results = cursor.fetchall()
        conn.close()

        return [
            {
                'timestamp': row[0],
                'attack_type': row[1],
                'source_ip': row[2],
                'target_port': row[3],
                'packets_count': row[4],
                'duration': row[5],
                'mitigated': bool(row[6])
            }
            for row in results
        ]

    def cleanup_old_data(self, days: int = 7):
        """Удалить устаревшие данные из базы"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Очистить старую статистику трафика
        cursor.execute(
            "DELETE FROM traffic_stats WHERE timestamp < datetime('now', '-' || ? || ' days')",
            (days,)
        )

        # Очистить старые события атак
        cursor.execute(
            "DELETE FROM attack_events WHERE timestamp < datetime('now', '-' || ? || ' days')",
            (days,)
        )

        # Очистить старые заблокированные IP (которые были разблокированы)
        cursor.execute(
            "DELETE FROM blocked_ips WHERE unblocked_at IS NOT NULL AND unblocked_at < datetime('now', '-' || ? || ' days')",
            (days,)
        )

        conn.commit()
        deleted = cursor.rowcount
        conn.close()

        logger.info(f"Удалено {deleted} устаревших записей")
