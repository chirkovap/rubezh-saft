#!/usr/bin/env python3
"""
САФТ Рубеж — Детектор атак

Обнаруживает DDoS-атаки и подозрительную активность на основе статистики XDP.
"""

import logging
import time
from threading import Thread, Event

logger = logging.getLogger(__name__)


class AttackDetector:
    """Детектор атак на основе статистики пакетов"""

    def __init__(self, xdp_manager, config):
        self.xdp_manager = xdp_manager
        self.config = config
        self.running = False
        self.stop_event = Event()
        self.thread = None

        # Пороги для определения атак
        self.drop_rate_threshold = config.get('protection.drop_rate_threshold', 50)  # %
        self.pps_threshold = config.get('protection.pps_threshold', 100000)  # packets/sec
        self.check_interval = config.get('protection.check_interval', 5)  # seconds

        # Предыдущие значения для расчета дельты
        self.prev_stats = None
        self.prev_time = None

        logger.info(f"Детектор атак инициализирован (порог drop_rate={self.drop_rate_threshold}%, порог pps={self.pps_threshold})")

    def start(self):
        """Запустить мониторинг атак в отдельном потоке"""
        if self.running:
            logger.warning("Детектор атак уже запущен")
            return

        self.running = True
        self.stop_event.clear()
        self.thread = Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Детектор атак запущен")

    def stop(self):
        """Остановить мониторинг атак"""
        if not self.running:
            return

        self.running = False
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        logger.info("Детектор атак остановлен")

    def _monitor_loop(self):
        """Основной цикл мониторинга"""
        logger.info("Цикл мониторинга детектора атак запущен")

        while not self.stop_event.is_set():
            try:
                self._check_for_attacks()
            except Exception as e:
                logger.error(f"Ошибка при обнаружении атак: {e}")

            # Ждем следующего интервала
            self.stop_event.wait(self.check_interval)

    def _check_for_attacks(self):
        """Проверить статистику и обнаружить атаки"""
        current_stats = self.xdp_manager.get_statistics()
        current_time = time.time()

        # Первый запуск - просто сохраняем статистику
        if self.prev_stats is None:
            self.prev_stats = current_stats
            self.prev_time = current_time
            return

        # Рассчитываем дельту за интервал
        time_delta = current_time - self.prev_time
        if time_delta < 1:
            return  # Слишком короткий интервал

        packets_total_delta = current_stats['packets_total'] - self.prev_stats['packets_total']
        packets_dropped_delta = current_stats['packets_dropped'] - self.prev_stats['packets_dropped']
        packets_passed_delta = current_stats['packets_passed'] - self.prev_stats['packets_passed']
        bytes_dropped_delta = current_stats['bytes_dropped'] - self.prev_stats['bytes_dropped']

        # Packets per second
        pps = packets_total_delta / time_delta
        dropped_pps = packets_dropped_delta / time_delta

        # Drop rate %
        drop_rate = (packets_dropped_delta / packets_total_delta * 100) if packets_total_delta > 0 else 0

        # 1. Проверка высокого drop rate (возможная атака)
        if drop_rate > self.drop_rate_threshold and packets_dropped_delta > 100:
            self.xdp_manager.event_logger.log_event(
                event_type='ATTACK',
                severity='CRITICAL',
                ip_address='N/A',
                message=f'Обнаружена возможная DDoS атака: {drop_rate:.1f}% пакетов заблокировано',
                details={
                    'drop_rate': round(drop_rate, 2),
                    'packets_dropped': packets_dropped_delta,
                    'packets_total': packets_total_delta,
                    'pps': round(pps, 2),
                    'dropped_pps': round(dropped_pps, 2),
                    'duration': round(time_delta, 2)
                }
            )
            logger.warning(f"ATTACK DETECTED: {drop_rate:.1f}% drop rate, {dropped_pps:.0f} pps dropped")

        # 2. Проверка высокого PPS (flood атака)
        if pps > self.pps_threshold:
            self.xdp_manager.event_logger.log_event(
                event_type='ATTACK',
                severity='WARNING',
                ip_address='N/A',
                message=f'Обнаружен высокий трафик: {pps:.0f} пакетов/сек',
                details={
                    'pps': round(pps, 2),
                    'packets_total': packets_total_delta,
                    'packets_dropped': packets_dropped_delta,
                    'drop_rate': round(drop_rate, 2),
                    'duration': round(time_delta, 2),
                    'attack_type': 'High PPS / Possible Flood'
                }
            )
            logger.warning(f"HIGH TRAFFIC: {pps:.0f} pps")

        # 3. Логируем DROP события если есть заблокированные пакеты
        if packets_dropped_delta > 0:
            # Логируем каждые N заблокированных пакетов
            if packets_dropped_delta >= 100:  # Пакетами от 100
                self.xdp_manager.event_logger.log_event(
                    event_type='DROP',
                    severity='INFO',
                    ip_address='N/A',
                    message=f'Заблокировано {packets_dropped_delta} пакетов за {time_delta:.1f}с',
                    details={
                        'packets_dropped': packets_dropped_delta,
                        'bytes_dropped': bytes_dropped_delta,
                        'dropped_pps': round(dropped_pps, 2),
                        'drop_rate': round(drop_rate, 2),
                        'duration': round(time_delta, 2)
                    }
                )

        # Обновляем предыдущие значения
        self.prev_stats = current_stats
        self.prev_time = current_time

    def get_attack_thresholds(self):
        """Получить текущие пороги детекции"""
        return {
            'drop_rate_threshold': self.drop_rate_threshold,
            'pps_threshold': self.pps_threshold,
            'check_interval': self.check_interval
        }

    def update_thresholds(self, drop_rate=None, pps=None, interval=None):
        """Обновить пороги детекции"""
        if drop_rate is not None:
            self.drop_rate_threshold = drop_rate
            logger.info(f"Порог drop_rate обновлён: {drop_rate}%")

        if pps is not None:
            self.pps_threshold = pps
            logger.info(f"Порог pps обновлён: {pps}")

        if interval is not None:
            self.check_interval = interval
            logger.info(f"Интервал проверки обновлён: {interval} с")
