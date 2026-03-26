#!/usr/bin/env python3
"""
XDPGuard — Основной демон

Главный сервис, управляющий XDP-защитой и веб-интерфейсом.
"""

import sys
import logging
import signal
import time
from pathlib import Path

# Добавить корень проекта в путь
sys.path.insert(0, str(Path(__file__).parent))

from python.config import Config
from python.xdpmanager import XDPManager
from python.attack_detector import AttackDetector
from web.app import create_app

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/xdpguard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class XDPGuardDaemon:
    """Основной демон XDPGuard"""

    def __init__(self, config_path="/etc/xdpguard/config.yaml"):
        self.config = Config(config_path)
        # XDPManager создаёт ConfigSync внутри себя
        self.xdp_manager = XDPManager(self.config)
        self.attack_detector = AttackDetector(self.xdp_manager, self.config)
        self.running = True

        # Установить обработчики сигналов
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)

    def start(self):
        """Запустить демон"""
        logger.info("=" * 60)
        logger.info("Запуск XDPGuard...")
        logger.info("=" * 60)

        # Загрузить XDP-программу
        try:
            if not self.xdp_manager.load_program():
                logger.error("Не удалось загрузить XDP-программу")
                sys.exit(1)
            logger.info("✓ XDP-программа успешно загружена")
            logger.info("✓ ConfigSync завершена (обработана XDPManager)")
        except Exception as e:
            logger.error(f"Ошибка инициализации XDP: {e}")
            sys.exit(1)

        # Запустить детектор атак
        try:
            self.attack_detector.start()
            logger.info("✓ Детектор атак запущен")
        except Exception as e:
            logger.error(f"Не удалось запустить детектор атак: {e}")

        # Запустить веб-интерфейс
        web_host = self.config.get('web.host', '0.0.0.0')
        web_port = self.config.get('web.port', 8080)
        app = create_app(self.config, self.xdp_manager)

        logger.info(f"✓ Веб-интерфейс запускается на http://{web_host}:{web_port}")
        logger.info("=" * 60)
        logger.info("XDPGuard работает. Для остановки нажмите Ctrl+C.")
        logger.info("=" * 60)

        try:
            app.run(
                host=web_host,
                port=web_port,
                debug=False,
                use_reloader=False
            )
        except Exception as e:
            logger.error(f"Ошибка веб-интерфейса: {e}")
            self.shutdown(None, None)

    def shutdown(self, signum, frame):
        """Корректное завершение работы"""
        logger.info("\n" + "=" * 60)
        logger.info("Завершение работы XDPGuard...")
        logger.info("=" * 60)

        self.running = False

        # Остановить детектор атак
        try:
            self.attack_detector.stop()
            logger.info("✓ Детектор атак остановлен")
        except Exception as e:
            logger.error(f"Ошибка при остановке детектора атак: {e}")

        # Выгрузить XDP-программу (очистка ConfigSync происходит в XDPManager)
        try:
            self.xdp_manager.unload_program()
            logger.info("✓ XDP-программа выгружена")
        except Exception as e:
            logger.error(f"Ошибка при выгрузке XDP: {e}")

        logger.info("✓ XDPGuard остановлен")
        sys.exit(0)


def main():
    """Точка входа"""
    daemon = XDPGuardDaemon()
    daemon.start()


if __name__ == "__main__":
    main()
