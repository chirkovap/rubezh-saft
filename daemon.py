#!/usr/bin/env python3
"""
XDPGuard — Main daemon

Primary service that manages XDP protection and the web interface.
"""

# gevent monkey-patching MUST happen before any other import so that the
# standard-library networking primitives (socket, ssl, threading, …) are
# replaced by gevent-aware equivalents before any other module imports them.
try:
    from gevent import monkey
    monkey.patch_all()
    _GEVENT_AVAILABLE = True
except ImportError:
    _GEVENT_AVAILABLE = False

import sys
import logging
import signal
import subprocess
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from python.config import Config
from python.xdpmanager import XDPManager
from python.attack_detector import AttackDetector
from web.app import create_app

# Configure logging
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
    """XDPGuard main daemon"""

    def __init__(self, config_path: str = "/etc/xdpguard/config.yaml") -> None:
        self.config = Config(config_path)
        # XDPManager creates ConfigSync internally
        self.xdp_manager = XDPManager(self.config)
        self.attack_detector = AttackDetector(self.xdp_manager, self.config)
        self.running = True
        self._web_server = None  # gevent WSGIServer instance, set in start()

        # Register signal handlers
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)

    def _detach_stale_xdp(self) -> None:
        """Снять устаревшую XDP-программу с интерфейса перед загрузкой."""
        interface: str = self.config.get('network.interface', 'eth0')
        try:
            subprocess.run(
                ['ip', 'link', 'set', 'dev', interface, 'xdp', 'off'],
                capture_output=True,
                timeout=5,
            )
            logger.debug(f"Устаревшая XDP-программа снята с интерфейса {interface}")
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug(f"Не удалось снять XDP с интерфейса {interface} (игнорируется): {e}")

    def start(self) -> None:
        """Start the daemon"""
        logger.info("=" * 60)
        logger.info("Запуск XDPGuard...")
        logger.info("=" * 60)

        # Load XDP program with retry logic
        max_attempts: int = 3
        backoff_delays: list[int] = [5, 10, 20]
        last_exception: Exception | None = None

        for attempt in range(1, max_attempts + 1):
            self._detach_stale_xdp()
            try:
                if not self.xdp_manager.load_program():
                    raise RuntimeError("load_program() вернул False")
                logger.info("XDP-программа успешно загружена")
                logger.info("Синхронизация конфигурации выполнена (обрабатывается XDPManager)")
                break
            except Exception as e:
                last_exception = e
                if attempt < max_attempts:
                    delay: int = backoff_delays[attempt - 1]
                    logger.warning(
                        f"Попытка {attempt}/{max_attempts} загрузки XDP не удалась: {e}. "
                        f"Повтор через {delay} с."
                    )
                    time.sleep(delay)
                else:
                    logger.critical(
                        f"Все {max_attempts} попытки загрузки XDP завершились неудачей. "
                        f"Последняя ошибка: {e}"
                    )
                    raise RuntimeError(
                        f"Не удалось загрузить XDP-программу после {max_attempts} попыток"
                    ) from last_exception

        # Start attack detector
        try:
            self.attack_detector.start()
            logger.info("Attack detector started")
        except Exception as e:
            logger.error(f"Failed to start attack detector: {e}")

        # Start web interface
        web_host: str = self.config.get('web.host', '0.0.0.0')
        web_port: int = self.config.get('web.port', 8080)
        app = create_app(self.config, self.xdp_manager)

        logger.info(f"Веб-интерфейс запускается на http://{web_host}:{web_port}")
        logger.info("=" * 60)
        logger.info("XDPGuard запущен. Для остановки нажмите Ctrl+C.")
        logger.info("=" * 60)

        if _GEVENT_AVAILABLE:
            from gevent.pywsgi import WSGIServer
            self._web_server = WSGIServer((web_host, web_port), app)
            try:
                self._web_server.serve_forever()
            except Exception as e:
                logger.error(f"Ошибка веб-сервера gevent: {e}")
                self.shutdown(None, None)
        else:
            logger.warning(
                "Библиотека gevent не установлена — используется встроенный сервер Flask. "
                "Для production-среды установите gevent: pip install gevent"
            )
            try:
                app.run(
                    host=web_host,
                    port=web_port,
                    debug=False,
                    use_reloader=False
                )
            except Exception as e:
                logger.error(f"Ошибка веб-интерфейса Flask: {e}")
                self.shutdown(None, None)

    def shutdown(self, signum: object, frame: object) -> None:
        """Graceful shutdown — each step is isolated so one failure never
        prevents subsequent cleanup steps from running."""
        logger.info("=" * 60)
        logger.info("Остановка XDPGuard...")
        logger.info("=" * 60)

        self.running = False

        # Step 1: Stop gevent web server (stop accepting new requests first)
        try:
            if self._web_server is not None:
                logger.info("Остановка веб-сервера...")
                self._web_server.stop(timeout=5)
                logger.info("Веб-сервер остановлен")
        except Exception as e:
            logger.error(f"Ошибка при остановке веб-сервера: {e}")

        # Step 2: Stop attack detector
        try:
            logger.info("Остановка детектора атак...")
            self.attack_detector.stop()
            logger.info("Детектор атак остановлен")
        except Exception as e:
            logger.error(f"Ошибка при остановке детектора атак: {e}")

        # Step 3: Stop packet capture
        try:
            logger.info("Остановка захвата пакетов...")
            if self.xdp_manager.packet_capture is not None:
                self.xdp_manager.packet_capture.stop()
                logger.info("Захват пакетов остановлен")
            else:
                logger.info("Захват пакетов не был запущен, пропуск")
        except Exception as e:
            logger.error(f"Ошибка при остановке захвата пакетов: {e}")

        # Step 4: Unload XDP program from the network interface
        try:
            logger.info("Выгрузка XDP-программы...")
            self.xdp_manager.unload_program()
            logger.info("XDP-программа выгружена")
        except Exception as e:
            logger.error(f"Ошибка при выгрузке XDP-программы: {e}")

        logger.info("XDPGuard остановлен")
        sys.exit(0)


def main() -> None:
    """Entry point"""
    daemon = XDPGuardDaemon()
    daemon.start()


if __name__ == "__main__":
    main()
