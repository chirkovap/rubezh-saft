#!/usr/bin/env python3
"""
САФТ Рубеж — Веб-интерфейс

REST API и дашборд для управления XDP-защитой.
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
import ipaddress
import logging
import os
import secrets
from functools import wraps

logger = logging.getLogger(__name__)

# Ключи, разрешённые для изменения через POST /api/config.
# Открыты только protection.* ключи; server, logging и secret_key
# намеренно исключены. Каждый ключ маппится в (тип, мин, макс).
# Для булевых полей мин/макс равны None.
MUTABLE_CONFIG_KEYS: dict = {
    'protection.enabled':          (bool,  None,    None),
    'protection.syn_rate':         (int,   1,       1_000_000),
    'protection.syn_burst':        (int,   1,       1_000_000),
    'protection.conn_rate':        (int,   1,       1_000_000),
    'protection.conn_burst':       (int,   1,       1_000_000),
    'protection.udp_rate':         (int,   1,       1_000_000),
    'protection.udp_burst':        (int,   1,       1_000_000),
    'protection.icmp_rate':        (int,   1,       1_000_000),
    'protection.icmp_burst':       (int,   1,       1_000_000),
    'protection.drop_rate_threshold': (int, 1,      100),
    'protection.pps_threshold':    (int,   1,       10_000_000),
    'protection.check_interval':   (int,   1,       3_600),
}


def _validate_config_key(key: str, value) -> str | None:
    """Проверить пару ключ/значение конфигурации по белому списку.

    Возвращает строку ошибки при неудаче или None если значение корректно.
    """
    if key not in MUTABLE_CONFIG_KEYS:
        return f"Key '{key}' is not allowed; only protection.* keys may be changed via the API"

    expected_type, min_val, max_val = MUTABLE_CONFIG_KEYS[key]

    if not isinstance(value, expected_type):
        # Python декодирует JSON boolean в bool корректно, но целое 1
        # тоже проходит isinstance(..., int), т.к. bool — подкласс int.
        # Защищаемся от этого для булевых полей.
        if expected_type is bool or not isinstance(value, expected_type):
            return (
                f"Key '{key}' expects {expected_type.__name__}, "
                f"got {type(value).__name__}"
            )

    if expected_type is int:
        if min_val is not None and value < min_val:
            return f"Key '{key}' must be >= {min_val}, got {value}"
        if max_val is not None and value > max_val:
            return f"Key '{key}' must be <= {max_val}, got {value}"

    return None


def create_app(config, xdp_manager):
    """Создать и настроить Flask-приложение"""

    # Определить директорию шаблонов
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

    app = Flask(__name__,
                template_folder=template_dir,
                static_folder=static_dir)

    app.config['SECRET_KEY'] = config.get('web.secret_key', 'dev-secret-key')
    app.config['XDP_MANAGER'] = xdp_manager
    app.config['CONFIG'] = config

    # Получить API-ключ один раз при создании приложения.
    # Пустая строка означает 'не настроен' — все POST-запросы будут
    # отклонены с 403 до установки ключа в config.yaml.
    _api_key = config.get('web.api_key', '')

    def require_auth(f):
        """Декоратор для обязательной аутентификации X-API-Key на POST-эндпоинтах.

        Поведение:
          - api_key не настроен (пустой) → 403
          - заголовок X-API-Key отсутствует → 401
          - заголовок X-API-Key неверный → 401
          - заголовок X-API-Key корректный → пропуск
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            if not _api_key:
                return jsonify({'error': 'API key not configured'}), 403
            client_key = request.headers.get('X-API-Key', '')
            if not client_key:
                return jsonify({'error': 'Missing X-API-Key header'}), 401
            # Сравнение с постоянным временем для защиты от timing-атак
            if not secrets.compare_digest(client_key, _api_key):
                return jsonify({'error': 'Invalid API key'}), 401
            return f(*args, **kwargs)
        return decorated

    # Routes
    @app.route('/')
    def index():
        """Главная страница дашборда — передаёт API-ключ в JS"""
        # Ключ передаётся на стороне сервера, чтобы браузер мог
        # включать его в fetch()-заголовки без отдельного запроса.
        return render_template('dashboard.html', api_key=_api_key)

    @app.route('/api/status')
    def api_status():
        """Получить статус системы и статистику"""
        try:
            stats = xdp_manager.get_statistics()
            blocked_ips = xdp_manager.get_blocked_ips()

            # Проверить на атаки при каждом запросе статуса
            xdp_manager.check_for_attacks()

            return jsonify({
                'status': 'running',
                'protection_enabled': config.get('protection.enabled', True),
                'stats': stats,
                'blocked_count': len(blocked_ips),
                'blocked_ips': blocked_ips[:20]  # Вернуть первые 20
            })
        except Exception as e:
            logger.error(f"Не удалось получить статус: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/block', methods=['POST'])
    @require_auth
    def api_block():
        """Заблокировать IP-адрес"""
        try:
            data = request.json
            ip = data.get('ip')

            if not ip:
                return jsonify({'success': False, 'error': 'IP address required'}), 400

            try:
                validated_ip = str(ipaddress.ip_address(ip))
            except ValueError:
                return jsonify({'error': f'Invalid IP address: {ip}'}), 400

            if validated_ip == request.remote_addr:
                return jsonify({'error': 'Cannot block your own IP'}), 400

            success = xdp_manager.block_ip(validated_ip)

            return jsonify({
                'success': success,
                'message': f'IP {validated_ip} blocked' if success else 'Failed to block IP'
            })
        except Exception as e:
            logger.error(f"Не удалось заблокировать IP: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/unblock', methods=['POST'])
    @require_auth
    def api_unblock():
        """Разблокировать IP-адрес"""
        try:
            data = request.json
            ip = data.get('ip')

            if not ip:
                return jsonify({'success': False, 'error': 'IP address required'}), 400

            try:
                validated_ip = str(ipaddress.ip_address(ip))
            except ValueError:
                return jsonify({'error': f'Invalid IP address: {ip}'}), 400

            success = xdp_manager.unblock_ip(validated_ip)

            return jsonify({
                'success': success,
                'message': f'IP {validated_ip} unblocked' if success else 'Failed to unblock IP'
            })
        except Exception as e:
            logger.error(f"Не удалось разблокировать IP: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/blocked')
    def api_blocked():
        """Получить список заблокированных IP"""
        try:
            blocked_ips = xdp_manager.get_blocked_ips()

            return jsonify({
                'blocked_ips': blocked_ips,
                'count': len(blocked_ips)
            })
        except Exception as e:
            logger.error(f"Не удалось получить список заблокированных IP: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/clear-rate-limits', methods=['POST'])
    @require_auth
    def api_clear_rate_limits():
        """Сбросить счётчики ограничения трафика"""
        try:
            success = xdp_manager.clear_rate_limits()

            return jsonify({
                'success': success,
                'message': 'Rate limits cleared' if success else 'Failed to clear'
            })
        except Exception as e:
            logger.error(f"Не удалось сбросить счётчики rate limit: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    # ========== EVENT LOGGING ENDPOINTS ==========

    @app.route('/api/events')
    def api_events():
        """Получить события безопасности"""
        try:
            limit = int(request.args.get('limit', 100))
            event_type = request.args.get('type', None)
            severity = request.args.get('severity', None)

            events = xdp_manager.get_events(limit, event_type, severity)

            return jsonify({
                'events': events,
                'count': len(events)
            })
        except Exception as e:
            logger.error(f"Не удалось получить события: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/events/raw')
    def api_events_raw():
        """Получить события в сыром формате (как они хранятся)"""
        try:
            limit = int(request.args.get('limit', 100))
            events = xdp_manager.get_events_raw(limit)

            return jsonify({
                'events': events,
                'count': len(events),
                'format': 'raw'
            })
        except Exception as e:
            logger.error(f"Не удалось получить сырые события: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/events/stats')
    def api_event_stats():
        """Статистика событий"""
        try:
            stats = xdp_manager.get_event_stats()
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Не удалось получить статистику событий: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/events/clear', methods=['POST'])
    @require_auth
    def api_clear_events():
        """Очистить логи событий"""
        try:
            count = xdp_manager.event_logger.clear()
            return jsonify({
                'success': True,
                'message': f'Логи очищены ({count} событий удалено)'
            })
        except Exception as e:
            logger.error(f"Не удалось очистить журнал событий: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    # ========== END EVENT ENDPOINTS ==========

    # ========== PACKET LOGGING ENDPOINTS ==========

    @app.route('/api/packets')
    def api_packets():
        """Получить логи пакетов"""
        try:
            limit = int(request.args.get('limit', 100))
            action = request.args.get('action', None)  # PASS or DROP
            protocol = request.args.get('protocol', None)  # TCP, UDP, ICMP

            packets = xdp_manager.get_packet_logs(limit, action, protocol)

            return jsonify({
                'packets': packets,
                'count': len(packets)
            })
        except Exception as e:
            logger.error(f"Не удалось получить логи пакетов: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/packets/stats')
    def api_packet_stats():
        """Статистика логов пакетов"""
        try:
            stats = xdp_manager.get_packet_stats()
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Не удалось получить статистику пакетов: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/packets/clear', methods=['POST'])
    @require_auth
    def api_clear_packets():
        """Очистить логи пакетов"""
        try:
            count = xdp_manager.packet_logger.clear()
            return jsonify({
                'success': True,
                'message': f'Логи пакетов очищены ({count} записей удалено)'
            })
        except Exception as e:
            logger.error(f"Не удалось очистить логи пакетов: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    # ========== END PACKET ENDPOINTS ==========

    @app.route('/api/health')
    def api_health():
        """Вернуть статус готовности на основе состояния XDP."""
        try:
            xdp_loaded = bool(xdp_manager.xdp_loaded)
            if xdp_loaded:
                return jsonify({'status': 'healthy', 'xdp_loaded': True}), 200
            return jsonify({'status': 'unhealthy', 'xdp_loaded': False}), 503
        except Exception as e:
            logger.error(f"Проверка состояния завершилась ошибкой: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/config', methods=['GET', 'POST'])
    def api_config():
        """Получить или обновить конфигурацию"""
        if request.method == 'GET':
            return jsonify(config.config)
        elif request.method == 'POST':
            # POST к /api/config требует аутентификации
            if not _api_key:
                return jsonify({'error': 'API key not configured'}), 403
            client_key = request.headers.get('X-API-Key', '')
            if not client_key:
                return jsonify({'error': 'Missing X-API-Key header'}), 401
            if not secrets.compare_digest(client_key, _api_key):
                return jsonify({'error': 'Invalid API key'}), 401
            try:
                data = request.json
                if not isinstance(data, dict) or not data:
                    return jsonify({'error': 'Request body must be a non-empty JSON object'}), 400

                # Проверяем все ключи до применения изменений — запрос атомарный
                # (нет частичных обновлений при смешанном вводе).
                errors = {}
                for key, value in data.items():
                    err = _validate_config_key(key, value)
                    if err:
                        errors[key] = err

                if errors:
                    return jsonify({'error': 'Invalid config keys or values', 'details': errors}), 400

                # Все значения прошли проверку — применяем.
                for key, value in data.items():
                    config.set(key, value)

                config.save()

                return jsonify({
                    'success': True,
                    'message': 'Configuration updated'
                })
            except Exception as e:
                logger.error(f"Не удалось обновить конфигурацию: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500

    @app.after_request
    def set_security_headers(response):
        """Добавить заголовки безопасности к каждому ответу."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com"
        )
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    return app
