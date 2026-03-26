#!/usr/bin/env python3
"""
XDPGuard Flask Web Application

Provides REST API and web dashboard for XDP management.
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
import ipaddress
import logging
import os
import secrets
from functools import wraps

logger = logging.getLogger(__name__)

# Keys that callers are permitted to modify via POST /api/config.
# Only protection.* keys are exposed; server, logging, and secret_key are
# intentionally excluded.  Each entry maps the dot-path to a (type, min, max)
# tuple.  For boolean fields min/max are None (not applicable).
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
    """Validate a single config key/value pair against the whitelist.

    Returns an error string on failure, or None when the value is acceptable.
    """
    if key not in MUTABLE_CONFIG_KEYS:
        return f"Key '{key}' is not allowed; only protection.* keys may be changed via the API"

    expected_type, min_val, max_val = MUTABLE_CONFIG_KEYS[key]

    if not isinstance(value, expected_type):
        # Python's json decoder maps JSON booleans to bool correctly, but an
        # integer such as 1 also passes isinstance(..., int) because bool is a
        # subclass of int — guard against that for bool fields.
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
    """Create and configure Flask application"""
    
    # Get the directory of this file for templates
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    
    app = Flask(__name__,
                template_folder=template_dir,
                static_folder=static_dir)
    
    app.config['SECRET_KEY'] = config.get('web.secret_key', 'dev-secret-key')
    app.config['XDP_MANAGER'] = xdp_manager
    app.config['CONFIG'] = config

    # Retrieve the configured API key once at app creation time.
    # An empty string means "not configured" — all POST requests will be
    # rejected with 403 until a real key is set in config.yaml.
    _api_key = config.get('web.api_key', '')

    def require_auth(f):
        """Decorator that enforces X-API-Key authentication on POST endpoints.

        Behaviour:
          - api_key not configured (empty) → 403
          - X-API-Key header missing       → 401
          - X-API-Key header wrong value   → 401
          - X-API-Key header correct       → pass through
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            if not _api_key:
                return jsonify({'error': 'API key not configured'}), 403
            client_key = request.headers.get('X-API-Key', '')
            if not client_key:
                return jsonify({'error': 'Missing X-API-Key header'}), 401
            # Timing-safe comparison to prevent timing-based key enumeration
            if not secrets.compare_digest(client_key, _api_key):
                return jsonify({'error': 'Invalid API key'}), 401
            return f(*args, **kwargs)
        return decorated

    # Routes
    @app.route('/')
    def index():
        """Main dashboard page — injects API key for JS POST calls"""
        # The key is injected server-side so the browser can include it in
        # fetch() headers without a separate round-trip endpoint.
        return render_template('dashboard.html', api_key=_api_key)

    @app.route('/api/status')
    def api_status():
        """Get system status and statistics"""
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
                'blocked_ips': blocked_ips[:20]  # Return first 20
            })
        except Exception as e:
            logger.error(f"Failed to get status: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/block', methods=['POST'])
    @require_auth
    def api_block():
        """Block an IP address"""
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
            logger.error(f"Failed to block IP: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/unblock', methods=['POST'])
    @require_auth
    def api_unblock():
        """Unblock an IP address"""
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
            logger.error(f"Failed to unblock IP: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/blocked')
    def api_blocked():
        """Get list of blocked IPs"""
        try:
            blocked_ips = xdp_manager.get_blocked_ips()
            
            return jsonify({
                'blocked_ips': blocked_ips,
                'count': len(blocked_ips)
            })
        except Exception as e:
            logger.error(f"Failed to get blocked IPs: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/clear-rate-limits', methods=['POST'])
    @require_auth
    def api_clear_rate_limits():
        """Clear rate limiting counters"""
        try:
            success = xdp_manager.clear_rate_limits()
            
            return jsonify({
                'success': success,
                'message': 'Rate limits cleared' if success else 'Failed to clear'
            })
        except Exception as e:
            logger.error(f"Failed to clear rate limits: {e}")
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
            logger.error(f"Failed to get events: {e}")
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
            logger.error(f"Failed to get raw events: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/events/stats')
    def api_event_stats():
        """Статистика событий"""
        try:
            stats = xdp_manager.get_event_stats()
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Failed to get event stats: {e}")
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
            logger.error(f"Failed to clear events: {e}")
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
            logger.error(f"Failed to get packet logs: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/packets/stats')
    def api_packet_stats():
        """Статистика логов пакетов"""
        try:
            stats = xdp_manager.get_packet_stats()
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Failed to get packet stats: {e}")
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
            logger.error(f"Failed to clear packet logs: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    # ========== END PACKET ENDPOINTS ==========

    @app.route('/api/config', methods=['GET', 'POST'])
    def api_config():
        """Get or update configuration"""
        if request.method == 'GET':
            return jsonify(config.config)
        elif request.method == 'POST':
            # POST to /api/config requires authentication
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

                # Validate every key before applying any change so the request
                # is all-or-nothing (no partial updates on mixed valid/invalid input).
                errors = {}
                for key, value in data.items():
                    err = _validate_config_key(key, value)
                    if err:
                        errors[key] = err

                if errors:
                    return jsonify({'error': 'Invalid config keys or values', 'details': errors}), 400

                # All values passed validation — apply them now.
                for key, value in data.items():
                    config.set(key, value)

                config.save()

                return jsonify({
                    'success': True,
                    'message': 'Configuration updated'
                })
            except Exception as e:
                logger.error(f"Failed to update config: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500

    return app
