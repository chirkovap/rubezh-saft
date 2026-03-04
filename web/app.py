#!/usr/bin/env python3
"""
XDPGuard Flask Web Application

Provides REST API and web dashboard for XDP management.
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
import logging
import os

logger = logging.getLogger(__name__)


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

    # Routes
    @app.route('/')
    def index():
        """Main dashboard page"""
        return render_template('dashboard.html')

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
    def api_block():
        """Блокировка IP адреса"""
        try:
            data = request.json
            ip = data.get('ip')
            
            if not ip:
                return jsonify({'success': False, 'error': 'IP address required'}), 400
            
            success = xdp_manager.block_ip(ip)
            
            return jsonify({
                'success': success,
                'message': f'IP {ip} blocked' if success else 'Failed to block IP'
            })
        except Exception as e:
            logger.error(f"Failed to block IP: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/unblock', methods=['POST'])
    def api_unblock():
        """Разблокировка IP адреса"""
        try:
            data = request.json
            ip = data.get('ip')
            
            if not ip:
                return jsonify({'success': False, 'error': 'IP address required'}), 400
            
            success = xdp_manager.unblock_ip(ip)
            
            return jsonify({
                'success': success,
                'message': f'IP {ip} unblocked' if success else 'Failed to unblock IP'
            })
        except Exception as e:
            logger.error(f"Failed to unblock IP: {e}")
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
            logger.error(f"Failed to get blocked IPs: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/clear-rate-limits', methods=['POST'])
    def api_clear_rate_limits():
        """Очистить счётчики rate limiting"""
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
        """Получить события в сыром формате"""
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
    
    # ========== PACKET LOGGING ENDPOINTS ==========
    
    @app.route('/api/packet-logs')
    def api_packet_logs():
        """Получить логи пакетов"""
        try:
            # Параметры
            limit = min(int(request.args.get('limit', 100)), 1000)
            action = request.args.get('action', None)  # 'PASS' or 'DROP'
            protocol = request.args.get('protocol', None)  # 'TCP', 'UDP', 'ICMP'
            reason = request.args.get('reason', None)  # 'normal', 'blacklist', 'rate_limit'
            src_ip = request.args.get('src_ip', None)
            dst_ip = request.args.get('dst_ip', None)
            
            # Собрать фильтры
            filters = {}
            if action:
                filters['action'] = action.upper()
            if protocol:
                filters['protocol'] = protocol.upper()
            if reason:
                filters['reason'] = reason.lower()
            if src_ip:
                filters['src_ip'] = src_ip
            if dst_ip:
                filters['dst_ip'] = dst_ip
            
            # Получить логи
            from python.packet_logger import get_packet_logger
            packet_logger = get_packet_logger()
            
            logs = packet_logger.get_logs(limit=limit, filters=filters if filters else None)
            
            return jsonify({
                'success': True,
                'logs': logs,
                'count': len(logs),
                'filters': filters
            })
        except Exception as e:
            logger.error(f"Failed to get packet logs: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/packet-logs/stats')
    def api_packet_log_stats():
        """Статистика логов пакетов"""
        try:
            from python.packet_logger import get_packet_logger
            packet_logger = get_packet_logger()
            
            stats = packet_logger.get_stats()
            
            return jsonify({
                'success': True,
                'stats': stats
            })
        except Exception as e:
            logger.error(f"Failed to get packet log stats: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/packet-logs/clear', methods=['POST'])
    def api_clear_packet_logs():
        """Очистить логи пакетов"""
        try:
            from python.packet_logger import get_packet_logger
            packet_logger = get_packet_logger()
            
            packet_logger.clear()
            
            return jsonify({
                'success': True,
                'message': 'Логи пакетов очищены'
            })
        except Exception as e:
            logger.error(f"Failed to clear packet logs: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # ========== END PACKET LOGGING ENDPOINTS ==========

    @app.route('/api/config', methods=['GET', 'POST'])
    def api_config():
        """Получить или обновить конфигурацию"""
        if request.method == 'GET':
            return jsonify(config.config)
        elif request.method == 'POST':
            try:
                data = request.json
                # Update config values
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
