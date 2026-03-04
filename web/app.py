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
        """Block an IP address"""
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
        """Unblock an IP address"""
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
