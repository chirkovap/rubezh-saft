#!/usr/bin/env python3
"""
САФТ Рубеж — Интерфейс командной строки

Управление системой защиты от DDoS-атак.
"""

import click
import requests
import json
import sys
from pathlib import Path

# API endpoint
API_BASE = "http://localhost:8080/api"


@click.group()
def cli():
    """САФТ Рубеж — Управление защитой от DDoS"""
    pass


@cli.command()
def status():
    """Показать текущий статус системы и статистику"""
    try:
        response = requests.get(f"{API_BASE}/status")
        data = response.json()

        click.echo("="*50)
        click.echo("САФТ Рубеж — Статус")
        click.echo("="*50)
        click.echo(f"Protection: {'ENABLED' if data['protection_enabled'] else 'DISABLED'}")
        click.echo(f"Status: {data['status'].upper()}")
        click.echo("")

        stats = data['stats']
        click.echo("Statistics:")
        click.echo(f"  Total Packets:   {stats['packets_total']:,}")
        click.echo(f"  Dropped:         {stats['packets_dropped']:,}")
        click.echo(f"  Passed:          {stats['packets_passed']:,}")
        click.echo(f"  Total Bytes:     {stats['bytes_total']:,}")
        click.echo(f"  Dropped Bytes:   {stats['bytes_dropped']:,}")
        click.echo("")

        click.echo(f"Blocked IPs: {data['blocked_count']}")
        if data['blocked_ips']:
            click.echo("  Recent blocks:")
            for ip in data['blocked_ips'][:10]:
                click.echo(f"    - {ip}")

    except requests.exceptions.ConnectionError:
        click.echo("ERROR: Не удалось подключиться к службе САФТ Рубеж", err=True)
        click.echo("Убедитесь, что служба запущена: systemctl status rubezh-saft", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('ip')
def block(ip):
    """Заблокировать IP-адрес"""
    try:
        response = requests.post(
            f"{API_BASE}/block",
            json={'ip': ip},
            headers={'Content-Type': 'application/json'}
        )
        data = response.json()

        if data['success']:
            click.echo(f"✓ IP {ip} blocked successfully")
        else:
            click.echo(f"✗ Failed to block IP {ip}: {data.get('error', 'Unknown error')}", err=True)
            sys.exit(1)

    except requests.exceptions.ConnectionError:
        click.echo("ERROR: Не удалось подключиться к службе САФТ Рубеж", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('ip')
def unblock(ip):
    """Разблокировать IP-адрес"""
    try:
        response = requests.post(
            f"{API_BASE}/unblock",
            json={'ip': ip},
            headers={'Content-Type': 'application/json'}
        )
        data = response.json()

        if data['success']:
            click.echo(f"✓ IP {ip} unblocked successfully")
        else:
            click.echo(f"✗ Failed to unblock IP {ip}: {data.get('error', 'Unknown error')}", err=True)
            sys.exit(1)

    except requests.exceptions.ConnectionError:
        click.echo("ERROR: Не удалось подключиться к службе САФТ Рубеж", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@cli.command(name='list-blocked')
def list_blocked():
    """Показать список заблокированных IP-адресов"""
    try:
        response = requests.get(f"{API_BASE}/blocked")
        data = response.json()

        if not data['blocked_ips']:
            click.echo("Нет заблокированных IP-адресов")
            return

        click.echo(f"Total blocked IPs: {data['count']}")
        click.echo("")

        for idx, ip in enumerate(data['blocked_ips'], 1):
            click.echo(f"{idx:3d}. {ip}")

    except requests.exceptions.ConnectionError:
        click.echo("ERROR: Не удалось подключиться к службе САФТ Рубеж", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@cli.command(name='clear-rate-limits')
def clear_rate_limits():
    """Сбросить счётчики ограничения трафика"""
    try:
        response = requests.post(
            f"{API_BASE}/clear-rate-limits",
            headers={'Content-Type': 'application/json'}
        )
        data = response.json()

        if data['success']:
            click.echo("✓ Rate limit counters cleared")
        else:
            click.echo("✗ Failed to clear rate limits", err=True)
            sys.exit(1)

    except requests.exceptions.ConnectionError:
        click.echo("ERROR: Не удалось подключиться к службе САФТ Рубеж", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def export(output):
    """Экспортировать статистику в JSON-файл"""
    try:
        response = requests.get(f"{API_BASE}/status")
        data = response.json()

        if output:
            output_path = Path(output)
        else:
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = Path(f'rubezh_stats_{timestamp}.json')

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        click.echo(f"✓ Statistics exported to {output_path}")

    except requests.exceptions.ConnectionError:
        click.echo("ERROR: Не удалось подключиться к службе САФТ Рубеж", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
