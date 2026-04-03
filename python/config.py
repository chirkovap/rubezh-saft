#!/usr/bin/env python3
"""
Модуль управления конфигурацией САФТ Рубеж

Загружает и управляет YAML-конфигурацией.
"""

import secrets
import yaml
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class Config:
    """Менеджер конфигурации САФТ Рубеж"""

    def __init__(self, config_path: str = "/etc/rubezh-saft/config.yaml"):
        self.config_path = Path(config_path)
        self.config = self.load()

    def load(self) -> dict:
        """Загрузить конфигурацию из YAML-файла"""
        if not self.config_path.exists():
            logger.error(f"Файл конфигурации не найден: {self.config_path}")
            return self._default_config()

        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                logger.info(f"Конфигурация загружена из {self.config_path}")
                return config
        except Exception as e:
            logger.error(f"Не удалось загрузить конфигурацию: {e}")
            return self._default_config()

    def save(self) -> bool:
        """Сохранить текущую конфигурацию в YAML-файл"""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
                logger.info(f"Конфигурация сохранена в {self.config_path}")
                return True
        except Exception as e:
            logger.error(f"Не удалось сохранить конфигурацию: {e}")
            return False

    def get(self, path: str, default: Any = None) -> Any:
        """Получить значение конфигурации по пути в точечной нотации

        Пример: config.get('network.interface', 'eth0')
        """
        keys = path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, default)
            else:
                return default

        return value

    def set(self, path: str, value: Any) -> bool:
        """Установить значение конфигурации по пути в точечной нотации"""
        keys = path.split('.')
        target = self.config

        for key in keys[:-1]:
            target = target.setdefault(key, {})

        target[keys[-1]] = value
        return True

    def _default_config(self) -> dict:
        """Вернуть конфигурацию по умолчанию"""
        return {
            'network': {
                'interface': 'eth0',
                'mode': 'router',
                'protected_ports': [80, 443, 22]
            },
            'protection': {
                'enabled': True,
                'syn_rate': 30,
                'syn_burst': 50,
                'whitelist_ips': ['127.0.0.0/8', '10.0.0.0/8']
            },
            'web': {
                'host': '127.0.0.1',  # Привязка только к localhost; установите 0.0.0.0 (с правилами брандмауэра) для удалённого доступа
                'port': 8080,
                # Генерируется в рантайме, чтобы каждая установка
                # с конфигурацией по умолчанию получала уникальный ключ.
                'secret_key': secrets.token_hex(32)
            },
            'logging': {
                'level': 'INFO',
                'file': '/var/log/rubezh-saft.log'
            }
        }

    def validate(self) -> bool:
        """Проверить конфигурацию"""
        required_keys = ['network', 'protection', 'web', 'logging']

        for key in required_keys:
            if key not in self.config:
                logger.error(f"Отсутствует обязательная секция конфигурации: {key}")
                return False

        return True

    def reload(self) -> bool:
        """Перезагрузить конфигурацию из файла"""
        self.config = self.load()
        return self.validate()
