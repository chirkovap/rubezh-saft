# Система журналирования событий САФТ "Рубеж"

## Обзор

Программный комплекс САФТ "Рубеж" включает SIEM-подобную систему журналирования событий безопасности с веб-интерфейсом для мониторинга в реальном времени.

## Типы событий

- **BLOCK** — IP-адрес заблокирован
- **UNBLOCK** — IP-адрес разблокирован
- **LOAD** — XDP-программа загружена в ядро
- **UNLOAD** — XDP-программа выгружена из ядра
- **SYSTEM** — системные события
- **DROP** — пакеты заблокированы по лимиту трафика
- **ATTACK** — обнаружена атака

## Уровни серьёзности

- **INFO** — информационные события
- **WARNING** — предупреждения
- **CRITICAL** — критические события

## Использование

### Веб-интерфейс

1. Откройте панель управления: `http://<IP-сервера>:8080`
2. Перейдите на вкладку "Журнал событий"
3. Используйте фильтры для поиска нужных событий

Функции вкладки:
- Фильтрация по типу события: BLOCK, UNBLOCK, SYSTEM и т.д.
- Фильтрация по уровню серьёзности: INFO, WARNING, CRITICAL
- Автоматическое обновление каждые 3 секунды
- Цветовое кодирование по уровню серьёзности
- Счётчики: всего событий, за последний час, критические и предупреждения

### REST API

#### Получить список событий

```bash
# Все события (по умолчанию 100)
curl http://localhost:8080/api/events

# С ограничением количества
curl http://localhost:8080/api/events?limit=50

# Фильтр по типу события
curl http://localhost:8080/api/events?type=BLOCK

# Фильтр по уровню серьёзности
curl http://localhost:8080/api/events?severity=CRITICAL

# Комбинированные фильтры
curl http://localhost:8080/api/events?type=BLOCK&severity=WARNING&limit=20
```

#### Статистика событий

```bash
curl http://localhost:8080/api/events/stats
```

Пример ответа:
```json
{
  "total": 156,
  "by_type": {
    "BLOCK": 45,
    "UNBLOCK": 12,
    "SYSTEM": 99
  },
  "by_severity": {
    "INFO": 120,
    "WARNING": 30,
    "CRITICAL": 6
  },
  "recent_count": {
    "last_hour": 23,
    "last_day": 156
  }
}
```

#### Очистить журнал

```bash
curl -X POST http://localhost:8080/api/events/clear
```

## Примеры событий

### Блокировка IP-адреса

```json
{
  "timestamp": "2026-03-04T12:15:30.123456",
  "type": "BLOCK",
  "severity": "WARNING",
  "ip": "192.168.1.100",
  "message": "IP-адрес 192.168.1.100 заблокирован",
  "details": {
    "method": "manual",
    "interface": "eth0"
  }
}
```

### Загрузка XDP-программы

```json
{
  "timestamp": "2026-03-04T10:00:15.987654",
  "type": "LOAD",
  "severity": "INFO",
  "ip": "N/A",
  "message": "XDP-программа успешно загружена на eth0",
  "details": {
    "interface": "eth0",
    "mode": "xdpgeneric"
  }
}
```

### Системная ошибка

```json
{
  "timestamp": "2026-03-04T14:30:45.555555",
  "type": "SYSTEM",
  "severity": "CRITICAL",
  "ip": "N/A",
  "message": "XDP-программа не найдена: /usr/lib/rubezh-saft/xdp_filter.o",
  "details": {
    "path": "/usr/lib/rubezh-saft/xdp_filter.o"
  }
}
```

## Конфигурация

### Максимальное количество событий в памяти

По умолчанию система хранит последние 1000 событий. Для изменения отредактируйте `python/xdpmanager.py`:

```python
self.event_logger = EventLogger(max_events=5000)  # увеличить до 5000
```

## Интеграция с SIEM

События также записываются в systemd journal:

```bash
# Просмотр всех событий в реальном времени
sudo journalctl -u rubezh-saft -f

# Фильтр по событиям блокировки
sudo journalctl -u rubezh-saft | grep "\[BLOCK\]"

# Фильтр по критическим событиям
sudo journalctl -u rubezh-saft -p err

# Экспорт в JSON
sudo journalctl -u rubezh-saft -o json > rubezh-saft-events.json
```

### Пересылка в централизованную SIEM-систему через rsyslog

```bash
# Добавить в /etc/rsyslog.d/rubezh-saft.conf
if $programname == 'rubezh-saft' then @@siem-server:514
```

## Примеры использования

### Мониторинг блокировок в реальном времени

```bash
watch -n 1 'curl -s "http://localhost:8080/api/events?type=BLOCK&limit=10" | jq .'
```

### Поиск критических событий

```bash
curl -s "http://localhost:8080/api/events?severity=CRITICAL" | jq '.events[] | "\(.timestamp) - \(.message)"'
```

### Статистика блокировок

```bash
curl -s http://localhost:8080/api/events/stats | jq '.by_type.BLOCK'
```

## Программный интерфейс (Python)

Для добавления пользовательских событий из кода:

```python
from python.xdpmanager import XDPManager

xdp = XDPManager(config)

xdp.event_logger.log_event(
    event_type='ATTACK',
    severity='CRITICAL',
    ip_address='10.0.0.50',
    message='DDoS-атака обнаружена',
    details={
        'packets_per_sec': 100000,
        'attack_type': 'SYN Flood'
    }
)

events = xdp.get_events(limit=50, event_type='ATTACK')
stats = xdp.get_event_stats()
```

## Характеристики производительности

- Хранение событий в памяти (быстрый доступ без дискового ввода-вывода)
- Потокобезопасная реализация на основе Lock
- Автоматическое вытеснение старых событий при достижении лимита (deque)
- Нет влияния на производительность XDP-фильтра ядра

## Устранение неисправностей

### События не отображаются в веб-интерфейсе

```bash
# Проверить API напрямую
curl http://localhost:8080/api/events

# Проверить журнал сервиса
sudo journalctl -u rubezh-saft -n 100

# Перезапустить сервис
sudo systemctl restart rubezh-saft
```

### Очистка журнала вручную

```bash
curl -X POST http://localhost:8080/api/events/clear
```

## Планируемые улучшения

- Автоматическое обнаружение паттернов DDoS-атак
- Уведомления по электронной почте и через Telegram
- Geo-IP информация в событиях
- Экспорт в Elasticsearch и Splunk
- Grafana-дашборды для визуализации событий
