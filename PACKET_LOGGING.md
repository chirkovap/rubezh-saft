# Журналирование пакетов в САФТ "Рубеж"

## Обзор

Программный комплекс САФТ "Рубеж" поддерживает детальное журналирование сетевых пакетов, проходящих через систему фильтрации. Функция обеспечивает мониторинг в реальном времени следующих параметров:

- IP-адрес источника и IP-адрес назначения
- Протокол: TCP, UDP, ICMP или иные
- Порты источника и назначения
- Размер пакета в байтах
- Решение фильтра: PASS (пропущен) или DROP (заблокирован)
- Временная метка с точностью до наносекунд

## Архитектура

### Компоненты

1. **Модуль PacketLogger** (`python/packet_logger.py`)
   - Хранит до 10 000 пакетов в памяти (deque)
   - Поддерживает фильтрацию по протоколу и решению фильтра
   - Сбор агрегированной статистики

2. **Веб API** (`web/app.py`)
   - `/api/packets` — получение журнала пакетов
   - `/api/packets/stats` — статистика по пакетам
   - `/api/packets/clear` — очистка журнала

3. **Веб-панель управления** (`web/templates/dashboard.html`)
   - Вкладка "Журнал пакетов"
   - Таблица с детальными данными
   - Фильтры по действию и протоколу
   - Автоматическое обновление каждые 2 секунды

## Настройка

### Конфигурация

Добавить или проверить в `/etc/rubezh-saft/config.yaml`:

```yaml
logging:
  enable_packet_logging: true  # Включить журналирование пакетов
  max_packets: 10000            # Максимальное количество пакетов в памяти

xdp:
  object_path: "/usr/lib/rubezh-saft/xdp_filter.o"
```

Применить изменения:

```bash
sudo systemctl restart rubezh-saft
```

## Использование

### Веб-интерфейс

1. Открыть панель управления: `http://<IP-сервера>:8080`
2. Перейти на вкладку "Журнал пакетов"
3. Доступные фильтры:
   - По действию: Все / PASS / DROP
   - По протоколу: Все / TCP / UDP / ICMP

### API

#### Получить журнал пакетов

```bash
# Все пакеты (последние 50)
curl http://localhost:8080/api/packets?limit=50

# Только заблокированные пакеты
curl http://localhost:8080/api/packets?action=DROP

# Только TCP-пакеты
curl http://localhost:8080/api/packets?protocol=TCP

# Комбинация фильтров
curl http://localhost:8080/api/packets?action=DROP&protocol=UDP&limit=100
```

#### Статистика пакетов

```bash
curl http://localhost:8080/api/packets/stats
```

Пример ответа:
```json
{
  "total": 5342,
  "by_action": {
    "PASS": 4891,
    "DROP": 451
  },
  "by_protocol": {
    "TCP": 3245,
    "UDP": 1897,
    "ICMP": 200
  },
  "recent_count": {
    "last_minute": 89,
    "last_hour": 5342
  }
}
```

#### Очистить журнал

```bash
curl -X POST http://localhost:8080/api/packets/clear
```

## Структура записи пакета

```json
{
  "timestamp": "2026-03-04T11:30:45.123456Z",
  "src_ip": "192.168.1.100",
  "dst_ip": "8.8.8.8",
  "protocol": "TCP",
  "src_port": 45678,
  "dst_port": 443,
  "size": 1420,
  "action": "PASS",
  "reason": null
}
```

## Производительность

Влияние на пропускную способность:
- Журналирование выключено: около 10–15 млн пакетов/с
- Журналирование включено: около 5–8 млн пакетов/с

Рекомендации для высоконагруженных систем:
1. Журналировать только заблокированные пакеты (action=DROP)
2. Применять сэмплирование: записывать каждый N-й пакет
3. Уменьшить значение `max_packets` для снижения потребления памяти

## Управление журналированием через bpftool

```bash
# Включить журналирование
sudo bpftool map update name logging_config key hex 00 00 00 00 value hex 01

# Выключить журналирование
sudo bpftool map update name logging_config key hex 00 00 00 00 value hex 00

# Проверить текущее состояние
sudo bpftool map dump name logging_config
```

## Примеры аналитических запросов

### Мониторинг заблокированных пакетов

```bash
curl http://localhost:8080/api/packets?action=DROP&limit=1000 | jq
```

### Анализ распределения трафика по протоколам

```bash
curl -s http://localhost:8080/api/packets/stats | jq '.by_protocol'
```

## Интеграция с внешними системами

Журнал пакетов может быть интегрирован с внешними системами анализа:
- Elasticsearch / Kibana
- Splunk
- Graylog
- Grafana Loki

Пример экспорта в Elasticsearch:

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(['http://localhost:9200'])

for packet in xdp_manager.get_packet_logs(limit=1000):
    es.index(index='rubezh-saft-packets', body=packet)
```

## Устранение неисправностей

### Журнал пакетов не заполняется

1. Проверить, что журналирование включено в конфигурации:
   ```bash
   grep enable_packet_logging /etc/rubezh-saft/config.yaml
   ```

2. Проверить, что XDP-программа загружена:
   ```bash
   sudo ip link show ens33
   ```

3. Проверить журнал сервиса:
   ```bash
   sudo journalctl -u rubezh-saft -f
   ```

### Снижение производительности из-за журналирования

1. Отключить журналирование PASS-пакетов, оставив только DROP
2. Уменьшить значение `max_packets` в конфигурации
3. Проверить наличие достаточного объёма оперативной памяти

## Планируемые улучшения

- Автоматический экспорт в syslog
- Поддержка IPv6
- Детальный анализ TCP-флагов
- Geo-IP информация для IP-адресов источника
- Агрегация сетевых потоков (NetFlow/sFlow)
- Обнаружение аномалий методами машинного обучения
