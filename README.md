# XDPGuard

**Высокопроизводительная система защиты от DDoS на основе XDP/eBPF** 🛡️

XDPGuard обеспечивает фильтрацию пакетов на уровне ядра с **динамической конфигурацией** — изменяйте лимиты трафика без перекомпиляции!

## ✨ Возможности

- 🚀 **Молниеносная скорость**: XDP обрабатывает пакеты на уровне драйвера сетевой карты
- ⚙️ **Динамическая конфигурация**: Изменяйте лимиты в реальном времени через `config.yaml`
- 🎯 **Протокол-специфичная защита**: Раздельные лимиты для TCP SYN, UDP, ICMP
- 🔒 **Белый/чёрный список**: Управление доступом на основе IP-адресов
- 📊 **Статистика в реальном времени**: Живой мониторинг и статистика пакетов
- 🌎 **Веб-интерфейс**: Красивый дашборд с тёмной темой (RU/EN)
- 📦 **Логирование пакетов**: Детальные журналы захвата (аналог ELK/Splunk)
- 🔔 **Система событий**: Обнаружение атак и логирование в стиле SIEM

## 📦 Быстрый старт

### Установка (автоматическая)

```bash
# Клонировать репозиторий
git clone https://github.com/chirkovap/xdpguard.git
cd xdpguard

# Запустить автоматическую установку (компилирует XDP, устанавливает всё необходимое)
sudo ./scripts/install.sh

# Открыть веб-интерфейс
firefox http://$(hostname -I | awk '{print $1}'):8080
```

**Готово!** 🎉 XDPGuard теперь защищает вашу систему.

### Обновление существующей установки

```bash
cd xdpguard
git pull origin main

# Обновить без потери конфигурации
sudo ./scripts/install.sh update
```

## ⚙️ Конфигурация

### Как это работает

🔑 **Ключевая особенность**: XDPGuard использует BPF maps для хранения конфигурации. При редактировании `/etc/xdpguard/config.yaml` и перезапуске Python автоматически синхронизирует значения с картами ядра XDP — **перекомпиляция не нужна**!

### Настройка лимитов трафика

Отредактируйте `/etc/xdpguard/config.yaml`:

```yaml
protection:
  enabled: true
  
  # Пакетов в секунду на один IP
  syn_rate: 1000      # TCP SYN пакеты
  udp_rate: 500       # UDP пакеты  
  icmp_rate: 100      # ICMP пакеты
  
  # Допустимый всплеск
  syn_burst: 2000
  udp_burst: 1000
  icmp_burst: 200
```

**Применить изменения:**

```bash
sudo systemctl restart xdpguard

# Проверить синхронизацию
sudo journalctl -u xdpguard -n 20 | grep -i "config"
```

### Управление белым списком

**ВАЖНО**: Добавьте свои управляющие IP-адреса, чтобы не потерять доступ!

```yaml
whitelist_ips:
  - 127.0.0.1           # Локальный хост
  - 192.168.0.0/16      # Локальная сеть
  - 10.0.0.0/8          # VPN сеть
  - YOUR.IP.HERE        # <-- Добавьте ваш IP!
```

### Сетевой интерфейс

```yaml
network:
  interface: ens33    # Измените при необходимости
  xdp_mode: xdpgeneric
```

Найти свой интерфейс: `ip link show`

## 🔧 Управление

### Управление сервисом

```bash
sudo systemctl status xdpguard
sudo systemctl start xdpguard
sudo systemctl stop xdpguard
sudo systemctl restart xdpguard
sudo journalctl -u xdpguard -f
```

### Команды CLI

```bash
cd /opt/xdpguard
sudo python3 cli.py stats
sudo python3 cli.py block 1.2.3.4
sudo python3 cli.py unblock 1.2.3.4
sudo python3 cli.py list
```

### Веб API

```bash
curl http://localhost:8080/api/status
curl http://localhost:8080/api/events?limit=20
curl http://localhost:8080/api/packets?limit=100
curl -X POST http://localhost:8080/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4", "reason": "malicious"}'
```

## 📊 Веб-дашборд

- **Дашборд**: Статистика в реальном времени, пропускная способность, процент блокировок
- **Журнал событий**: Обнаружение атак, блокировки, системные события
- **Журнал пакетов**: Детальный захват пакетов с фильтрацией
- **Темы**: Переключение светлой/тёмной темы
- **Языки**: Русский/Английский

Доступно по адресу: `http://<ip-вашего-сервера>:8080`

## 🛠️ Архитектура

**Ключевые компоненты:**

1. **XDP фильтр** (`bpf/xdp_filter.c`): C-программа, работающая в ядре
2. **ConfigSync** (`python/config_sync.py`): Синхронизирует YAML с BPF maps
3. **XDPManager** (`python/xdpmanager.py`): Управляет жизненным циклом XDP
4. **Веб-дашборд** (`web/app.py`): Интерфейс на основе Flask

## 🐛 Устранение неисправностей

### SSH/Веб-интерфейс недоступен

```bash
sudo ip link set dev ens33 xdp off
sudo nano /etc/xdpguard/config.yaml
sudo systemctl restart xdpguard
```

### Изменения конфигурации не применяются

```bash
sudo journalctl -u xdpguard -n 30 | grep -i sync
```

### Высокий процент блокировок (>50%)

```bash
curl http://localhost:8080/api/status
curl http://localhost:8080/api/events
```

## 📚 Частые вопросы

**В: Действительно ли config.yaml работает без перекомпиляции?**  
О: Да! Начиная с коммита `919041d`, Python динамически синхронизирует конфиг с BPF maps.

**В: Почему виртуальная машина тормозит после включения XDPGuard?**  
О: Используйте режим `xdpgeneric` (по умолчанию). Нативный `xdpdrv` требует поддержки драйвера.

**В: Можно ли использовать в продакшне?**  
О: Да, но сначала протестируйте лимиты!

**В: Как добавить целую подсеть в белый список?**  
О: Используйте CIDR нотацию: `192.168.0.0/24` или `10.0.0.0/8`

**В: Защищает ли от всех DDoS атак?**  
О: Снижает эффективность объёмных атак (SYN flood, UDP flood, ICMP flood). Атаки на уровне приложения требуют дополнительной защиты.

## 📝 Системные требования

- **ОС**: Ubuntu 20.04+, Debian 11+ или аналог
- **Ядро**: 5.4+ с поддержкой XDP
- **ОЗУ**: минимум 512МБ, рекомендуется 1ГБ
- **Диск**: 100МБ для установки
- Требуется **доступ root**

## 👥 Участие в разработке

1. Сделайте fork репозитория
2. Создайте ветку: `git checkout -b feature/amazing`
3. Зафиксируйте изменения: `git commit -m 'Добавить amazing функцию'`
4. Отправьте: `git push origin feature/amazing`
5. Откройте Pull Request

## 📜 Лицензия

Лицензия GPL-3.0 — см. файл [LICENSE](LICENSE)

## 👏 Благодарности

- **eBPF/XDP**: Подсистема BPF ядра Linux
- **libbpf**: Библиотека BPF
- **Flask**: Веб-фреймворк
- **Plotly**: Графики (если включены)

## 📧 Поддержка

- **Проблемы**: [GitHub Issues](https://github.com/chirkovap/xdpguard/issues)
- **Документация**: Этот README + комментарии в коде
- **Сообщество**: [Discussions](https://github.com/chirkovap/xdpguard/discussions)

---

**Сделано с ❤️ и eBPF**
