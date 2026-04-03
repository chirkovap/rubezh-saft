# Краткое руководство по развертыванию САФТ "Рубеж"

Данное руководство описывает минимальный набор шагов для быстрого ввода программного комплекса в эксплуатацию.


## Минимальные требования

- Ubuntu 20.04+ / Debian 11+ или совместимый дистрибутив
- Ядро Linux 4.18 и выше (с поддержкой XDP)
- Права суперпользователя (sudo)
- Оперативная память: не менее 512 МБ


## Установка

### Шаг 1. Клонирование репозитория

```bash
cd /opt
sudo git clone https://github.com/chirkovap/rubezh-saft.git
cd rubezh-saft
```

### Шаг 2. Запуск установки

```bash
sudo chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

Скрипт автоматически выполнит следующие действия:
- установит системные зависимости (clang, llvm, libbpf-dev, bpftool)
- скомпилирует XDP-программу
- установит Python-зависимости
- настроит systemd-сервис `rubezh-saft.service`
- создаст конфигурационный файл `/etc/rubezh-saft/config.yaml`

### Шаг 3. Настройка сетевого интерфейса

```bash
# Определить имя сетевого интерфейса
ip link show

# Открыть конфигурацию для редактирования
sudo nano /etc/rubezh-saft/config.yaml
```

Указать корректное имя интерфейса:

```yaml
network:
  interface: ens33      # Заменить на актуальное имя (eth0, ens3 и т.д.)
  xdp_mode: xdpgeneric  # Универсальный режим, совместимый с любым драйвером
```

Сохранить файл: Ctrl+O, Enter, Ctrl+X.

### Шаг 4. Запуск сервиса

```bash
sudo systemctl start rubezh-saft

# Проверить статус
sudo systemctl status rubezh-saft
```

Ожидаемый вывод:
```
rubezh-saft.service - САФТ "Рубеж" — система защиты от DDoS
   Loaded: loaded
   Active: active (running)
```


## Проверка работоспособности

### Проверка 1: XDP загружен в ядро

```bash
sudo ip link show <имя-интерфейса>
```

В выводе должна присутствовать строка `xdp` или `xdpgeneric`.

### Проверка 2: Веб-панель управления доступна

```bash
# Проверить API
curl http://localhost:8080/api/status

# Открыть в браузере
firefox http://localhost:8080
```

### Проверка 3: CLI работает

```bash
python3 /opt/rubezh-saft/cli.py status
```


## Первоначальная настройка

### Добавление управляющих IP в белый список

Перед активной эксплуатацией необходимо добавить IP-адрес управляющей станции в белый список, чтобы исключить самоблокировку:

```yaml
whitelist_ips:
  - 127.0.0.1
  - 192.168.1.0/24    # Подсеть управляющих станций
  - 203.0.113.10      # Конкретный IP управляющей станции
```

### Настройка лимитов трафика

```yaml
protection:
  enabled: true
  syn_rate: 1000      # TCP SYN пакетов в секунду на IP
  udp_rate: 500       # UDP пакетов в секунду на IP
  icmp_rate: 100      # ICMP пакетов в секунду на IP
```

Применить изменения:
```bash
sudo systemctl restart rubezh-saft
```


## Основные операции

### Блокировка IP-адреса

```bash
# Через CLI
python3 /opt/rubezh-saft/cli.py block 192.168.1.100

# Через API
curl -X POST http://localhost:8080/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "атака"}'
```

### Просмотр статистики

```bash
# CLI
python3 /opt/rubezh-saft/cli.py status

# API с форматированием
curl http://localhost:8080/api/status | python3 -m json.tool
```

### Просмотр журнала в реальном времени

```bash
sudo journalctl -u rubezh-saft -f
```

### Мониторинг в терминале

```bash
watch -n 1 'curl -s http://localhost:8080/api/status | python3 -m json.tool'
```


## Диагностика BPF

```bash
# Показать загруженные BPF-программы
sudo bpftool prog show

# Показать BPF-карты
sudo bpftool map show

# Статистика сетевого уровня
sudo bpftool net show
```


## Устранение типовых проблем

### Сервис не запускается

```bash
# Просмотр журнала ошибок
sudo journalctl -u rubezh-saft -n 100 --no-pager

# Проверка синтаксиса конфигурации
python3 -c "import yaml; yaml.safe_load(open('/etc/rubezh-saft/config.yaml'))"
```

### XDP-программа не загружается

```bash
# Проверить наличие скомпилированного объекта
ls -la /usr/lib/rubezh-saft/xdp_filter.o

# Перекомпилировать
cd /opt/rubezh-saft/bpf
sudo make clean && sudo make && sudo make install

# Убедиться, что установлен режим xdpgeneric
grep xdp_mode /etc/rubezh-saft/config.yaml
```

### Ошибка "BTF is required"

```bash
sudo nano /etc/rubezh-saft/config.yaml
# Установить: xdp_mode: xdpgeneric
sudo systemctl restart rubezh-saft
```

### Веб-панель недоступна

```bash
sudo netstat -tlnp | grep 8080

# Открыть порт в брандмауэре
sudo ufw allow 8080
```


## Следующие шаги

- Полная документация: [README.md](README.md)
- Руководство по обновлению: [UPDATE.md](UPDATE.md)
- Участие в разработке: [CONTRIBUTING.md](CONTRIBUTING.md)
- Сообщить о проблеме: [GitHub Issues](https://github.com/chirkovap/rubezh-saft/issues)
