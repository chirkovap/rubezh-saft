# Руководство по обновлению САФТ "Рубеж"

Данное руководство предназначено для пользователей, у которых уже установлен программный комплекс САФТ "Рубеж", и описывает процедуру обновления до актуальной версии без потери конфигурации.


## Что изменилось в текущей версии

### Исправлено

1. Динамическая конфигурация: файл `config.yaml` синхронизируется с XDP-фильтром через BPF-карты без перекомпиляции
2. Белый список: IP-адреса из `whitelist_ips` автоматически применяются к BPF-карте `whitelist`
3. Лимиты трафика: изменения `syn_rate`, `udp_rate`, `icmp_rate` вступают в силу после перезапуска сервиса
4. PacketLogger: исправлена инициализация модуля захвата пакетов
5. ConfigSync: добавлен новый модуль синхронизации конфигурации

### Добавлено

- `python/config_sync.py` — модуль синхронизации конфигурации с BPF-картами
- `scripts/install.sh` — автоматический установщик с поддержкой режима обновления
- Улучшена обработка ошибок при вызовах bpftool
- Добавлена проверка корректности синхронизации конфигурации при запуске


## Способ 1: Автоматическое обновление (рекомендуется)

```bash
cd /opt/rubezh-saft

# Отключить XDP на время обновления во избежание потери SSH-доступа
sudo ip link set dev ens33 xdp off

# Получить обновления из репозитория
sudo git pull origin main

# Запустить скрипт обновления (конфигурация сохраняется)
sudo ./scripts/install.sh update

# Проверить статус после обновления
sudo systemctl status rubezh-saft
```


## Способ 2: Ручное обновление

```bash
cd /opt/rubezh-saft

# 1. Остановить сервис и отключить XDP
sudo systemctl stop rubezh-saft
sudo ip link set dev ens33 xdp off

# 2. Создать резервную копию конфигурации
sudo cp /etc/rubezh-saft/config.yaml /etc/rubezh-saft/config.yaml.backup

# 3. Получить обновления
sudo git pull origin main

# 4. Перекомпилировать XDP-программу
mkdir -p build
clang -O2 -g -target bpf -D__BPF_TRACING__ \
    -I/usr/include/$(uname -m)-linux-gnu \
    -c bpf/xdp_filter.c -o build/xdp_filter.o

sudo cp build/xdp_filter.o /usr/lib/rubezh-saft/

# 5. Обновить файлы пользовательского пространства
sudo cp -r python /opt/rubezh-saft/
sudo cp -r web /opt/rubezh-saft/
sudo cp daemon.py /opt/rubezh-saft/
sudo cp cli.py /opt/rubezh-saft/

# 6. Запустить сервис
sudo systemctl start rubezh-saft

# 7. Проверить журнал
sudo journalctl -u rubezh-saft -n 30
```


## Проверка после обновления

### 1. Проверка работы ConfigSync

```bash
sudo journalctl -u rubezh-saft -n 50 | grep -E "(ConfigSync|sync|Config)"
```

Ожидаемый вывод:
```
ConfigSync инициализирован
Синхронизация конфигурации: SYN=1000, UDP=500, ICMP=100, Enabled=1
Лимиты трафика синхронизированы с XDP
Белый список синхронизирован с XDP
Проверка конфигурации пройдена
```

### 2. Проверка работы модуля захвата пакетов

```bash
sudo journalctl -u rubezh-saft -n 50 | grep -i packet
```

### 3. Проверка API

```bash
# Статус системы
curl http://localhost:8080/api/status

# Журнал пакетов (должны присутствовать данные)
curl http://localhost:8080/api/packets?limit=5

# Журнал событий
curl http://localhost:8080/api/events?limit=10
```


## Настройка конфигурации после обновления

Откройте `/etc/rubezh-saft/config.yaml` и проверьте актуальность параметров:

```yaml
protection:
  enabled: true
  syn_rate: 1000      # Пакетов SYN в секунду на IP
  udp_rate: 500       # Пакетов UDP в секунду на IP
  icmp_rate: 100      # Пакетов ICMP в секунду на IP

whitelist_ips:
  - 127.0.0.1
  - ::1
  - 192.168.0.0/16    # Добавить адрес управляющей станции
  - 203.0.113.10      # Адрес управляющей станции

logging:
  enable_packet_logging: true
```

Применить изменения:

```bash
sudo systemctl restart rubezh-saft
sudo journalctl -u rubezh-saft -n 30 | grep sync
```


## Устранение неисправностей при обновлении

### Потеря SSH-доступа после обновления

```bash
# Выполнить через консоль виртуальной машины
sudo ip link set dev ens33 xdp off
sudo systemctl stop rubezh-saft

# Исправить конфигурацию
sudo nano /etc/rubezh-saft/config.yaml
# Увеличить лимиты и добавить управляющий IP в whitelist_ips

sudo systemctl start rubezh-saft
```

### Ошибка синхронизации ConfigSync

```bash
# Проверить наличие модуля
ls -lh /opt/rubezh-saft/python/config_sync.py

# Загрузить из репозитория при необходимости
sudo curl -o /opt/rubezh-saft/python/config_sync.py \
  https://raw.githubusercontent.com/chirkovap/rubezh-saft/main/python/config_sync.py

sudo systemctl restart rubezh-saft
```

### Ошибка компиляции XDP-программы

```bash
# Установить недостающие зависимости
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# Повторить компиляцию
cd /opt/rubezh-saft
clang -O2 -g -target bpf -D__BPF_TRACING__ \
    -I/usr/include/$(uname -m)-linux-gnu \
    -c bpf/xdp_filter.c -o build/xdp_filter.o
```


## Тестирование после обновления

### Базовая проверка

```bash
# Веб-панель управления
curl http://localhost:8080/api/status

# Журнал пакетов
curl http://localhost:8080/api/packets?limit=10
```

### Проверка белого списка

```bash
YOUR_IP=$(echo $SSH_CLIENT | awk '{print $1}')
echo "Управляющий IP: $YOUR_IP"
grep -A 10 "whitelist_ips" /etc/rubezh-saft/config.yaml
```


## Откат к предыдущей версии

```bash
cd /opt/rubezh-saft
sudo systemctl stop rubezh-saft
sudo git log --oneline          # Найти хеш предыдущего коммита
sudo git checkout <хеш-коммита>
sudo ./scripts/install.sh update
```


## Полная переустановка

Применяется в случае необходимости чистой установки:

```bash
# Сохранить конфигурацию
sudo cp /etc/rubezh-saft/config.yaml ~/config.yaml.backup

# Удалить текущую установку
sudo systemctl stop rubezh-saft
sudo systemctl disable rubezh-saft
sudo rm -rf /opt/rubezh-saft
sudo rm -rf /etc/rubezh-saft
sudo rm -rf /usr/lib/rubezh-saft
sudo rm /etc/systemd/system/rubezh-saft.service
sudo systemctl daemon-reload

# Выполнить чистую установку
cd ~
git clone https://github.com/chirkovap/rubezh-saft.git
cd rubezh-saft
sudo ./scripts/install.sh

# Восстановить конфигурацию
sudo cp ~/config.yaml.backup /etc/rubezh-saft/config.yaml
sudo systemctl restart rubezh-saft
```


## Поддержка

При возникновении проблем в процессе обновления:

1. Изучите секцию "Устранение неисправностей" в [README.md](README.md)
2. Создайте обращение на [GitHub Issues](https://github.com/chirkovap/rubezh-saft/issues), приложив вывод журнала:
   ```bash
   sudo journalctl -u rubezh-saft -n 100 > rubezh-saft.log
   ```
