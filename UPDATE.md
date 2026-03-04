# 🔄 Обновление XDPGuard

**Для пользователей, у которых уже установлен XDPGuard**

Это обновление исправляет критическую проблему: **config.yaml теперь РЕАЛЬНО работает** без перекомпиляции!

## 🎯 Что нового

### ✅ Исправлено

1. **Динамическая конфигурация**: `config.yaml` синхронизируется с XDP через BPF maps
2. **Whitelist работает**: IP из `whitelist_ips` автоматически добавляются
3. **Rate limits применяются**: Изменения syn_rate/udp_rate/icmp_rate работают сразу
4. **PacketCapture исправлен**: Теперь корректно инициализируется
5. **ConfigSync добавлен**: Новый модуль для синхронизации

### ✨ Добавлено

- `python/config_sync.py` - модуль синхронизации конфигурации
- `scripts/install.sh` - автоматический установщик с UPDATE режимом
- Улучшенная обработка ошибок
- Проверка синхронизации конфигурации

## 🚀 Быстрое обновление

### Вариант 1: Автоматический (Рекомендуется)

```bash
cd /opt/xdpguard

# Отключите XDP на время обновления (чтобы не потерять SSH)
sudo ip link set dev ens33 xdp off

# Получите обновления
sudo git pull origin main

# Запустите обновление (сохраняет ваш config)
sudo ./scripts/install.sh update

# Проверьте статус
sudo systemctl status xdpguard
```

### Вариант 2: Ручной

```bash
cd /opt/xdpguard

# 1. Остановите сервис
sudo systemctl stop xdpguard
sudo ip link set dev ens33 xdp off

# 2. Сохраните конфиг (на всякий случай)
sudo cp /etc/xdpguard/config.yaml /etc/xdpguard/config.yaml.backup

# 3. Получите обновления
sudo git reset --hard HEAD  # Отменить локальные изменения
sudo git pull origin main

# 4. Перекомпилируйте XDP
mkdir -p build
clang -O2 -g -target bpf -D__BPF_TRACING__ \
    -I/usr/include/$(uname -m)-linux-gnu \
    -c bpf/xdp_filter.c -o build/xdp_filter.o

sudo cp build/xdp_filter.o /usr/lib/xdpguard/

# 5. Обновите Python файлы
sudo cp -r python /opt/xdpguard/
sudo cp -r web /opt/xdpguard/
sudo cp daemon.py /opt/xdpguard/
sudo cp cli.py /opt/xdpguard/

# 6. Перезапустите
sudo systemctl start xdpguard

# 7. Проверьте логи
sudo journalctl -u xdpguard -n 30
```

## ⚙️ Проверка после обновления

### 1. Проверьте, что ConfigSync работает

```bash
sudo journalctl -u xdpguard -n 50 | grep -E "(ConfigSync|sync|Config)"
```

**Должно быть:**
```
ConfigSync initialized
Syncing config: SYN=1000, UDP=500, ICMP=100, Enabled=1
✓ Rate limits synced to XDP successfully
✓ Whitelist synced to XDP
✓ Config verification passed
```

### 2. Проверьте, что PacketCapture запущен

```bash
sudo journalctl -u xdpguard -n 50 | grep -i packet
```

**Должно быть:**
```
PacketCapture initialized for ens33
PacketCapture инициализирован, будет запущен после загрузки XDP
✓ Захват пакетов запущен
```

### 3. Проверьте API

```bash
# Статус
curl http://localhost:8080/api/status

# Пакеты (должны быть данные)
curl http://localhost:8080/api/packets?limit=5

# События
curl http://localhost:8080/api/events?limit=10
```

## 🐛 Если что-то пошло не так

### SSH/Веб недоступны

```bash
# Через консоль VM (VMware/VirtualBox)
sudo ip link set dev ens33 xdp off
sudo systemctl stop xdpguard

# Исправьте конфиг
sudo nano /etc/xdpguard/config.yaml
# Увеличьте rate limits:
#   syn_rate: 1000
#   udp_rate: 500
# Добавьте свой IP в whitelist_ips!

sudo systemctl start xdpguard
```

### ConfigSync не работает

```bash
# Проверьте, что файл есть
ls -lh /opt/xdpguard/python/config_sync.py

# Если нет - скачайте напрямую
sudo curl -o /opt/xdpguard/python/config_sync.py \
  https://raw.githubusercontent.com/chirkovap/xdpguard/main/python/config_sync.py

# Перезапустите
sudo systemctl restart xdpguard
```

### Компиляция XDP не работает

```bash
# Установите зависимости
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# Попробуйте снова
cd /opt/xdpguard
clang -O2 -g -target bpf -D__BPF_TRACING__ \
    -I/usr/include/$(uname -m)-linux-gnu \
    -c bpf/xdp_filter.c -o build/xdp_filter.o
```

## 📝 Настройка после обновления

### Обновите конфиг

Откройте `/etc/xdpguard/config.yaml` и проверьте:

```yaml
protection:
  syn_rate: 1000      # Было 30 - ОБЯЗАТЕЛЬНО увеличьте!
  udp_rate: 500       # Было 50
  icmp_rate: 100      # Было 10
  
whitelist_ips:
  - 127.0.0.1
  - ::1
  - 192.168.0.0/16    # Добавьте вашу сеть
  - ВАШ.IP.АДРЕС      # ВАЖНО!

logging:
  enable_packet_logging: true  # Должно быть true
```

### Применить изменения

```bash
sudo systemctl restart xdpguard

# Проверить
sudo journalctl -u xdpguard -n 30 | grep "sync"
```

## ✅ Тестирование

### 1. Базовая проверка

```bash
# Веб UI
firefox http://localhost:8080

# API
curl http://localhost:8080/api/status

# Логи пакетов
curl http://localhost:8080/api/packets?limit=10
```

### 2. Проверка rate limits

```bash
# Сгенерируйте трафик
ping -c 50 8.8.8.8

# Проверьте статистику
curl http://localhost:8080/api/status

# Drop rate должен быть <10%
```

### 3. Проверка whitelist

```bash
# Ваш IP должен быть в whitelist
YOUR_IP=$(echo $SSH_CLIENT | awk '{print $1}')
echo "Your IP: $YOUR_IP"

# Убедитесь, что он в конфиге
grep -A 5 "whitelist_ips" /etc/xdpguard/config.yaml
```

## 📚 Дополнительно

### Откатиться к старой версии

```bash
cd /opt/xdpguard
sudo systemctl stop xdpguard
sudo git log --oneline  # Найдите старый коммит
sudo git checkout <old-commit-sha>
sudo ./scripts/install.sh update
```

### Полная переустановка

```bash
# Сохраните конфиг
sudo cp /etc/xdpguard/config.yaml ~/config.yaml.backup

# Удалите старую установку
sudo systemctl stop xdpguard
sudo systemctl disable xdpguard
sudo rm -rf /opt/xdpguard
sudo rm -rf /etc/xdpguard
sudo rm -rf /usr/lib/xdpguard
sudo rm /etc/systemd/system/xdpguard.service
sudo systemctl daemon-reload

# Свежая установка
cd ~
git clone https://github.com/chirkovap/xdpguard.git
cd xdpguard
sudo ./scripts/install.sh

# Восстановите конфиг
sudo cp ~/config.yaml.backup /etc/xdpguard/config.yaml
sudo systemctl restart xdpguard
```

## 📧 Поддержка

Если возникли проблемы:

1. Проверьте [README.md](README.md) - секция Troubleshooting
2. Откройте [Issue на GitHub](https://github.com/chirkovap/xdpguard/issues)
3. Приложите вывод:
   ```bash
   sudo journalctl -u xdpguard -n 100 > xdpguard.log
   ```

---

**Обновление завершено! Теперь config.yaml РЕАЛЬНО работает** ✅
