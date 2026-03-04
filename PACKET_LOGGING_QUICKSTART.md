# 🚀 Быстрый старт: Логирование пакетов XDPGuard

## 🎯 Что это?

Система логирования пакетов добавляет **третью вкладку "Логи пакетов"** в веб-интерфейс, где вы увидите:

✅ **Каждый пакет** проходящий через XDP фильтр  
✅ IP адреса, порты, протокол (TCP/UDP/ICMP)  
✅ Действие: **PASS** (пропущен) или **DROP** (заблокирован)  
✅ Причину: normal, blacklist, rate_limit  
✅ TCP флаги (SYN, ACK, FIN, RST)  
✅ Размер пакета  
✅ Фильтрацию и поиск  

💡 **Как ELK/Kibana, но для XDP трафика!**

---

## ⚡ Установка за 5 минут

### Шаг 1: Переключитесь на ветку с логированием

```bash
cd /opt/xdpguard

# Остановите сервис
sudo systemctl stop xdpguard

# Переключитесь на ветку с логированием
sudo git fetch origin
sudo git checkout feature/packet-logging
sudo git pull origin feature/packet-logging
```

### Шаг 2: Компиляция XDP программы с логированием

```bash
cd /opt/xdpguard/bpf

# Очистка
sudo make clean

# Компиляция новой версии с ring buffer
sudo clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include/x86_64-linux-gnu \
    -c xdp_filter_with_logging.c \
    -o /usr/lib/xdpguard/xdp_filter.o

# Проверьте что файл создан
ls -lh /usr/lib/xdpguard/xdp_filter.o

# Проверьте что есть ring buffer
llvm-objdump -t /usr/lib/xdpguard/xdp_filter.o | grep packet_logs
```

### Шаг 3: Обновление Python кода

```bash
cd /opt/xdpguard

# Очистка кэша
sudo rm -rf python/__pycache__
sudo find . -name "*.pyc" -delete

# Проверьте что есть новый модуль
ls -lh python/packet_logger.py
```

### Шаг 4: Запуск системы

```bash
# Запустите сервис
sudo systemctl start xdpguard

# Проверьте статус
sudo systemctl status xdpguard

# Проверьте логи
sudo journalctl -u xdpguard -n 30 --no-pager
```

### Шаг 5: Проверка

```bash
# 1. Проверьте что XDP загружен
sudo ip link show eth0 | grep xdp

# 2. Проверьте BPF программы
sudo bpftool prog show | grep xdp

# 3. Проверьте что есть ring buffer
sudo bpftool map show | grep packet_logs

# 4. Проверьте API
curl http://localhost:8080/api/packet-logs?limit=10
```

### Шаг 6: Откройте веб-интерфейс

```
http://your-server-ip:8080
```

Вы увидите **три вкладки**:
1. 📈 Дашборд - статистика
2. 📜 Логи событий - системные события
3. 📦 **Логи пакетов** ← 🎉 **НОВОЕ!**

---

## 📊 Возможности вкладки "Логи пакетов"

### Таблица пакетов

| Время | IP источника | Порт | IP назначения | Порт | Протокол | Действие | Причина | Флаги | Размер |
|------|--------------|------|----------------|------|---------|---------|---------|---------|---------|
| 14:25:30.123 | 192.168.1.100 | 54321 | 10.0.0.1 | 80 | TCP | **PASS** | normal | SYN | 60B |
| 14:25:29.456 | 192.168.1.50 | 12345 | 10.0.0.1 | 443 | TCP | **DROP** | blacklist | SYN,ACK | 64B |
| 14:25:28.789 | 8.8.8.8 | 53 | 10.0.0.1 | 12345 | UDP | **PASS** | normal | - | 128B |

### Фильтры

🔴 **По действию**: Все | PASS | DROP  
🔵 **По протоколу**: Все | TCP | UDP | ICMP  
🟡 **По причине**: Все | Normal | Blacklist | Rate Limit  
🔍 **Поиск**: По IP адресу (источник/назначение)  

### Действия

🔄 **Обновить** - Real-time обновление каждые 2 секунды  
🗑️ **Очистить логи** - Удалить все записи  
💾 **Экспорт CSV** - Скачать логи для анализа  
👁️ **Клик по пакету** - Показать полные детали + быстрая блокировка IP  

### Статистика

📊 **Всего логов**: 15,230  
✅ **PASS**: 14,100  
❌ **DROP**: 1,130  
🔵 **TCP**: 12,000 | **UDP**: 3,000 | **ICMP**: 230  

---

## 🛠️ Устранение проблем

### Не компилируется XDP программа

```bash
# Установите зависимости
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# Попробуйте с другими флагами
sudo clang -O2 -target bpf -c xdp_filter_with_logging.c -o /usr/lib/xdpguard/xdp_filter.o
```

### Логи не появляются

```bash
# Проверьте что ring buffer создан
sudo bpftool map show | grep packet_logs

# Если нет, значит старая версия XDP загружена
# Перекомпилируйте и перезапустите
```

### Ошибка "packet_logs not found"

```bash
# Убедитесь что используется правильная версия
strings /usr/lib/xdpguard/xdp_filter.o | grep packet_logs

# Если не нашло, значит загружена старая версия
cd /opt/xdpguard/bpf
sudo make clean
sudo clang -O2 -target bpf -c xdp_filter_with_logging.c -o /usr/lib/xdpguard/xdp_filter.o
sudo systemctl restart xdpguard
```

### Высокая нагрузка CPU

```bash
# Уменьшите частоту сэмплирования
# Отредактируйте xdp_filter_with_logging.c:
#define SAMPLE_RATE 1000  # Вместо 100

# Перекомпилируйте
sudo make clean && sudo make
sudo systemctl restart xdpguard
```

---

## 👍 Преимущества

✅ **Полная видимость** - все заблокированные пакеты  
✅ **Умное сэмплирование** - не перегружает систему  
✅ **Минимальный overhead** - <1% CPU  
✅ **Real-time** - обновление каждые 2 секунды  
✅ **Фильтры и поиск** - найти нужный пакет  
✅ **Экспорт в CSV** - для анализа  

---

## 📚 Дополнительно

- [📝 Полная документация](docs/PACKET_LOGGING.md)
- [🐛 Сообщить о проблеме](https://github.com/chirkovap/xdpguard/issues)
- [💬 Telegram поддержка](https://t.me/xdpguard)

---

⭐ **Если помогло - поставьте звёздочку на GitHub!**
