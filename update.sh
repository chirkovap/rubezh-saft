#!/bin/bash

# XDPGuard Update Script
# Автоматическое обновление системы защиты от DDoS

set -e  # Остановка при ошибке

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}    XDPGuard - Скрипт автоматического обновления${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Проверка прав суперпользователя
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}✗ Этот скрипт должен запускаться с правами root${NC}"
   echo -e "${YELLOW}  Используйте: sudo ./update.sh${NC}"
   exit 1
fi

# Путь к XDPGuard
XDPGUARD_PATH="/opt/xdpguard"

if [ ! -d "$XDPGUARD_PATH" ]; then
    echo -e "${RED}✗ Директория XDPGuard не найдена: $XDPGUARD_PATH${NC}"
    exit 1
fi

cd "$XDPGUARD_PATH"

echo -e "${YELLOW}[1/6]${NC} Проверка текущей версии..."
CURRENT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
echo -e "      Текущий коммит: ${CURRENT_COMMIT:0:8}"

echo ""
echo -e "${YELLOW}[2/6]${NC} Получение обновлений из GitHub..."
git fetch origin

REMOTE_COMMIT=$(git rev-parse origin/main)
echo -e "      Последний коммит: ${REMOTE_COMMIT:0:8}"

if [ "$CURRENT_COMMIT" == "$REMOTE_COMMIT" ]; then
    echo -e "${GREEN}✓ Система уже обновлена до последней версии${NC}"
    echo ""
    echo -e "${BLUE}Хотите перезапустить сервис? (y/n)${NC}"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY]|[дД][аА]|[дД])$ ]]; then
        echo -e "${YELLOW}[6/6]${NC} Перезапуск XDPGuard..."
        systemctl restart xdpguard
        sleep 2
        systemctl status xdpguard --no-pager
        echo -e "${GREEN}✓ Сервис перезапущен${NC}"
    fi
    exit 0
fi

echo ""
echo -e "${YELLOW}[3/6]${NC} Остановка сервиса XDPGuard..."
systemctl stop xdpguard 2>/dev/null || echo "      Сервис не запущен"
echo -e "${GREEN}✓ Сервис остановлен${NC}"

echo ""
echo -e "${YELLOW}[4/6]${NC} Применение обновлений..."
git reset --hard origin/main
echo -e "${GREEN}✓ Обновления применены${NC}"

echo ""
echo -e "${YELLOW}[5/6]${NC} Очистка кэша Python..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
echo -e "${GREEN}✓ Кэш очищен${NC}"

echo ""
echo -e "${YELLOW}[6/6]${NC} Запуск XDPGuard..."
systemctl start xdpguard
sleep 2

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if systemctl is-active --quiet xdpguard; then
    echo -e "${GREEN}✓ XDPGuard успешно обновлён и запущен!${NC}"
    echo ""
    echo -e "${GREEN}Изменения:${NC}"
    git log --oneline "$CURRENT_COMMIT".."$REMOTE_COMMIT" | head -5 | sed 's/^/  • /'
    echo ""
    echo -e "${BLUE}Статус сервиса:${NC}"
    systemctl status xdpguard --no-pager | head -10
    echo ""
    echo -e "${GREEN}Веб-интерфейс доступен по адресу:${NC}"
    IP=$(hostname -I | awk '{print $1}')
    echo -e "  ${BLUE}http://${IP}:8080${NC}"
else
    echo -e "${RED}✗ Ошибка при запуске XDPGuard${NC}"
    echo ""
    echo -e "${YELLOW}Проверьте логи:${NC}"
    echo -e "  sudo journalctl -u xdpguard -n 30 --no-pager"
    exit 1
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
