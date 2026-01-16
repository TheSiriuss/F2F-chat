# F2F Chat (Alpha)

> **Secure P2P CLI Messenger in Go.**  
> End-to-End Encryption, Forward Secrecy & DHT discovery.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8.svg)](https://golang.org)


F2F Chat — это полностью децентрализованный мессенджер для терминала. Никаких серверов, никаких баз данных. Только вы, ваш собеседник и математика.

## Особенности
*   **True P2P:** Прямое соединение через LibP2P (работает через NAT).
*   **End-to-End Encryption:** Все сообщения шифруются (NaCl/Box).
*   **Forward Secrecy:** Для каждой сессии генерируются новые эфемерные ключи. Если у вас украдут статический ключ, старые переписки расшифровать невозможно.
*   **DHT Discovery:** Поиск друзей через глобальную сеть IPFS/Kad-DHT.

## Установка и запуск

```bash
# Клонирование
git clone https://github.com/TheSiriuss/F2F-chat.git
cd F2F-chat

# Запуск
go mod tidy
go run main.go

📖 Команды
Команда	Описание
.login <nick>	Создать профиль и войти в сеть
.info	Показать ваш PeerID и Fingerprint
.bootstrap	Подключиться к DHT нодам (для поиска других)
.addfriend <nick> <id> <key>	Добавить друга (данные взять из его .info)
.connect <nick>	Начать чат (Handshake + обмен ключами)
.fingerprint [nick]	Сверить отпечатки ключей (для параноиков)
```
## Дисклеймер

Проект находится в стадии Alpha. Используйте на свой страх и риск.
Код распространяется под лицензией AGPLv3 — свобода превыше всего.

## Поддержка (XMR)

[![Monero](https://img.shields.io/badge/XMR-QR_Code-FF6600.svg?logo=monero)](https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=monero:89SfJ2HriKs216t6hJtEbShY37Em3z1us7GqFYK6kS7JGPtoiLgaeVp7JJbXqMxgoHhPoNbGVRZWKivwiVaHkrXy7vCRaAh)

```text
89SfJ2HriKs216t6hJtEbShY37Em3z1us7GqFYK6kS7JGPtoiLgaeVp7JJbXqMxgoHhPoNbGVRZWKivwiVaHkrXy7vCRaAh

