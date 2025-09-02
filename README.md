# [UtyaVPN-Server](https://t.me/UtyaVPN_bot)
|Уникальное решение с поддержкой АнтиЗапрет и полного туннелирования с использованием протоколов **VLESS (XTLS, Reality)**, **OpenVPN** (с патчем для обхода блокировок), **WireGuard** и **AmneziaWG**|
|------------------|

---

## Описание

Проект является форком [AntiZapret-VPN](https://github.com/GubernievS/AntiZapret-VPN) с добавлением нового функционала и телеграм-бота для управления.

### АнтиЗапрет 

АнтиЗапрет реализует технологию [раздельного туннелирования](https://encyclopedia.kaspersky.ru/glossary/split-tunneling).

Через АнтиЗапрет работают только (список сайтов автоматически обновляется ежедневно с 2:00 до 4:00 по времени сервера):

- Заблокированные Роскомнадзором сайты и IP-адреса (например discord.com)
- Сайты с незаконными ограничениями (например youtube.com)
- Сайты, ограничивающие доступ из России (например intel.com, chatgpt.com)

Все остальные сайты работают напрямую через вашего провайдера, не снижая скорость и не нарушая работу сайтов с проверкой российского IP (Госуслуги, банки, интернет-магазины, стриминговые сервисы и т.д.).

**Важно:** Для корректной работы АнтиЗапрет нужно [отключить DNS в браузере](https://www.google.ru/search?q=отключить+DNS+в+браузере).

### Полный VPN

Через полный VPN работают все сайты, доступные с вашего сервера, что позволяет обходить любые блокировки.

Сервер рекомендуется располагать за пределами России и стран СНГ, иначе гарантии разблокировки нет.

---

## Протоколы и клиенты

### VLESS (XTLS / Reality)

- Форматы файлов: `*.json`, `*.txt`
- Клиенты:
  - **Windows/macOS/Linux**: [V2RayN](https://github.com/2dust/v2rayN)
  - **Android**: [V2Box](https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box&hl=en)
  - **iOS**: [V2Box](https://apps.apple.com/sg/app/v2box-v2ray-client/id6446814690), [Streisand](https://apps.apple.com/sg/app/streisand/id6450534064)

### OpenVPN

- Формат файлов: `*.ovpn`
- Клиенты:
  - **Windows/macOS/Linux/Android/iOS**: [OpenVPN Connect](https://openvpn.net/client/)

### WireGuard

- Формат файлов: `*-WG.conf`
- Клиенты:
  - **Windows/macOS/Linux/Android/iOS**: [WireGuard](https://www.wireguard.com/install/)
  - **AmneziaWG**: поддержка WireGuard с обходом DPI

### AmneziaWG

- Формат файлов: `*-AM.conf`
- Клиенты:
  - **Windows/macOS/Linux/Android/iOS**: [AmneziaWG](https://amnezia.app/ru/downloads)

---

## Установка и обновление

1. Поддерживаемые системы: **Ubuntu 22.04/24.04**, **Debian 11/12** (рекомендуется Ubuntu 24.04).  
2. В терминале под root выполнить:

```sh
bash <(wget -qO- --no-hsts --inet4-only https://raw.githubusercontent.com/UtyaVPN/UtyaVPN-Server/main/setup.sh)
````

3. Следовать инструкциям установщика (выбор патчей, DNS, блокировок рекламы, настройки VLESS, OpenVPN, WireGuard и AmneziaWG).
4. Дождаться перезагрузки сервера.

---

## Настройка и управление

### Телеграм-бот

После установки запускается [bot](https://github.com/UtyaVPN/UtyaVPN) для управления и выдачи клиентских конфигураций.

### Скрипт управления клиентами

* Путь: `/root/antizapret/client.py`
* Пример интерактивного запуска:

```sh
/root/antizapret/client.py
```

Или использовать следующие команды:

*   **OpenVPN - Добавить/обновить клиента:**
    ```sh
    /root/antizapret/client.py 1 [имя_клиента] [срок_действия_сертификата_в_днях]
    ```
*   **OpenVPN - Удалить клиента:**
    ```sh
    /root/antizapret/client.py 2 [имя_клиента]
    ```
*   **OpenVPN - Список клиентов:**
    ```sh
    /root/antizapret/client.py 3
    ```
*   **WireGuard/AmneziaWG - Добавить клиента:**
    ```sh
    /root/antizapret/client.py 4 [имя_клиента]
    ```
*   **WireGuard/AmneziaWG - Удалить клиента:**
    ```sh
    /root/antizapret/client.py 5 [имя_клиента]
    ```
*   **WireGuard/AmneziaWG - Список клиентов:**
    ```sh
    /root/antizapret/client.py 6
    ```
*   **VLESS - Добавить пользователя:**
    ```sh
    /root/antizapret/client.py 7 [email_пользователя]
    ```
*   **VLESS - Удалить пользователя:**
    ```sh
    /root/antizapret/client.py 8 [email_пользователя]
    ```
*   **VLESS - Список пользователей:**
    ```sh
    /root/antizapret/client.py 9
    ```
*   **VLESS - Загрузить всех пользователей из БД в Xray:**
    ```sh
    /root/antizapret/client.py 10
    ```
*   **Создать все типы VPN клиентов:**
    ```sh
    /root/antizapret/client.py 11 [имя_клиента] [срок_действия_сертификата_в_днях]
    ```
*   **Удалить клиента со всех протоколов:**
    ```sh
    /root/antizapret/client.py 12 [имя_клиента]
    ```
*   **Пересоздать файлы профилей клиентов:**
    ```sh
    /root/antizapret/client.py 13
    ```
*   **Резервное копирование конфигурации и клиентов:**
    ```sh
    /root/antizapret/client.py 14
    ```
Данные опции также доступны в интерактивном меню.

---

## Ручные настройки

* Добавление/исключение сайтов и IP для АнтиЗапрет:

```sh
nano /root/antizapret/config/include-hosts.txt
nano /root/antizapret/config/exclude-hosts.txt
nano /root/antizapret/config/include-ips.txt
```

* Патч для обхода блокировок OpenVPN:

```sh
/root/antizapret/patch-openvpn.sh [0-2]
```

* Включение/отключение OpenVPN DCO:

```sh
/root/antizapret/openvpn-dco.sh [y/n]
```

---

## Настройка на роутерах

* OpenVPN: [Keenetic](./Keenetic.md), [TP-Link](./TP-Link.md), [MikroTik](https://github.com/Kirito0098/AntiZapret-OpenVPN-Mikrotik)
* WireGuard / AmneziaWG: [Keenetic](https://4pda.to/forum/index.php?showtopic=1095869), [MikroTik](https://github.com/Kirito0098/AntiZapret-WG-Mikrotik), [OpenWRT](https://telegra.ph/AntiZapret-WireGuardAmneziaWG-on-OpenWRT-03-16)
