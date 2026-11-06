# NetGuardian 3.1

**Adaptive route manager for Windows.** NetGuardian finds an address that actually
accepts TCP connections for a host name and pins it in the system `hosts` file,
so an application stops hanging on `SYN_SENT` / `CLOSE_WAIT` because of a broken
DNS answer or an unreachable CDN edge.

Every change is reversible: the file is written atomically, backed up first,
re-read for verification and rolled back automatically if TLS validation of the
new route fails.

> **English summary**: NetGuardian is a dependency-free Windows console tool that
> pins host names to reachable IPv4 addresses through the `hosts` file. It
> validates the configuration, discovers addresses through a built-in DNS client,
> writes reversible marked blocks atomically with backups, verifies pinned routes
> over TLS and rolls back on failure. Commands: `scan`, `apply`, `validate`,
> `cleanup`, `prune`, `repair`, `status`, `diag`, `backups`, `tcpview`, `config`, `lang`, plus an
> interactive menu. Python 3.9+ or the single-file `NetGuardian.exe`.

---

## Содержание

- [Документация](#документация)
- [Что нового в 3.1](#что-нового-в-31)
- [Что нового в 3.0](#что-нового-в-30)
- [Быстрый старт](#быстрый-старт)
- [Команды](#команды)
- [Как это работает](#как-это-работает)
- [Безопасность изменений](#безопасность-изменений)
- [Конфигурация](#конфигурация)
- [Диагностика](#диагностика)
- [Частые проблемы](#частые-проблемы)
- [Сборка из исходников](#сборка-из-исходников)
- [Структура проекта](#структура-проекта)
- [Совместимость](#совместимость)
- [Лицензия](#лицензия)

---

## Документация

| Файл | Кому и зачем |
|---|---|
| [README.txt](README.txt) | новый пользователь: установка, меню, команды, частые проблемы |
| `README.md` | полный справочник: все команды, конфигурация, внутренности |
| [README.en.md](README.en.md) | English README for EU publication and international users |
| [README.en.txt](README.en.txt) | the same English guide in plain text (Notepad) |
| [NOTICE.txt](NOTICE.txt) | copyright, MIT terms and third-party notices |
| [docs/PROJECT.txt](docs/PROJECT.txt) | описание проекта: цель, задачи, результаты, ограничения |
| [docs/HOW-IT-WORKS.txt](docs/HOW-IT-WORKS.txt) | разработчик/ревьюер: архитектура, алгоритмы, форматы, ограничения |
| [docs/RELEASE.txt](docs/RELEASE.txt) | что входит в релиз, кому что выдавать, чек-лист |
| [docs/REVIEW.md](docs/REVIEW.md) | аудит v2.3: найденные дефекты и решения 3.0 |
| [CHANGELOG.md](CHANGELOG.md) | история изменений по версиям |

Текстовые файлы сохранены в UTF-8 с BOM и CRLF — открываются в Блокноте
без настройки кодировки.

---

## Что нового в 3.1

- Профиль `github_access` расширен: `github.com`, `api.github.com`,
  `raw.githubusercontent.com`, `gist.githubusercontent.com`, `codeload.github.com`.
- Добавлен профиль `gitlab_access`: `gitlab.com` и `registry.gitlab.com`.
- Новое поле `domain_candidates`: свой список IPv4 для каждого домена. У GitHub
  разные адреса у web, raw, API и codeload, поэтому один общий список не подходит.
- Для `github_access` и `gitlab_access` проверены реальные маршруты и TLS:
  `github.com` — 140.82.121.3/4, `api.github.com` — 140.82.121.6,
  `raw.githubusercontent.com` — 185.199.108–111.133,
  `codeload.github.com` — 140.82.121.9, `gitlab.com` — 172.65.251.78,
  `registry.gitlab.com` — 35.227.35.254.
- 108 тестов (добавлены проверки `domain_candidates`, приоритета адресов
  и разбора subject сертификата в `test_security.py`).
- Релизный комплект `NetGuardian-3.1.1-release`.

Подробности по маршрутам и конфликту в hosts — в разделе
[GitHub и GitLab](#github-и-gitlab).

---

## Что нового в 3.0

Версия 2.3 была рабочим прототипом на 670 строк с несколькими опасными
местами: `hosts` перезаписывался «на месте», резервных копий не было,
`nslookup` разбирался регуляркой, IPv6 и состояния `FIN_WAIT_*` не читались,
а TCPView качался по неверному URL (`Tcpview.zip` вместо `TCPView.zip`), из-за
чего стабильно возвращался 404.

В 3.0 ядро переписано на пакет из 15 модулей без внешних зависимостей:

- собственный DNS-клиент (UDP + TCP fallback) вместо разбора вывода `nslookup`;
- атомарная запись `hosts` через временный файл и `os.replace`;
- резервные копии, восстановление, автоматический откат при ошибке проверки;
- обнаружение конфликтующих строк в `hosts`, из-за которых старый фикс «не работал»;
- проверка TLS именно по закреплённому IP (SNI остаётся доменным);
- корректный URL TCPView, проверка подписи Authenticode и защита от zip-slip;
- полноценный CLI с `--json`, кодами возврата и документацией;
- 91 модульный тест на стандартном `unittest`, без сети и без прав администратора.

Подробный разбор находок — в [docs/REVIEW.md](docs/REVIEW.md), история
изменений — в [CHANGELOG.md](CHANGELOG.md). Исходник 2.3 сохранён в
[`legacy/guardian_v2.3.py`](legacy/guardian_v2.3.py).

## Быстрый старт

### Портативная сборка (рекомендуется)

Папка `dist\NetGuardian\` ничего не распаковывает при старте, поэтому работает
и там, где `%TEMP%` ограничен политикой или песочницей.

1. Запустите `dist\NetGuardian\run.cmd` (или `NetGuardian.exe` в той же папке)
   **от имени администратора** — без этого Windows не даст изменить
   `C:\Windows\System32\drivers\etc\hosts`.
2. Выберите пункт `[2]`, чтобы применить профиль, или `[1]` для поиска
   зависших соединений.
3. Проверьте результат пунктом `[3]` (TLS-проверка) или `[7]` (состояние).

При первом запуске рядом с EXE создаётся `routes.json` с тремя профилями:
`microsoft_fix`, `github_access`, `gitlab_access`.

### Один файл

`dist\NetGuardian.exe` — та же программа одним файлом. При старте она
распаковывает встроенные библиотеки в `%TEMP%`; если запись туда запрещена
(песочница, Controlled Folder Access, политика), окно закроется сразу.
В этом случае используйте портативную сборку или `dist\run.cmd`, который
показывает код ошибки и не закрывает окно.

### Из исходников

```powershell
python guardian.py            # интерактивный центр управления
python guardian.py --help     # список команд
python guardian.py config --check
```

Зависимостей нет: нужен только Python 3.9+ для Windows.

## Команды

| Команда | Назначение |
|---|---|
| `netguardian` / `netguardian menu` | интерактивное меню |
| `netguardian scan` | найти зависшие TCP-соединения и предложить профиль |
| `netguardian apply NAME` | найти адреса, выбрать лучший по TCP RTT и применить профиль |
| `netguardian apply NAME --dry-run` | показать план, ничего не записывая |
| `netguardian validate [NAME]` | проверить закреплённые маршруты по TLS |
| `netguardian cleanup [NAME]` | удалить один фикс |
| `netguardian cleanup --all --yes` | удалить все блоки NetGuardian |
| `netguardian prune --all --dry-run` | показать записи, чей адрес умер или не даёт TLS |
| `netguardian prune --all --yes` | убрать такие записи из блоков NetGuardian |
| `netguardian prune --all --foreign` | ещё и отчёт по чужим строкам `hosts` (не удаляются) |
| `netguardian repair --dry-run` | проверить блоки NetGuardian и показать план замены мёртвых IP |
| `netguardian repair --yes` | заменить мёртвые IP только на проверенные TCP+TLS кандидаты |
| `NetGuardian-Repair.cmd` | то же одной кнопкой от администратора, с бэкапом и отчётом |
| `netguardian status` | активные блоки, кэш, резервные копии |
| `netguardian diag DOMAIN` | полная диагностика домена |
| `netguardian backups` | список копий `hosts` |
| `netguardian backups --restore 1` | восстановить копию |
| `netguardian tcpview` | скачать (с проверкой подписи) и запустить TCPView |
| `netguardian config --check` | проверить `routes.json` |
| `netguardian config --show` | показать действующую конфигурацию |
| `netguardian lang ru` | переключить язык и сохранить выбор |

Глобальные параметры работают до и после команды:

| Параметр | Значение |
|---|---|
| `--config PATH` | путь к `routes.json` |
| `--data-dir PATH` | каталог для кэша, логов и резервных копий |
| `--hosts PATH` | подменить путь к `hosts` (тесты, портативный режим) |
| `--lang {en,ru,auto}` | язык интерфейса |
| `--json` | машиночитаемый вывод |
| `--no-color` | отключить ANSI-цвета |
| `--verbose` | дублировать лог в консоль |

Коды возврата: `0` — успех, `1` — ошибка выполнения, `2` — ошибка
конфигурации/аргументов, `3` — нужны права администратора, `4` — повреждён
блок NetGuardian в `hosts`.

Примеры для скриптов:

```powershell
netguardian status --json
netguardian apply github_access --json --no-verify
netguardian diag github.com --json
netguardian cleanup --all --yes --json
```

## Как это работает

1. **Поиск адреса.** Сначала проверяется кэш (TTL из `cache_ttl_hours`), затем
   IP из `static_candidates`, затем локальный DNS-сервер (`local_dns`), затем
   системный резолвер. Каждый кандидат проверяется реальным TCP-подключением на
   порт из `ports` (по умолчанию 443). Мёртвый адрес отбрасывается.
2. **Запись.** Выбранный адрес попадает в `hosts` одним блоком с маркерами
   `# === NETGUARDIAN FIX (profile) [timestamp] BEGIN/END ===`.
   Сначала создаётся резервная копия, затем файл пишется атомарно.
   После записи содержимое перечитывается и сверяется с планом.
3. **Проверка.** Если включён `verify_after_apply`, NetGuardian открывает TLS к
   закреплённому IP с SNI домена, проверяет цепочку и издателя из
   `expected_issuers`. При ошибке изменения автоматически откатываются.
4. **Очистка.** `cleanup` удаляет только блоки NetGuardian и не трогает
   остальные строки. Одиночный профиль удаляется по имени.

Старые блоки, созданные версией 2.3, читаются и удаляются тем же кодом —
формат маркеров совместим.

## Безопасность изменений

- **Атомарная запись.** Временный файл в том же каталоге + `os.replace`;
  оборванная запись не может оставить половину `hosts`.
- **Резервная копия перед каждой записью.** Хранится в `backups/`,
  ротация по `backup_keep`. Восстановление — `backups --restore`.
- **Проверка после записи.** Блок перечитывается; при расхождении файл
  возвращается к исходному состоянию.
- **Выбор по RTT.** `apply` и `repair` измеряют TCP-рукопожатие до каждого
  кандидата и закрепляют самый быстрый, а не первый ответивший. В строке
  `domain -> ip` рядом с источником печатается RTT в миллисекундах.
- **Откат после неудачной TLS-проверки.** `apply` возвращает `hosts` к копии
  и сообщает причину.
- **Конфликты.** Если в `hosts` уже есть строка, привязывающая тот же домен к
  другому IP, запись блокируется: старая строка идёт раньше и всё равно
  выиграет. Удалите её, закомментируйте или примените `--force`.
- **Повреждённые маркеры.** Незакрытый или чужой блок останавливает операцию
  с кодом `4`; файл не изменяется.
- **Кодировка и переводы строк.** Определяются автоматически (`utf-8`,
  `utf-8-sig`, `cp1251`, `utf-16`), CRLF сохраняется, комментарии не портятся.
- **Права.** Запись требует администратора; в интерактивном режиме
  предлагается перезапуск через UAC.
- **TCPView.** Скачивается только с `live.sysinternals.com` /
  `download.sysinternals.com`, проверяется подпись Authenticode с ожидаемым
  издателем Microsoft. Без подписи запуск отклоняется, если не указан
  `--allow-unsigned`.

## Конфигурация

Файл `routes.json` (рядом с EXE; при read-only установке —
`%LOCALAPPDATA%\NetGuardian\routes.json`):

```json
{
  "settings": {
    "language": "auto",
    "local_dns": "",
    "dns_timeout_sec": 3,
    "tcp_timeout_sec": 3,
    "cache_ttl_hours": 6,
    "backup_keep": 10,
    "verify_after_apply": true,
    "stuck_states": ["SYN_SENT", "CLOSE_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "LAST_ACK", "CLOSING"]
  },
  "profiles": {
    "github_access": {
      "description": "GitHub web, API, raw content and archives",
      "process_hints": ["git", "Code", "chrome", "firefox", "msedge"],
      "domains": ["github.com", "api.github.com", "raw.githubusercontent.com",
                  "gist.githubusercontent.com", "codeload.github.com"],
      "strategy": "static_first",
      "static_candidates": [],
      "domain_candidates": {
        "github.com": ["140.82.121.3", "140.82.112.3"],
        "api.github.com": ["140.82.121.6"],
        "raw.githubusercontent.com": ["185.199.108.133", "185.199.109.133"],
        "codeload.github.com": ["140.82.121.9"]
      },
      "expected_issuers": ["Sectigo", "DigiCert", "Let's Encrypt"],
      "ports": [443]
    },
    "gitlab_access": {
      "description": "GitLab web and container registry",
      "process_hints": ["git", "chrome", "firefox", "msedge"],
      "domains": ["gitlab.com", "registry.gitlab.com"],
      "strategy": "static_first",
      "static_candidates": [],
      "domain_candidates": {
        "gitlab.com": ["172.65.251.78"],
        "registry.gitlab.com": ["35.227.35.254"]
      },
      "expected_issuers": ["Sectigo", "DigiCert"],
      "ports": [443]
    }
  }
}
```

### `settings`

| Ключ | По умолчанию | Смысл |
|---|---|---|
| `language` | `auto` | `auto`, `en` или `ru` |
| `local_dns` | `""` | IPv4 локального DNS; пусто = системный резолвер |
| `dns_timeout_sec` | `3` | таймаут DNS-запроса |
| `tcp_timeout_sec` | `3` | таймаут TCP-проверки |
| `cache_ttl_hours` | `6` | срок жизни кэша; `0` отключает кэш |
| `backup_keep` | `10` | сколько копий `hosts` хранить |
| `verify_after_apply` | `true` | TLS-проверка и откат после `apply` |
| `stuck_states` | `SYN_SENT`, `CLOSE_WAIT`, `FIN_WAIT_1`, `FIN_WAIT_2`, `LAST_ACK`, `CLOSING` | какие состояния считать зависшими |

### `profiles`

| Поле | Обязательно | Смысл |
|---|---|---|
| `description` | нет | описание для меню |
| `domains` | да | домены; можно вставлять URL, путь отбросится |
| `process_hints` | нет | подстроки имён процессов для `scan` |
| `strategy` | нет | `static_first`, `dns_discovery_only`, `static_only`, `system_dns` |
| `static_candidates` | для `static_*` | общий список IPv4, проверяемых первыми |
| `domain_candidates` | нет | объект `"домен": [IPv4, ...]`; имеет приоритет над `static_candidates` |
| `expected_issuers` | нет | подстроки издателя сертификата |
| `ports` | нет | порты TCP-проверки, по умолчанию `[443]` |

Стратегии:

- `static_first` — сначала адреса из `domain_candidates` для этого домена (или
  общий `static_candidates`), затем локальный DNS, затем системный.
- `dns_discovery_only` — локальный DNS, затем системный.
- `static_only` — только `domain_candidates` / `static_candidates` (без DNS).
- `system_dns` — сначала системный резолвер, затем локальный DNS.

Кэш проверяется первым в любой стратегии; закэшированный адрес всё равно
проверяется TCP-подключением и отбрасывается, если стал недоступен.

## GitHub и GitLab

В 3.1 добавлены профили `github_access` и `gitlab_access`. Адреса проверены
TCP-подключением и TLS из тестовой сети (DNS `192.168.1.1`, 31.10.2026):

| Домен | Рабочие адреса | Издатель сертификата |
|---|---|---|
| `github.com` | 140.82.121.3, 140.82.112.3, 140.82.113.3, 140.82.114.3 | Sectigo |
| `api.github.com` | 140.82.121.6, 140.82.112.6, 140.82.113.6 | Sectigo |
| `raw.githubusercontent.com` | 185.199.108–111.133 | Let's Encrypt |
| `gist.githubusercontent.com` | 185.199.108–111.133 | Let's Encrypt |
| `codeload.github.com` | 140.82.121.9, 140.82.112.9 | Sectigo |
| `gitlab.com` | 172.65.251.78 | Sectigo |
| `registry.gitlab.com` | 35.227.35.254 | Sectigo |

Порядок действий:

```powershell
netguardian diag github.com
netguardian cleanup --all
netguardian apply github_access --dry-run
netguardian apply github_access
netguardian validate github_access
```

**Важно про старую строку.** Если в `hosts` есть
`185.199.108.133 github.com`, она перекрывает блок NetGuardian. Это адрес
GitHub Pages, а не web-фронта GitHub: TLS с ним может проходить, но отдаётся
не тот сайт. Удалите или закомментируйте строку в блокноте от администратора,
затем примените профиль. `cleanup` удаляет только блоки NetGuardian и эту
строку не тронет.

**Если IP заблокирован.** NetGuardian меняет только сопоставление
«домен → IPv4» в `hosts`. Если провайдер или сам сервис блокирует российские
адреса на уровне сети/аккаунта, hosts не поможет: нужен другой канал доступа.
NetGuardian не подменяет ваш IP и не является VPN; решение об использовании
VPN остаётся за пользователем.

## Диагностика

`netguardian diag github.com` проверяет по порядку: записи в `hosts`, системный
DNS, локальный DNS, TCP-доступность каждого адреса, TLS-сертификат (издатель,
срок действия), системный прокси. Итог — один из вердиктов:

| Вердикт | Что означает | Что делать |
|---|---|---|
| `ok` | маршрут исправен | ничего |
| `dns` | имя не разрешается | проверить `local_dns`, применить профиль |
| `tcp` | адреса не отвечают на 443 | применить профиль/другой IP, проверить сеть |
| `tls` | TCP есть, TLS падает | проверить прокси/VPN/антивирус |
| `hosts` | устаревшая запись подменяет имя | `cleanup` |

Вывод `--json` предназначен для скриптов и мониторинга.

## Частые проблемы

**«NetGuardian.exe не запускается».** Однофайловая сборка распаковывает
библиотеки в `%TEMP%`; если запись туда запрещена (песочница, Controlled Folder
Access, ограниченный профиль), окно закрывается без сообщения. Запустите
портативную версию `dist\NetGuardian\NetGuardian.exe` — она ничего не
распаковывает. Либо запустите `run.cmd`: он покажет код ошибки и оставит окно
открытым. Если Windows показывает SmartScreen, нажмите «Подробнее → Выполнить
всё равно» и сверьте SHA256 с `SHA256SUMS.txt`.

**«Access denied» при записи `hosts`.** Запустите от имени администратора. В
интерактивном режиме NetGuardian сам предложит перезапуск через UAC.

**«Existing hosts entry conflicts…».** В `hosts` уже есть строка для этого
домена с другим IP. Удалите/закомментируйте её или используйте `--force`.
NetGuardian не удаляет чужие строки автоматически.

**`validate` показывает `UNTRUSTED`.** Скорее всего, трафик перехватывает
прокси, VPN или антивирус. Проверьте `diag DOMAIN`: если TCP открыт, а TLS
падает — смотрите системный прокси.

**`apply` пишет «no reachable address».** Ни один адрес не принял TCP на 443.
Проверьте сеть, `local_dns` и `static_candidates`; при необходимости задайте
другой порт в `ports`.

**Старые фиксы 2.3 не удаляются.** Они удаляются: `netguardian cleanup --all`.
Формат маркеров совместим.

**Программа установлена в `Program Files`.** Конфигурация, кэш, логи и копии
автоматически переезжают в `%LOCALAPPDATA%\NetGuardian`; `hosts` всё равно
требует администратора.

## Сборка из исходников

```powershell
python -m unittest discover -s tests -t .   # 108 тестов, без сети и администратора
.\build.ps1                                  # тесты + dist\NetGuardian.exe + SHA256
```

`build.ps1` собирает обе формы релиза: портативную папку `dist\NetGuardian\`
(с `run.cmd`) и один файл `dist\NetGuardian.exe`, без UPX (меньше ложных
срабатываний антивирусов), с иконкой и версией `3.1.1.0`. Затем он проверяет
`--version`, упаковывает оба варианта и исходники в ZIP и пишет
`dist\SHA256SUMS.txt`.

Иконка пересоздаётся командой `python packaging\make_icon.py` (нужен Pillow).

## Структура проекта

```
NetGuardian-3.1/
├── guardian.py              точка входа (совместима с python guardian.py)
├── netguardian/
│   ├── cli.py               команды, меню, коды возврата
│   ├── config.py            схема, валидация, routes.json
│   ├── hosts.py             атомарная запись, блоки, копии, откат
│   ├── resolver.py          кэш, DNS-клиент, TCP-проверка
│   ├── scanner.py          разбор netstat/tasklist
│   ├── sslcheck.py          TLS-сертификаты
│   ├── diagnostics.py       сквозная диагностика
│   ├── tcpview.py           загрузка и проверка подписи TCPView
│   ├── security.py          UAC, Authenticode
│   ├── i18n.py              en/ru без внешних зависимостей
│   ├── paths.py             портативный и %LOCALAPPDATA% режимы
│   ├── log.py               ротация логов
│   ├── fsutil.py            атомарная запись
│   ├── errors.py            иерархия исключений
│   └── ui.py                консоль, цвета, таблицы
├── tests/                   91 unittest-тестов
├── packaging/               version_info, run.cmd, генератор иконки
├── assets/                  netguardian.ico / .png
├── docs/REVIEW.md           аудит версии 2.3
├── docs/PROJECT.txt         описание проекта и результатов
├── docs/HOW-IT-WORKS.txt    техническое описание проекта
├── docs/RELEASE.txt         состав релиза и чек-лист
├── README.txt               руководство для новых пользователей
├── legacy/                  исходники и spec 2.3
├── build.ps1                сборка релиза
├── NetGuardian.spec         PyInstaller (один файл)
└── NetGuardian-portable.spec PyInstaller (портативная папка)
```

## Совместимость

- Windows 10/11, Windows Server 2012+.
- Python 3.9+ (разработка и тесты — на 3.12).
- Только стандартная библиотека; Pillow нужен лишь для пересоздания иконки,
  PyInstaller — только для сборки EXE.
- Кэш версии 2.x читается автоматически и перезаписывается в формат 3.x.

## Лицензия

MIT. См. [LICENSE](LICENSE).
