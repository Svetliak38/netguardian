"""Small dependency-free translation layer (English / Russian)."""

from __future__ import annotations

import os
from typing import Dict

DEFAULT_LANGUAGE = "en"
SUPPORTED_LANGUAGES = ("en", "ru")

_STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        # ---- common -----------------------------------------------------
        "common.yes": "y",
        "common.no": "n",
        "common.ok": "OK",
        "common.error": "Error",
        "common.warning": "Warning",
        "common.info": "Info",
        "common.none": "none",
        "common.unknown": "unknown",
        "common.cancelled": "Cancelled.",
        "common.invalid_choice": "Invalid choice.",
        "common.press_enter": "Press Enter to continue...",
        "common.interrupted": "Interrupted.",
        "common.unexpected": "Unexpected error: {error}",
        "common.windows_only": "NetGuardian targets Windows; this operating system is not supported.",
        "common.admin": "administrator",
        "common.not_admin": "standard user",
        "common.done": "Done.",
        "common.nothing": "Nothing to do.",
        "common.dry_run": "Dry run: nothing was written.",
        "common.yesno_hint": "Please answer y or n.",
        "common.back": "Back",
        "app.tagline": "Adaptive route manager | Initiated by Svetliak",
        "settings.open_folder": "Open the data folder? (y/n): ",
        # ---- configuration ---------------------------------------------
        "config.created": "Created default configuration: {path}",
        "config.loaded": "Configuration: {path}",
        "config.invalid": "Invalid configuration in {path}: {reason}",
        "config.missing": "Configuration file not found: {path}",
        "config.hint": "Fix the file or pass --config PATH. Run 'netguardian config --check' for details.",
        "config.valid": "Configuration is valid: {profiles} profile(s), {domains} domain(s).",
        "config.current": "Configuration: {path}",
        "config.profiles": "Profiles: {names}",
        "config.settings": "Settings: {settings}",
        "config.language": "Language: {language}",
        # ---- administrator / elevation ---------------------------------
        "admin.required": "This operation needs administrator rights to modify the hosts file.",
        "admin.hint": "Restart NetGuardian as administrator (right-click -> Run as administrator).",
        "admin.elevate_question": "Restart NetGuardian with administrator rights now? (y/n): ",
        "admin.elevate_failed": "Could not start the elevated instance: {error}",
        "admin.elevated_continue": "Continuing in the elevated window.",
        # ---- menu -------------------------------------------------------
        "menu.title": "CONTROL CENTER",
        "menu.scan": "[1] Scan for stuck connections",
        "menu.apply": "[2] Apply a profile",
        "menu.validate": "[3] Validate routes (TLS)",
        "menu.cleanup": "[4] Clean up fixes",
        "menu.tcpview": "[5] Launch TCPView",
        "menu.diag": "[6] Diagnose a connection",
        "menu.status": "[7] Status and active fixes",
        "menu.backups": "[8] Backups and restore",
        "menu.settings": "[9] Settings",
        "menu.lang": "[L] Switch language / Язык",
        "menu.exit": "[0] Exit",
        "menu.prompt": "Select an option: ",
        "menu.header_mode": "Mode: {admin} | Data: {data}",
        # ---- scan -------------------------------------------------------
        "scan.running": "Scanning active connections...",
        "scan.none": "No stuck connections detected.",
        "scan.found": "Stuck connections found: {count}",
        "scan.header": "PID      PROCESS                STATE        REMOTE",
        "scan.match": "Best matching profile: {profile}",
        "scan.no_match": "No profile matches this process.",
        "scan.confirm": "Apply profile '{profile}' now? (y/n): ",
        "scan.failed": "Could not read the connection table: {error}",
        # ---- apply ------------------------------------------------------
        "apply.select": "Available profiles:",
        "apply.prompt": "Select a profile number: ",
        "apply.bad_selection": "Invalid profile selection.",
        "apply.start": "Resolving addresses for profile '{profile}'...",
        "apply.domain_ok": "  {domain} -> {ip} ({source})",
        "apply.domain_missing": "  {domain} -> no reachable address, skipped",
        "apply.nothing": "No reachable addresses found; the hosts file was not changed.",
        "apply.blocked_conflict": "Existing hosts entry conflicts with the planned route: {line}",
        "apply.conflict_hint": "Remove or comment that line first, or pass --force to override.",
        "apply.written": "Profile '{profile}' applied: {count} entr(y/ies).",
        "apply.unchanged": "Profile '{profile}' is already up to date.",
        "apply.verify_start": "Verifying the pinned routes over TLS...",
        "apply.verify_ok": "Route verified: {domain} ({ip})",
        "apply.verify_failed": "Route verification failed for {domain}: {reason}",
        "apply.rolled_back": "Changes rolled back; the hosts file is unchanged.",
        "apply.rollback_failed": "Rollback failed ({error}); restore a backup manually.",
        "apply.failed": "Could not apply the profile: {error}",
        "apply.no_profiles": "No profiles are defined in the configuration.",
        "apply.conflict_count": "{count} conflicting hosts line(s) detected.",
        # ---- cleanup ----------------------------------------------------
        "cleanup.none": "No NetGuardian blocks are present in the hosts file.",
        "cleanup.confirm_all": "Remove ALL NetGuardian fixes from the hosts file? (y/n): ",
        "cleanup.confirm_one": "Remove the '{profile}' fix? (y/n): ",
        "cleanup.done": "Removed {count} block(s) from the hosts file.",
        "cleanup.select": "Which fix should be removed?",
        "cleanup.all": "[A] All fixes",
        "cleanup.back": "[0] Cancel",
        "cleanup.need_target": "Specify a profile name, or --all to remove every NetGuardian fix.",
        # ---- prune ------------------------------------------------------
        "prune.header": "Checking pinned entries...",
        "prune.no_blocks": "No NetGuardian blocks to prune.",
        "prune.none": "Every pinned entry answers on TCP; nothing to prune.",
        "prune.dead": "  {domain} -> {ip}: no TCP answer",
        "prune.broken": "  {domain} -> {ip}: TCP open, TLS not confirmed ({reason})",
        "prune.keep": "  {domain} -> {ip}: ok",
        "prune.summary": "dead: {dead}, broken: {broken}, kept: {keep}.",
        "prune.confirm": "Remove {count} pinned entr(y/ies) from the hosts file? (y/n): ",
        "prune.done": "Pruned {count} entr(y/ies) from the hosts file.",
        "prune.dry_run": "Dry run: the hosts file was not changed.",
        "prune.verified": "Verified: no dead entries left for the affected profiles.",
        "prune.verify_failed": "Pruning verification failed: {error}",
        "prune.need_target": "Specify a profile name, or --all to prune every NetGuardian block.",
        "prune.foreign": "  line {line}: {domain} -> {ip} is not usable (not created by NetGuardian, left untouched)",
        "prune.foreign_broken": "  line {line}: {domain} -> {ip} answers TCP but fails TLS ({reason}); not created by NetGuardian, left untouched",
        "apply.not_fixable": "Profile '{profile}' is diagnostics-only, nothing was written.",
        "apply.not_fixable_reason": "TCP connects but TLS is reset - this is filtering, not a stale address, so pinning a different IP cannot help.",
        "apply.not_fixable_hint": "Run 'netguardian diag {domain}' for details, or delete this profile if you do not need it.",
        # ---- validate ---------------------------------------------------
        "validate.running": "Validating pinned routes...",
        "validate.ok": "  {domain}: secure ({issuer})",
        "validate.untrusted": "  {domain}: UNTRUSTED - {reason}",
        "validate.unreachable": "  {domain}: unreachable at {ip}",
        "validate.no_profile": "No profile named '{profile}'.",
        "validate.summary": "Validated {ok}/{total} route(s).",
        "validate.issuer_mismatch": "issuer '{issuer}' does not match expected: {expected}",
        "validate.expires": "certificate expires in {days} day(s)",
        # ---- diagnostics ------------------------------------------------
        "diag.prompt": "Domain or URL to test: ",
        "diag.running": "Diagnosing {domain}...",
        "diag.hosts": "Hosts override: {value}",
        "diag.no_hosts": "Hosts override: none",
        "diag.dns_system": "System DNS: {ips}",
        "diag.dns_local": "Local DNS {server}: {ips}",
        "diag.dns_fail": "DNS resolution failed: {error}",
        "diag.tcp": "TCP {ip}:{port}: {state}",
        "diag.tcp_ok": "open",
        "diag.tcp_fail": "closed/timeout",
        "diag.tls": "TLS handshake: {state}",
        "diag.tls_ok": "ok",
        "diag.tls_fail": "failed",
        "diag.cert": "Certificate: {subject} | issuer: {issuer} | expires in {days} day(s)",
        "diag.proxy": "System proxy: {value}",
        "diag.proxy_off": "System proxy: disabled",
        "diag.verdict": "Verdict: {verdict}",
        "diag.verdict_ok": "the route looks healthy",
        "diag.verdict_dns": "name resolution is the problem",
        "diag.verdict_tcp": "addresses are unreachable; a different IP or network is needed",
        "diag.verdict_tls": "TCP works but TLS fails; the connection is likely intercepted",
        "diag.verdict_hosts": "a stale hosts entry is hijacking the name",
        "diag.hint": "Suggested action: {action}",
        "diag.action_ok": "nothing to do",
        "diag.action_apply": "apply the profile that owns this domain",
        "diag.action_cleanup": "run cleanup to remove stale entries",
        "diag.action_proxy": "check the system proxy or VPN",
        "diag.action_network": "check the network, then try another profile",
        # ---- status -----------------------------------------------------
        "status.title": "NetGuardian status",
        "status.hosts": "Hosts file: {path}",
        "status.hosts_missing": "Hosts file not found: {path}",
        "status.blocks": "Active fixes: {count}",
        "status.block": "  [{profile}] {count} entr(y/ies), updated {ts}",
        "status.entry": "    {ip} {domain}",
        "status.no_blocks": "No active fixes.",
        "status.cache": "Cached addresses: {count}",
        "status.cache_entry": "    {domain} -> {ip} ({age})",
        "status.cache_empty": "Cache is empty.",
        "status.backups": "Hosts backups: {count}",
        "status.config": "Configuration: {path}",
        "status.profiles": "Profiles: {count}",
        # ---- backups ----------------------------------------------------
        "backups.none": "No backups found.",
        "backups.title": "Available hosts backups:",
        "backups.restored": "Hosts file restored from {name}.",
        "backups.invalid": "Not a valid NetGuardian backup: {path}",
        "backups.confirm": "Restore {name} over the current hosts file? (y/n): ",
        "backups.created": "Backup created: {path}",
        # ---- language ---------------------------------------------------
        "lang.changed": "Language: {language}",
        "lang.invalid": "Unsupported language '{code}'; available: en, ru.",
        "lang.current": "Current language: {language}",
        # ---- TCPView ----------------------------------------------------
        "tcpview.found": "TCPView found: {path}",
        "tcpview.downloading": "Downloading TCPView from {url}...",
        "tcpview.downloaded": "TCPView downloaded: {path}",
        "tcpview.verifying": "Checking the digital signature...",
        "tcpview.signature_ok": "Signature valid: {signer}",
        "tcpview.signature_bad": "Signature check failed: {reason}",
        "tcpview.unsigned_blocked": "Refusing to run an unsigned TCPView. Use --allow-unsigned only if you trust the file.",
        "tcpview.launched": "TCPView launched.",
        "tcpview.failed": "Could not launch TCPView: {error}",
        "tcpview.manual": "Download TCPView manually: {url}",
        "tcpview.unavailable": "Could not download TCPView: {error}",
        # ---- hosts / io errors -----------------------------------------
        "error.hosts_denied": "Access denied while writing {path}. Administrator rights are required.",
        "error.hosts_read": "Could not read {path}: {error}",
        "error.hosts_write": "Could not write {path}: {error}",
        "error.hosts_malformed": "Broken NetGuardian block at line {line}; refusing to modify the file. Fix or remove it (or pass --force).",
        "error.restore": "Could not restore {path}: {error}",
        "error.backup": "Could not create a backup: {error}",
    },
    "ru": {
        # ---- common -----------------------------------------------------
        "common.yes": "д",
        "common.no": "н",
        "common.ok": "OK",
        "common.error": "Ошибка",
        "common.warning": "Внимание",
        "common.info": "Инфо",
        "common.none": "нет",
        "common.unknown": "неизвестно",
        "common.cancelled": "Отменено.",
        "common.invalid_choice": "Неверный выбор.",
        "common.press_enter": "Нажмите Enter, чтобы продолжить...",
        "common.interrupted": "Прервано.",
        "common.unexpected": "Непредвиденная ошибка: {error}",
        "common.windows_only": "NetGuardian предназначен для Windows; эта система не поддерживается.",
        "common.admin": "администратор",
        "common.not_admin": "обычный пользователь",
        "common.done": "Готово.",
        "common.nothing": "Делать нечего.",
        "common.dry_run": "Пробный запуск: ничего не записано.",
        "common.yesno_hint": "Ответьте «д» или «н».",
        "common.back": "Назад",
        "app.tagline": "Адаптивный диспетчер маршрутов | Инициатор: Svetliak",
        "settings.open_folder": "Открыть папку с данными? (д/н): ",
        # ---- configuration ---------------------------------------------
        "config.created": "Создана конфигурация по умолчанию: {path}",
        "config.loaded": "Конфигурация: {path}",
        "config.invalid": "Ошибка в конфигурации {path}: {reason}",
        "config.missing": "Файл конфигурации не найден: {path}",
        "config.hint": "Исправьте файл или укажите --config ПУТЬ. Подробности: netguardian config --check.",
        "config.valid": "Конфигурация корректна: профилей — {profiles}, доменов — {domains}.",
        "config.current": "Конфигурация: {path}",
        "config.profiles": "Профили: {names}",
        "config.settings": "Параметры: {settings}",
        "config.language": "Язык: {language}",
        # ---- administrator / elevation ---------------------------------
        "admin.required": "Для изменения файла hosts нужны права администратора.",
        "admin.hint": "Перезапустите NetGuardian от имени администратора (правый клик -> «Запуск от имени администратора»).",
        "admin.elevate_question": "Перезапустить NetGuardian с правами администратора сейчас? (д/н): ",
        "admin.elevate_failed": "Не удалось запустить копию с повышенными правами: {error}",
        "admin.elevated_continue": "Продолжаем в новом окне с правами администратора.",
        # ---- menu -------------------------------------------------------
        "menu.title": "ЦЕНТР УПРАВЛЕНИЯ",
        "menu.scan": "[1] Поиск зависших соединений",
        "menu.apply": "[2] Применить профиль",
        "menu.validate": "[3] Проверить маршруты (TLS)",
        "menu.cleanup": "[4] Удалить исправления",
        "menu.tcpview": "[5] Запустить TCPView",
        "menu.diag": "[6] Диагностика соединения",
        "menu.status": "[7] Состояние и активные исправления",
        "menu.backups": "[8] Резервные копии и восстановление",
        "menu.settings": "[9] Настройки",
        "menu.lang": "[L] Переключить язык / Language",
        "menu.exit": "[0] Выход",
        "menu.prompt": "Выберите пункт: ",
        "menu.header_mode": "Режим: {admin} | Данные: {data}",
        # ---- scan -------------------------------------------------------
        "scan.running": "Сканирование активных соединений...",
        "scan.none": "Зависших соединений не обнаружено.",
        "scan.found": "Найдено зависших соединений: {count}",
        "scan.header": "PID      ПРОЦЕСС                СОСТОЯНИЕ    УДАЛЁННЫЙ АДРЕС",
        "scan.match": "Лучший профиль: {profile}",
        "scan.no_match": "Ни один профиль не подходит к этому процессу.",
        "scan.confirm": "Применить профиль «{profile}» сейчас? (д/н): ",
        "scan.failed": "Не удалось прочитать таблицу соединений: {error}",
        # ---- apply ------------------------------------------------------
        "apply.select": "Доступные профили:",
        "apply.prompt": "Выберите номер профиля: ",
        "apply.bad_selection": "Неверный выбор профиля.",
        "apply.start": "Поиск адресов для профиля «{profile}»...",
        "apply.domain_ok": "  {domain} -> {ip} ({source})",
        "apply.domain_missing": "  {domain} -> нет доступного адреса, пропуск",
        "apply.nothing": "Доступных адресов не найдено; файл hosts не изменён.",
        "apply.blocked_conflict": "В hosts уже есть конфликтующая строка: {line}",
        "apply.conflict_hint": "Удалите или закомментируйте её, либо укажите --force.",
        "apply.written": "Профиль «{profile}» применён: записей — {count}.",
        "apply.unchanged": "Профиль «{profile}» уже применён и актуален.",
        "apply.verify_start": "Проверка закреплённых маршрутов по TLS...",
        "apply.verify_ok": "Маршрут проверен: {domain} ({ip})",
        "apply.verify_failed": "Проверка маршрута не удалась для {domain}: {reason}",
        "apply.rolled_back": "Изменения откатаны; файл hosts остался прежним.",
        "apply.rollback_failed": "Не удалось откатить изменения ({error}); восстановите резервную копию вручную.",
        "apply.failed": "Не удалось применить профиль: {error}",
        "apply.no_profiles": "В конфигурации нет ни одного профиля.",
        "apply.conflict_count": "Найдено конфликтующих строк в hosts: {count}.",
        # ---- cleanup ----------------------------------------------------
        "cleanup.none": "В файле hosts нет блоков NetGuardian.",
        "cleanup.confirm_all": "Удалить ВСЕ исправления NetGuardian из hosts? (д/н): ",
        "cleanup.confirm_one": "Удалить исправление «{profile}»? (д/н): ",
        "cleanup.done": "Удалено блоков из hosts: {count}.",
        "cleanup.select": "Какое исправление удалить?",
        "cleanup.all": "[A] Все исправления",
        "cleanup.back": "[0] Отмена",
        "cleanup.need_target": "Укажите имя профиля или --all, чтобы удалить все исправления NetGuardian.",
        # ---- prune ------------------------------------------------------
        "prune.header": "Проверка закреплённых записей...",
        "prune.no_blocks": "Нет блоков NetGuardian для чистки.",
        "prune.none": "Все закреплённые записи отвечают по TCP; чистить нечего.",
        "prune.dead": "  {domain} -> {ip}: TCP не отвечает",
        "prune.broken": "  {domain} -> {ip}: TCP открыт, TLS не подтверждён ({reason})",
        "prune.keep": "  {domain} -> {ip}: ok",
        "prune.summary": "мёртвых: {dead}, битых: {broken}, оставлено: {keep}.",
        "prune.confirm": "Удалить закреплённых записей: {count}? (y/n): ",
        "prune.done": "Удалено записей из hosts: {count}.",
        "prune.dry_run": "Холостой прогон: файл hosts не изменён.",
        "prune.verified": "Проверено: мёртвых записей по затронутым профилям не осталось.",
        "prune.verify_failed": "Проверка после чистки не прошла: {error}",
        "prune.need_target": "Укажите имя профиля или --all, чтобы почистить все блоки NetGuardian.",
        "prune.foreign": "  строка {line}: {domain} -> {ip} не работает (запись не от NetGuardian, не трогаю)",
        "prune.foreign_broken": "  строка {line}: {domain} -> {ip} отвечает по TCP, но TLS не проходит ({reason}); запись не от NetGuardian, не трогаю",
        "apply.not_fixable": "Профиль '{profile}' только для диагностики, запись не выполнялась.",
        "apply.not_fixable_reason": "TCP открывается, но TLS рвётся — это фильтрация, а не устаревший адрес; закрепление другого IP не поможет.",
        "apply.not_fixable_hint": "Запустите 'netguardian diag {domain}' для деталей или удалите этот профиль, если он не нужен.",
        # ---- validate ---------------------------------------------------
        "validate.running": "Проверка закреплённых маршрутов...",
        "validate.ok": "  {domain}: защищено ({issuer})",
        "validate.untrusted": "  {domain}: НЕ ДОВЕРЯТЬ — {reason}",
        "validate.unreachable": "  {domain}: недоступен по адресу {ip}",
        "validate.no_profile": "Профиль «{profile}» не найден.",
        "validate.summary": "Проверено маршрутов: {ok}/{total}.",
        "validate.issuer_mismatch": "издатель «{issuer}» не соответствует ожидаемым: {expected}",
        "validate.expires": "сертификат истекает через {days} дн.",
        # ---- diagnostics ------------------------------------------------
        "diag.prompt": "Домен или URL для проверки: ",
        "diag.running": "Диагностика {domain}...",
        "diag.hosts": "Запись в hosts: {value}",
        "diag.no_hosts": "Записи в hosts: нет",
        "diag.dns_system": "Системный DNS: {ips}",
        "diag.dns_local": "Локальный DNS {server}: {ips}",
        "diag.dns_fail": "Не удалось разрешить имя: {error}",
        "diag.tcp": "TCP {ip}:{port}: {state}",
        "diag.tcp_ok": "открыт",
        "diag.tcp_fail": "закрыт/таймаут",
        "diag.tls": "TLS-рукопожатие: {state}",
        "diag.tls_ok": "успешно",
        "diag.tls_fail": "ошибка",
        "diag.cert": "Сертификат: {subject} | издатель: {issuer} | истекает через {days} дн.",
        "diag.proxy": "Системный прокси: {value}",
        "diag.proxy_off": "Системный прокси: выключен",
        "diag.verdict": "Вердикт: {verdict}",
        "diag.verdict_ok": "маршрут выглядит исправным",
        "diag.verdict_dns": "проблема в разрешении имён",
        "diag.verdict_tcp": "адреса недоступны; нужен другой IP или сеть",
        "diag.verdict_tls": "TCP работает, но TLS падает; вероятна перехват/подмена",
        "diag.verdict_hosts": "устаревшая запись в hosts подменяет имя",
        "diag.hint": "Рекомендация: {action}",
        "diag.action_ok": "ничего делать не нужно",
        "diag.action_apply": "примените профиль, которому принадлежит домен",
        "diag.action_cleanup": "запустите очистку, чтобы убрать устаревшие записи",
        "diag.action_proxy": "проверьте системный прокси или VPN",
        "diag.action_network": "проверьте сеть и попробуйте другой профиль",
        # ---- status -----------------------------------------------------
        "status.title": "Состояние NetGuardian",
        "status.hosts": "Файл hosts: {path}",
        "status.hosts_missing": "Файл hosts не найден: {path}",
        "status.blocks": "Активные исправления: {count}",
        "status.block": "  [{profile}] записей — {count}, обновлено {ts}",
        "status.entry": "    {ip} {domain}",
        "status.no_blocks": "Активных исправлений нет.",
        "status.cache": "Кэш адресов: {count}",
        "status.cache_entry": "    {domain} -> {ip} ({age})",
        "status.cache_empty": "Кэш пуст.",
        "status.backups": "Резервных копий hosts: {count}",
        "status.config": "Конфигурация: {path}",
        "status.profiles": "Профилей: {count}",
        # ---- backups ----------------------------------------------------
        "backups.none": "Резервных копий не найдено.",
        "backups.title": "Доступные резервные копии hosts:",
        "backups.restored": "Файл hosts восстановлен из {name}.",
        "backups.invalid": "Это не резервная копия NetGuardian: {path}",
        "backups.confirm": "Восстановить {name} поверх текущего hosts? (д/н): ",
        "backups.created": "Создана резервная копия: {path}",
        # ---- language ---------------------------------------------------
        "lang.changed": "Язык: {language}",
        "lang.invalid": "Неподдерживаемый язык «{code}»; доступны: en, ru.",
        "lang.current": "Текущий язык: {language}",
        # ---- TCPView ----------------------------------------------------
        "tcpview.found": "TCPView найден: {path}",
        "tcpview.downloading": "Загрузка TCPView с {url}...",
        "tcpview.downloaded": "TCPView загружен: {path}",
        "tcpview.verifying": "Проверка цифровой подписи...",
        "tcpview.signature_ok": "Подпись действительна: {signer}",
        "tcpview.signature_bad": "Проверка подписи не удалась: {reason}",
        "tcpview.unsigned_blocked": "Запуск TCPView без подписи запрещён. Используйте --allow-unsigned, только если доверяете файлу.",
        "tcpview.launched": "TCPView запущен.",
        "tcpview.failed": "Не удалось запустить TCPView: {error}",
        "tcpview.manual": "Скачайте TCPView вручную: {url}",
        "tcpview.unavailable": "Не удалось загрузить TCPView: {error}",
        # ---- hosts / io errors -----------------------------------------
        "error.hosts_denied": "Доступ к {path} запрещён. Нужны права администратора.",
        "error.hosts_read": "Не удалось прочитать {path}: {error}",
        "error.hosts_write": "Не удалось записать {path}: {error}",
        "error.hosts_malformed": "Повреждённый блок NetGuardian в строке {line}; файл не изменялся. Исправьте или удалите его (либо укажите --force).",
        "error.restore": "Не удалось восстановить {path}: {error}",
        "error.backup": "Не удалось создать резервную копию: {error}",
    },
}


def _normalise(code: str) -> str:
    code = (code or "").strip().lower().replace("_", "-")
    if "-" in code:
        code = code.split("-", 1)[0]
    return code


def normalize_language(code: str) -> str:
    """Map user input such as ``ru-RU`` / ``EN`` to a supported code."""
    code = _normalise(code)
    return code if code in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def detect_system_language() -> str:
    """Best-effort detection of the Windows UI language."""
    env = os.environ.get("NETGUARDIAN_LANG") or os.environ.get("LANG")
    if env:
        return normalize_language(env)
    try:
        import ctypes

        lang_id = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        if (lang_id & 0x3FF) == 0x19:  # LANG_RUSSIAN
            return "ru"
    except Exception:
        pass
    return DEFAULT_LANGUAGE


class _State:
    language = DEFAULT_LANGUAGE


def set_language(code: str) -> str:
    _State.language = normalize_language(code)
    return _State.language


def get_language() -> str:
    return _State.language


def available_languages():
    return SUPPORTED_LANGUAGES


def t(key: str, **kwargs) -> str:
    """Translate *key* into the active language with optional formatting."""
    catalog = _STRINGS.get(_State.language) or _STRINGS[DEFAULT_LANGUAGE]
    text = catalog.get(key) or _STRINGS[DEFAULT_LANGUAGE].get(key) or key
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            return text
    return text


def catalog(language: str = "") -> Dict[str, str]:
    """Expose a catalog copy (used by tests and tooling)."""
    return dict(_STRINGS.get(normalize_language(language or _State.language), _STRINGS[DEFAULT_LANGUAGE]))


def language_name(code: str = "") -> str:
    code = normalize_language(code or _State.language)
    return {"en": "English", "ru": "Русский"}.get(code, code)


__all__ = [
    "DEFAULT_LANGUAGE",
    "SUPPORTED_LANGUAGES",
    "available_languages",
    "catalog",
    "detect_system_language",
    "get_language",
    "language_name",
    "normalize_language",
    "set_language",
    "t",
]
