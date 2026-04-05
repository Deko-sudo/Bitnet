Найдено, что ещё осталось (по приоритету)

[P1] Долгоживущий master key всё ещё хранится в AuthManager на весь unlocked-сеанс, поэтому «полного устранения» ключа из RAM архитектурно пока нет: auth_manager.py:152, auth_manager.py:237, auth_manager.py:337.
[P1] BreachMonitorService может скрывать реальные ошибки мониторинга: check_now() увеличивает счётчик даже если проверка упала, а _check_item() глотает исключения и только печатает в stdout: breach_monitor.py:605, breach_monitor.py:606, breach_monitor.py:681.
[P1] Импорт/экспорт сейчас завязан на жёстко заданные "/safe/... директории, что в реальной среде (особенно Windows) фактически ломает feature без доп. конфигурации: import_export.py:89, import_export.py:172, import_export.py:283.
[P2] Email breach-check после перезапуска процесса не сможет работать без email_resolver (runtime-кэш email не персистится) и это легко пропустить из-за п. выше: breach_monitor.py:246, breach_monitor.py:753, breach_monitor.py:776.
[P2] API-слой всё ещё не подключён (роутеры отсутствуют): main.py:24.
[P3] Остались stub-блоки (биометрия), это не уязвимость напрямую, но незавершённый security-feature: advanced_security.py:600, advanced_security.py:646.
