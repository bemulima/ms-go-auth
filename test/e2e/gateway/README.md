# E2E (Gateway) — ms-go-auth

Тесты проверяют флоу из `wiki/AUTHENTICATION.md`, выполняя реальные запросы только через `ms-getway`.

## Требования
- Запущены контейнеры (gateway + auth + зависимости).
- Доступен student/guest gateway: `${GATEWAY_URL}` (по умолчанию `http://localhost:8080`).

## Переменные окружения
- `GATEWAY_URL` — base URL для student/guest gateway.
- `ADMIN_GATEWAY_URL` — base URL для admin gateway (не используется в этом наборе).
- `HTTP_TIMEOUT` — таймаут curl (сек), по умолчанию `30`.
- `DEBUG=1` — подробный вывод.
- `MISMATCHES_OUT` — путь к файлу, куда дописывать найденные несоответствия (markdown).

## Запуск
```bash
cd ms-go-auth
bash test/e2e/gateway/run-tests.sh
```
