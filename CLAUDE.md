# boiller — правила проєкту

## Структура
- `boiller.py` — контролер: раз на 60 с читає інвертор Deye (Modbus через pysolarmanv5) і вмикає/вимикає бойлер через розетку Xiaomi. Пише історію в `data_history.json` через `data_storage.py`.
- `web_server.py` — Flask: графіки (`templates/index.html`), API `/api/data`, `/api/latest`, роздача APK з `app/` через `/download/<file>`.
- Запуск у Docker: `docker compose up -d check web` (`check` — контролер, `web` — сервер на порту 8080).
- Android-додаток «Світлячок» живе в сусідньому репозиторії `../boiller_app`. Тут лежить лише готовий `app/boiller-monitor.apk`.

## Як оновлювати APK
1. Код міняти в `../boiller_app` (Kotlin, `app/src/main/java/com/boiller/monitor/`).
2. Підняти `versionCode` і `versionName` у `../boiller_app/app/build.gradle.kts`.
3. Збирати **тільки чисто**: `./gradlew clean assembleDebug`. Без `clean` інкрементальне пакування лишає в zip «дірки» на ~1 МБ.
4. Використовувати саме **debug**-збірку: release не має signingConfig і не підписаний, а на телефоні вже стоїть версія з debug-підписом. Інший підпис не встановиться поверх.
5. Скопіювати `app/build/outputs/apk/debug/boiller-monitor-debug-<version>.apk` → `app/boiller-monitor.apk` (ім'я фіксоване, бо його тягне `/download/`).
6. Перевірити підпис: `apksigner verify --print-certs app/boiller-monitor.apk` (очікується `CN=Android Debug`). `apksigner` лежить в `~/Library/Android/sdk/build-tools/<ver>/`.

## Сповіщення в додатку (NotificationService.kt)
- Канали: `status` (тихий, постійний), `change` (гучний), `change_quiet` (тихий, поза дозволеними годинами).
- Дозволені години для звуку задаються в налаштуваннях і стосуються лише сповіщень про зміну світла.
- Алерт «Інвертор завис?» (значення не змінюються 10 хв) іде завжди на гучний канал, уночі теж. Не додавати йому перевірку годин.

## Git
- Не робити `git commit` / `git push` без явного прохання. «Збережи зміни» означає зберегти файли.
