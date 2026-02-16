# IP Camera Testing System

В проекте есть standalone-приложение `ip-camera-testing.html` и backend авторизации.

## Быстрый старт

1. Установить зависимости:

```bash
npm install
```

2. Запустить сервер авторизации и статику:

```bash
npm run server
```

3. Открыть в браузере:

```text
http://localhost:8787
```

## Что уже реализовано

- Регистрация и вход пользователей (`/api/auth/register`, `/api/auth/login`).
- Проверка сессии (`/api/auth/me`).
- Доступ к интерфейсу тестирования только после входа.
- Изоляция данных тестов по пользователям в `localStorage`.

## Файлы

- `ip-camera-testing.html` — основной интерфейс тестирования.
- `server/index.js` — backend авторизации на Express.
- `server/data/users.json` — локальное хранилище пользователей.
