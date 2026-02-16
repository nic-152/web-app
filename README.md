# IP Camera Testing System

Приложение для командного тестирования IP-камер с авторизацией, проектами и ролями доступа.

## Запуск

```bash
cd /home/error/web-app
npm install
npm run server
```

Открыть в браузере: `http://localhost:8787`

## Что реализовано

- Регистрация и вход пользователей.
- Проекты команды с ролями:
  - `owner` — полный доступ + выдача прав.
  - `editor` — редактирование тестов и сохранение.
  - `viewer` — только просмотр.
- Общий прогресс тестирования хранится на сервере по проекту.
- Автосохранение и ручные кнопки сохранения/загрузки.
- Экспорт отчёта TXT из текущего состояния проекта.

## API

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/projects`
- `POST /api/projects`
- `POST /api/projects/:projectId/members` (только `owner`)
- `GET /api/projects/:projectId/members`
- `PATCH /api/projects/:projectId/members/:userId` (только `owner`)
- `DELETE /api/projects/:projectId/members/:userId` (только `owner`)
- `GET /api/projects/:projectId/session`
- `PUT /api/projects/:projectId/session` (`owner`/`editor`)

## Файлы

- `ip-camera-testing.html` — основной интерфейс.
- `server/index.js` — backend API.
- `server/data/users.json` — пользователи.
- `server/data/projects.json` — проекты, роли и сессии.
