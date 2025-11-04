FastAPI-приложение для управления пользователями, ролями, правами доступа. Включает интеграцию с базой данных (SQLite), JWT-аутентификацию, двухфакторную аутентификацию (OAuth 2.0), систему ролей и разрешений, а также модуль парсинга, анализа данных с загрузкой CSV/Excel файлов.

## Документация по API роутам

### Авторизация и аккаунт (`/auth`)
- **POST /auth/register** — регистрация нового пользователя
- **POST /auth/login** — вход пользователя по логину/паролю (jwt)
- **POST /auth/out** — разлогин текущего токена
- **POST /auth/out_all** — разлогин всех токенов пользователя
- **POST /auth/refresh** — получить новый access-токен по refresh-токену
- **GET  /auth/me** — инфо о текущем пользователе по токену
- **POST /auth/change_password** — смена пароля
- **GET  /auth/tokens** — получить все активные токены
- **POST /auth/2fa/generate** — создать код 2FA 
- **POST /auth/2fa/verify** — подтвердить 2FA и получить полный токен
- **POST /auth/2fa/toggle** — включить/выключить двухфакторку

### Пользователи, роли и права (`/api/ref/*`)
- **GET  /api/ref/user/** — список пользователей
- **GET  /api/ref/user/{id}/role** — список ролей пользователя
- **PUT  /api/ref/user/{user_id}/role/{role_id}** — выдать роль пользователю
- **DELETE /api/ref/{user}/{role}** — удалить роль у пользователя

#### Роли
- **POST   /api/ref/policy/role** — создать роль
- **GET    /api/ref/policy/role** — список ролей
- **GET    /api/ref/policy/role/{id}** — получить роль
- **PUT    /api/ref/policy/role/{id}** — обновить роль
- **DELETE /api/ref/policy/role/{id}** — жёстко удалить роль
- **DELETE /api/ref/policy/role/{id}/soft** — мягко удалить роль
- **POST   /api/ref/policy/role/{role_id}/restore** — восстановить мягко удалённую роль
- **POST   /api/ref/policy/role/{role_id}/permission/{permission_id}** — привязать разрешение к роли

#### Права
- **POST   /api/ref/policy/permission** — создать разрешение
- **GET    /api/ref/policy/permission** — список разрешений
- **GET    /api/ref/policy/permission/{id}** — получить разрешение
- **PUT    /api/ref/policy/permission/{id}** — обновить разрешение
- **DELETE /api/ref/policy/permission/{id}** — жёстко удалить разрешение
- **DELETE /api/ref/policy/permission/{id}/soft** — мягко удалить разрешение
- **POST   /api/ref/policy/permission/{id}/restore** — восстановить мягко удалённое разрешение

### Журнал изменений и восстановление
- **GET  /api/ref/user/{id}/story** — история изменений пользователя
- **GET  /api/ref/policy/roles/{id}/story** — история изменений конкретной роли
- **GET  /api/ref/policy/permission/{id}/story** — история изменений разрешения
- **POST /api/ref/log/{log_id}/restore** — восстановить прошлое состояние из лога

### Работа с БД (технические)
- **POST /database/setup** — пересоздать все таблицы
- **POST /database/create_tables** — создать таблицы, не удаляя старые
- **POST /database/drop_tables** — удалить все таблицы
- **POST /seed** — сидирование БД 

### Информационные роуты (`/info`)
- **GET /info/server** — инфо о сервере
- **GET /info/client** — ip и user-agent клиента
- **GET /info/database** — какая бд используется

### Модуль парсинга посещаемости (`/visits`)
- **POST /visits/check** — анализ посещаемости из файла csv/xlsx (вне основной темы ролевой системы)
