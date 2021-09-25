WebSocket API
-
**Модуль** для [Апостол](https://github.com/ufocomp/apostol-crm).

Описание
-
* **WebSocket API** предоставляет возможность подключения к API системы по протоколу [WebSocket](https://ru.wikipedia.org/wiki/WebSocket).

Установка
-
Следуйте указаниям по сборке и установке [Апостол](https://github.com/ufocomp/apostol-crm#%D1%81%D0%B1%D0%BE%D1%80%D0%BA%D0%B0-%D0%B8-%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0)

Описание
-

## Запрос клиента

Чтобы установить с сервером соединение WebSocket, клиентское приложение должно выполнить «Рукопожатие» («Opening Handshake»), как описано в [RFC6455](https://tools.ietf.org/html/rfc6455) [раздел 4](https://tools.ietf.org/html/rfc6455#section-4).

Сервер накладывает дополнительные ограничения на URL-адрес и подпротокол WebSocket, подробно описанные ниже.

### URL подключения

Чтобы инициировать соединение WebSocket, клиенту требуется URL-адрес [RFC3986](https://tools.ietf.org/html/rfc3986) для подключения (URL подключения).

[Взаимодействие с системой](https://github.com/ufocomp/module-AppServer#%D0%B4%D0%BE%D1%81%D1%82%D1%83%D0%BF-%D0%BA-api) происходит в рамках ранее созданной сессии. Сессия создается после успешной аутентификации пользователя в системе. Результатом которой является получение маркера доступа, идентификатора сессии и секретного ключа.

URL подключения содержит в себе код сессии и идентификатор сеанса связи.

Формат URL подключения:
````
ws[s]://[ws.]exemple.com/session/<code>[/<identity>]
````
* Где:
  `<code>` - **Обязательный**. Код сессии (40 символов);
  `<identity>` - **Необязательный**. Идентификатор сеанса связи в рамках сессии. Используется для установки нескольких соединений к одной сессии.

Пример:
````
wss://ws.exemple.com/session/c83b2f85321f95341707624546ca6ac4fa6d1115
````

````
wss://ws.exemple.com/session/c83b2f85321f95341707624546ca6ac4fa6d1115/user1
````

## RPC framework

Протокол WebSocket сам по себе не дает возможности отправлять сообщения в режиме запрос/ответ. Чтобы обеспечить эту возможность был создан небольшой RPC протокол поверх WebSocket в формате JSON.

### Описание JSON ключей

Ключ | Расшифровка | Тип данных | Назначение, примечания
----- | ----------- | ---------- | ----------------------
t | MessageTypeId | INTEGER | Тип сообщения. Описание ниже.
u | UniqueId | UUID | Уникальный идентификатор сообщения. Если сообщение от сервера является ответом на запрос от клиента, то UniqueId будет одинаковым.
a | Action | STRING | Действие (маршрут к конечной точке API).
c | ErrorCode | INTEGER | Код ошибки.
m | ErrorMessage | STRING |  Сообщение об ошибке.
p | Payload | JSON | Полезная нагрузка.

### Тип сообщения (MessageTypeId):

Тип сообщения | Номер типа сообщения | Направление | Описание
----- | ----------- | ---------- | ----------------------
OPEN | 0 | Клиент -> Сервер | Авторизация. Открытие ранее созданной сессии.
CLOSE | 1 | Клиент -> Сервер | Закрытие сессии (выход из системы).
CALL | 2 | Клиент <-> Сервер | Запрос.
CALLRESULT | 3 | Сервер -> Клиент | Ответ на запрос.
CALLERROR | 4 | Сервер -> Клиент | Ответ на запрос с ошибкой.

## Авторизация

* После подключения клиенты нужно авторизоваться.

Авторизация может быть выполнена в автоматическом режиме при условии, если в момент установки связи были указаны соответствующие HTTP-заголовки:

- `Authorization: Bearer <token>`

Или:

- `Session: <session>`
- `Secret: <secret>`

Если заполнение HTTP-заголовков блокируется на стороне используемого, клиентским приложением, фрейворком, то авторизация выполняется путем отправки пакета `OPEN` с данными авторизации (которые выдал [сервер авторизации](https://github.com/ufocomp/module-AuthServer)) это может быть или маркер доступа (`token`) или секретный код сессии `secret`.

После успешной авторизации Вы сможете отправлять API запросы с типом сообщения `CALL`. Где маршрут к конечной точке API указывается в ключе `Action`, а JSON тело запроса в ключе `Payload`.

Попытка отправить запрос до выполнения успешной процедуры авторизации приведет к ответу с типом сообщения `CALLERROR`:

**Пример:**

Если код сессии указан не верно или сессия была закрыта то ответ будет с типом сообщения `CALLERROR`:
````json
{"t":4,"u":"<uuid>","c":400,"m":"Код сессии не найден."}
````

Авторизация по секретному коду сессии:
````json
{"t":0,"u":"<uuid>","p":{"secret": "MWCJ14k/RJyiHskQB8DoVbliiwDeNGKsgsAMugp3OZt+M0Zj44hDykwRuFoWEwuG"}}
````

Положительный ответ:
````json
{"t":3,"u":"<uuid>","p":{"authorized": true, "code": "amAJmzkxvDE+ad7KwkRtZU1qkUod+3XuycBbxRqHOOjBdeOkkR+lSExI4L8LAcb+", "message": "Успешно."}}
````
* Где:
  `code` - Новый [код авторизации](https://github.com/ufocomp/module-AuthServer#%D0%BA%D0%BE%D0%B4-%D0%B0%D0%B2%D1%82%D0%BE%D1%80%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D0%B8) на получение маркера доступа (не путать с секретным кодом сессии).

Отрицательный ответ:
````json
{"t":4,"u":"<uuid>","c":401,"m":"Выход из системы. Секретный код сессии не прошёл проверку."}
````
**ВНИМАНИЕ**: При передаче неверных данных авторизации сессия будет закрыта, но не соединение.

Авторизация по маркеру доступа:
````json
{"t":0,"u":"<uuid>","p":{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiIDogImFjY291bnRzLnBsdWdtZS5ydSIsICJhdWQiIDogInNlcnZpY2UtcGx1Z21lLnJ1IiwgInN1YiIgOiAiYzgzYjJmODUzMjFmOTUzNDE3MDc2MjQ1NDZjYTZhYzRmYTZkMTExNSIsICJpYXQiIDogMTYwNjIxMDcwNiwgImV4cCIgOiAxNjA2MjE0MzA2fQ.ZI82FKXAgA1CZm3gx9XCpgpq_WyZJvwqYI4nOdccVts"}}
````
**ВНИМАНИЕ**: Не забывайте, что маркер доступа имеет ограниченный срок жизни.

Положительный ответ:
````json
{"t":3,"u":"<uuid>","p":{"authorized": true, "message": "Успешно."}}
````

Отрицательный ответ:
````json
{"t":4,"u":"<uuid>","c":403,"m":"Verification failed: Token expired."}
````

## Передача данных

Предусмотрена возможность отправки произвольных данных клиентскому приложению подключенному по WebSocket.

Для этого нужно отправить на сервер REST API запрос:

```http request
POST /ws/<code>[/<identity>]

<anydata>
```

* Где:
  - `<code>` - **Обязательный**. Код сессии WebSocket соединения на которое необходимо передать данные;
  - `<identity>` - **Необязательный**. Идентификатор сеанса связи в рамках сессии (при наличии);
  - `<anydata>` - **Необязательный**. Любые данные в произвольном формате.

Данные будут отправлены запросом с типом сообщения `CALL` в `Action` будет указано значение `/ws` в `Payload` будут произвольные данные из REST API запроса.

Пример:
````http request
POST /ws/8c98085f34c83a0eea5f40791218fbf80f1858d3 HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[...].9GI82ffkIhbUeWR8if3a8q78nfXAL4AFOMp3kWDTHOA
Content-Type: application/json

{"anydata":null}
````

Положительный ответ:
````json
{"sent": true, "status": "Success"}
````

Отрицательный ответ:
````json
{"sent": false, "status": "Session not found"}
````

## Подписка на события

* Для того чтобы получать данные от сервера без предварительных запросов со стороны клиентского приложения нужно подписаться на события.

* Для того чтобы подписаться на события нужно выбрать _издателя_ и настроить _слушателя_ (установить фильтр и параметры).

# Издатели

## Уведомления (`notify`)

Издатель `notify` предоставляет возможность подписаться на системные события, которые возникают каждый раз, когда пользователь системы взаимодействует с тем или иным объектом.

### Фильтр

Представление JSON для фильтра отбора событий:

```
{
  "entities": enum (string),
  "classes": enum (string),
  "actions": enum (string),
  "methods": enum (string),
  "objects": enum (numeric)
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
entities | JSON array | Коды | **Необязательный**. Сущность. Массив кодов.
classes  | JSON array | Коды | **Необязательный**. Класс. Массив кодов.
actions  | JSON array | Коды | **Необязательный**. Событие. Массив кодов.
methods  | JSON array | Коды | **Необязательный**. Метод. Массив кодов.
objects  | JSON array | Идентификаторы | **Необязательный**. Объекты. Массив идентификаторов.

**ВАЖНО**: Фильтр по полям работает по условию `И`, по значением в поле по условию `ИЛИ`.

**ВАЖНО**: Поля в которых не заданы значения игнорируются.

### Параметры

Представление JSON параметров:

```
{
  "type": string,
  "hook": Hook
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
type | STRING | notify, object, mixed, hook | **Необязательный**. Тип ответа.
hook  | JSON | Hook | **Обязательный** для типа hook. Ловушка.

* Если указать `notify`, то в ответ будут приходить сами уведомления.
* Если указать `object`, то в ответ будут приходить данные объекта в формате /get запроса.
* Если указать `mixed`, то в ответ будут приходить и сами уведомления и данные объекта в формате /get запроса.
* Если указать `hook`, то ответом будет результат выполнения API запроса из `Hook`.

### Hook

Ловушка задает параметры выполнения запроса API. При каждом выполнении условий подписки ответом будут данные из запроса ловушки.

```
{
  "method": string,
  "path": string,
  "payload": json
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
method | STRING | POST, GET | **Необязательный**. HTTP-метод.
path  | STRING | | **Обязательный**. REST API путь к конечной точке.
payload  | JSON | Hook | **Вариативный**. Полезная нагрузка. Зависит от запроса.

## Извещения (`notice`)

Издатель `notice` предоставляет возможность подписаться на системные извещения.

### Фильтр

Представление JSON для фильтра отбора событий:

```
{
  "categories": enum (string)
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
categories  | JSON array | Коды (строка) | **Необязательный**. Категория.

**ВАЖНО**: Фильтр по полям работает по условию `И`, по значением в поле по условию `ИЛИ`.

**ВАЖНО**: Поля в которых не заданы значения игнорируются.

### Параметры

Представление JSON параметров:

```
{
  "type": string
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
type | STRING | notify | **Необязательный**. Тип ответа.

## Сообщения (`message`)

Издатель `message` предоставляет возможность подписаться на входящие и исходящие сообщения.

### Фильтр

Представление JSON для фильтра отбора событий:

```
{
  "classes": enum (string)
  "types": enum (string)
  "agents": enum (string)
  "codes": enum (string)
  "profiles": enum (string)
  "addresses": enum (string)
  "subjects": enum (string)
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
classes  | JSON array | inbox, outbox | **Необязательный**. Класс сообщения (входящее или исходящее).
types  | JSON array | Коды (строка) | **Необязательный**. Код типа агента.
agents  | JSON array | Коды (строка) | **Необязательный**. Код агента.
codes  | JSON array | Коды (строка) | **Необязательный**. Код сообщения.
profiles  | JSON array |  | **Необязательный**. Профиль настроек. Используется для определения профиля настроек сообщения или адреса отправителя.
addresses  | JSON array |  | **Необязательный**. Адрес получателя. Для API запросов - это маршрут REST API.
subjects  | JSON array |  | **Необязательный**. Тема сообщения.

**ВАЖНО**: Фильтр по полям работает по условию `И`, по значением в поле по условию `ИЛИ`.

**ВАЖНО**: Поля в которых не заданы значения игнорируются.

### Параметры

Представление JSON параметров:

```
{
  "type": string
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
type | STRING | notify | **Необязательный**. Тип ответа.

## Журнал событий (`log`)

Издатель `log` предоставляет возможность подписаться на журнал событий.

### Фильтр

Представление JSON для фильтра отбора событий:

```
{
  "types": enum (string),
  "codes": enum (integer),
  "categories": enum (string)
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
types | JSON array | M, W, E, D | **Необязательный**. Тип: Message, Warning, Error, Debug.
codes  | JSON array | Коды (число) | **Необязательный**. Код. Натуральное число.
categories  | JSON array | Коды (строка) | **Необязательный**. Категория.

**ВАЖНО**: Фильтр по полям работает по условию `И`, по значением в поле по условию `ИЛИ`.

**ВАЖНО**: Поля в которых не заданы значения игнорируются.

### Параметры

Представление JSON параметров:

```
{
  "type": string
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
type | STRING | notify | **Необязательный**. Тип ответа.

## Геолокация (`geo`)

Издатель `geo` предоставляет возможность подписаться на поступающие данные геолокации.

### Фильтр

Представление JSON для фильтра отбора данных:

```
{
  "codes": enum (string),
  "objects": enum (numeric)
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
codes | JSON array | Коды (строка) | **Необязательный**. Коды групп координат (мест положений). По умолчанию `default`.
objects  | JSON array | Идентификаторы | **Необязательный**. Объекты. Массив идентификаторов.

**ВАЖНО**: Фильтр по полям работает по условию `И`, по значением в поле по условию `ИЛИ`.

**ВАЖНО**: Поля в которых не заданы значения игнорируются.

### Параметры

Представление JSON параметров:

```
{
  "type": string
}
```

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
type | STRING | notify | **Необязательный**. Тип ответа.

# Наблюдатель (`observer`)

## Конечные точки наблюдателя

### Подписаться

```http request
POST /api/v1/observer/subscribe
```
Подписаться на события издателя.

**Параметры запроса:**

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
publisher | STRING | notify, log, geo | **Обязательный**. Код издателя.
filter | JSON |  | **Необязательный**. Фильтр отбора событий издателя.
params | JSON |  | **Необязательный**. Параметры слушателя.

Примеры запроса:

Подписаться на все события издателя с кодом `notify`.
````json
{"t":2,"u":"<uuid>","a":"/observer/subscribe","p":{"publisher":"notify"}}
````

Подписаться на события издателя с кодом `notify` с учётом фильтра:
````json
{"t":2,"u":"<uuid>","a":"/observer/subscribe","p":{"publisher":"notify","filter":{"classes":["client", "device"]},"params":{"type":"object"}}}
````
Где фильтр:
- Классы (`classes`): client, device

Параметры:
- Тип (`type`): object (в ответ будут приходить данные объекта в формате /get запроса).

Подписаться на все входящие сообщения:
````json
{"t":2,"u":"observer","a":"/observer/subscribe","p":{"publisher":"notify", "filter": {"entities": ["message"], "classes": ["inbox"], "actions": ["create"]}, "params": {"type": "object"}}}
````

Отловить создание нового клиента и получить данные в виде списка клиентов:
````json
{"t":2,"u":"<uuid>","a":"/observer/subscribe","p":{"publisher":"notify","filter":{"classes":["client"],"actions":["create"]},"params":{"type":"hook","hook":{"path": "/api/v1/client/list", "payload": {}}}}}
````

### Отписаться

```http request
POST /api/v1/observer/unsubscribe
```
Отписаться от событий издателя.

**Параметры запроса:**

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
publisher | STRING | notify, log, geo | **Обязательный**. Код издателя.

Пример запроса:
````json
{"t":2,"u":"<uuid>","a":"/observer/unsubscribe","p":{"publisher":"notify"}}
````

# Издатель (`publisher`)

## Конечные точки издателя

```http request
POST /api/v1/observer/publisher
```
Получить данные издателя.

**Параметры запроса:**

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
code | STRING | notify, log, geo | **Обязательный**. Код издателя.
fields | JSON array |  | **Необязательный**. Массив JSON string полей в таблице, если не указано то запрос вернет все поля.

### Данные издателя

```http request
POST /api/v1/observer/publisher/get
```
Получить данные издателя.

**Параметры запроса:**

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
code | STRING | notify, log, geo | **Обязательный**. Код издателя.
fields | JSON array |  | **Необязательный**. Массив JSON string полей в таблице, если не указано то запрос вернет все поля.

### Количество издателей

```http request
POST /api/v1/observer/publisher/count
```
Количество издателей с возможностью указания фильтра отбора данных.

**Параметры запроса:**
[Общие параметры запроса для списка](https://github.com/ufocomp/db-platform#%D0%BE%D0%B1%D1%89%D0%B8%D0%B5-%D0%BF%D0%B0%D1%80%D0%B0%D0%BC%D0%B5%D1%82%D1%80%D1%8B-%D0%B7%D0%B0%D0%BF%D1%80%D0%BE%D1%81%D0%B0-%D0%B4%D0%BB%D1%8F-%D1%81%D0%BF%D0%B8%D1%81%D0%BA%D0%B0)

### Список издателей
```http request
POST /api/v1/observer/publisher/list
```
Список издателей с возможностью указания фильтра отбора.

**Параметры запроса:**
[Общие параметры запроса для списка](https://github.com/ufocomp/db-platform#%D0%BE%D0%B1%D1%89%D0%B8%D0%B5-%D0%BF%D0%B0%D1%80%D0%B0%D0%BC%D0%B5%D1%82%D1%80%D1%8B-%D0%B7%D0%B0%D0%BF%D1%80%D0%BE%D1%81%D0%B0-%D0%B4%D0%BB%D1%8F-%D1%81%D0%BF%D0%B8%D1%81%D0%BA%D0%B0)

# Слушатель (`listener`)

## Конечные точки слушателя

```http request
POST /api/v1/observer/listener
```
Получить данные слушателя по коду издателя.

**Параметры запроса:**

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
publisher | STRING | notify | **Обязательный**. Код издателя.
session | STRING |  | **Необязательный**. Код сессии.
fields | JSON array |  | **Необязательный**. Массив JSON string полей в таблице, если не указано то запрос вернет все поля.

### Установить слушателя

```http request
POST /api/v1/observer/listener/set
```
Установить данные слушателя.

**Параметры запроса:**

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
publisher | STRING |  | **Обязательный**. Идентификатор издателя.
session | STRING |  | **Необязательный**. Код сессии.
filter | JSON |  | **Необязательный**. Фильтр отбора событий издателя.
params | JSON |  | **Необязательный**. Параметры слушателя.

### Данные слушателя

```http request
POST /api/v1/observer/listener/get
```
Получить данные слушателя.

**Параметры запроса:**

Поле | Тип | Значение | Описание
------------ | ------------ | ------------ |------------
publisher | STRING |  | **Обязательный**. Код издателя.
session | STRING |  | **Необязательный**. Код сессии.
fields | JSON array |  | **Необязательный**. Массив JSON string полей в таблице, если не указано то запрос вернет все поля.

### Количество слушателей

```http request
POST /api/v1/observer/listener/count
```
Количество слушателей с возможностью указания фильтра отбора данных.

**Параметры запроса:**
[Общие параметры запроса для списка](https://github.com/ufocomp/db-platform#%D0%BE%D0%B1%D1%89%D0%B8%D0%B5-%D0%BF%D0%B0%D1%80%D0%B0%D0%BC%D0%B5%D1%82%D1%80%D1%8B-%D0%B7%D0%B0%D0%BF%D1%80%D0%BE%D1%81%D0%B0-%D0%B4%D0%BB%D1%8F-%D1%81%D0%BF%D0%B8%D1%81%D0%BA%D0%B0)

### Список слушателей
```http request
POST /api/v1/observer/listener/list
```
Список слушателей с возможностью указания фильтра отбора.

**Параметры запроса:**
[Общие параметры запроса для списка](https://github.com/ufocomp/db-platform#%D0%BE%D0%B1%D1%89%D0%B8%D0%B5-%D0%BF%D0%B0%D1%80%D0%B0%D0%BC%D0%B5%D1%82%D1%80%D1%8B-%D0%B7%D0%B0%D0%BF%D1%80%D0%BE%D1%81%D0%B0-%D0%B4%D0%BB%D1%8F-%D1%81%D0%BF%D0%B8%D1%81%D0%BA%D0%B0)

#### Примеры

Запрос "Кто я":
````json
{"t":2,"u":"<uuid>","a":"/whoami"}
````

Запросить:

Сущности:
````json
{"t":2,"u":"<uuid>","a":"/entity","p":{"fields": ["id", "code", "name"]}}
````

Классы:
````json
{"t":2,"u":"<uuid>","a":"/class","p":{"fields": ["id", "entity", "entitycode", "entityname", "code", "label"]}}
````

Действия:
````json
{"t":2,"u":"<uuid>","a":"/action","p":{"fields": ["id", "code", "name"]}}
````

Методы:
````json
{"t":2,"u":"<uuid>","a":"/method","p":{"fields": ["id", "class", "classcode", "classlabel", "action", "actioncode", "actionname", "code", "label"]}}
````
