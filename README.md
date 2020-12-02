WebSocket API
-
**Модуль** для [Апостол](https://github.com/ufocomp/apostol-aws).

Описание
-
* **WebSocket API** предоставляет возможность подключения к API системы по протоколу [WebSocket](https://ru.wikipedia.org/wiki/WebSocket).

Установка
-
Следуйте указаниям по сборке и установке [Апостол](https://github.com/ufocomp/apostol-aws#%D1%81%D0%B1%D0%BE%D1%80%D0%BA%D0%B0-%D0%B8-%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0)

Описание
-

### Запрос клиента

Чтобы установить соединение, клиентское приложение инициирует соединение WebSocket, как описано в [RFC6455](https://tools.ietf.org/html/rfc6455) [раздел 4](https://tools.ietf.org/html/rfc6455#section-4), «Opening Handshake».

Система накладывает дополнительные ограничения на URL-адрес и подпротокол WebSocket, подробно описанные ниже.

#### URL подключения

Чтобы инициировать соединение WebSocket, клиенту требуется URL-адрес [RFC3986](https://tools.ietf.org/html/rfc3986) для подключения (URL подключения). URL подключения содержит в себе идентификатор устройства, благодаря которому система знает, какому устройству принадлежит соединение WebSocket. 

[Взаимодействие с системой](https://github.com/ufocomp/module-AppServer#%D0%B4%D0%BE%D1%81%D1%82%D1%83%D0%BF-%D0%BA-api) происходит в рамках ранее созданной сессии. Сессия создается после успешной аутентификации пользователя в системе. Результатом которой является получение маркера доступа, идентификатора сессии и секретного ключа. 

Окончательный URL подключения выглядит так:
````
wss://ws.exemple.com/session/<uuid>
````
 * Где:
    `<uuid>` - Идентификатор устройства (уникальный в рамках системы).

Пример:
````
wss://ws.exemple.com/session/ABC-01234
````

### RPC framework

Протокол WebSocket сам по себе не дает возможности отправлять сообщения в режиме запрос/ответ. Чтобы обеспечить эту возможность был создан небольшой RPC протокол поверх WebSocket в формате JSON.

#### Описание JSON ключей

 Ключ | Расшифровка | Тип данных | Назначение, примечания 
----- | ----------- | ---------- | ----------------------
 t | MessageTypeId | INTEGER | Тип сообщения. Описание ниже.
 u | UniqueId | UUID | Идентификатор сообщения.
 a | Action | STRING | Действие. 
 c | ErrorCode | INTEGER | Код ошибки.
 m | ErrorMessage | STRING |  Сообщение об ошибке.
 p | Payload | JSON | Полезная нагрузка.

#### Тип сообщения (MessageTypeId):

Тип сообщения | Номер типа сообщения | Направление | Описание
----- | ----------- | ---------- | ----------------------
OPEN | 0 | Клиент-Сервер | Подключение к ранее открытой сессии.
CLOSE | 1 | Клиент-Сервер | Закрытие сессии (выход из системы).
CALL | 2 | Клиент-Сервер | Запрос.
CALLRESULT | 3 | Сервер-Клиент | Ответ на запрос.
CALLERROR | 4 | Сервер-Клиент | Ответ на запрос с ошибкой.

### Авторизация

* После подключения клиенты нужно авторизоваться.

Авторизация может быть выполнена в автоматическом режиме при условии, если в момент установки связи были указаны HTTP-заголовки:

Authorization:
  1. Или `Basic BASE64(username:password)`;
  2. Или `Bearer TokenJWT`.

Или:

 3. В HTTP заголовке передать:
  - `Session: <session>`
  - `Secret: <secret>`

Если заполнение HTTP-заголовков блокируется на стороне используемого, клиентским приложением, фрейворка, то авторизация выполняется путем отправки пакета t:0 с данными авторизации (которые выдал [сервер авторизации](https://github.com/ufocomp/module-AuthServer)) это может быть или маркер доступа (`access_token`) или пара `Session/Secret`.

#### Примеры

Авторизация:
````json
{"t":0,"u":"001","p":{"session": "0cadfc416c7a6b3e9fed3dbf915db38c32e4081c", "secret": "MWCJ14k/RJyiHskQB8DoVbliiwDeNGKsgsAMugp3OZt+M0Zj44hDykwRuFoWEwuG"}}
````

Авторизация по маркеру доступа:
````json
{"t":0,"u":"001","p":{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiIDogImFjY291bnRzLnBsdWdtZS5ydSIsICJhdWQiIDogInNlcnZpY2UtcGx1Z21lLnJ1IiwgInN1YiIgOiAiYzgzYjJmODUzMjFmOTUzNDE3MDc2MjQ1NDZjYTZhYzRmYTZkMTExNSIsICJpYXQiIDogMTYwNjIxMDcwNiwgImV4cCIgOiAxNjA2MjE0MzA2fQ.ZI82FKXAgA1CZm3gx9XCpgpq_WyZJvwqYI4nOdccVts"}}
````

Запрос:
````json
{"t":2,"u":"001","a":"/whoami"}
````

Вход в систему под другим пользователем (после авторизации):
````json
{"t":2,"u":"001","a":"/sign/in","p":{"username":"admin","password":"admin"}}
````
