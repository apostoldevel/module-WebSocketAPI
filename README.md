WebSocket API
-

[![ru](https://img.shields.io/badge/lang-ru-green.svg)](https://github.com/apostoldevel/module-WebSocketAPI/blob/master/README.ru-RU.md)

A **Worker module** for [Apostol](https://github.com/apostoldevel/apostol) + [db-platform](https://github.com/apostoldevel/db-platform) — **Apostol CRM**[^crm].

Description
-

**WebSocket API** provides real-time WebSocket connectivity to the API. It implements a lightweight JSON-based RPC protocol over WebSocket, an event subscription system (Observer pattern), and a REST endpoint for pushing data to connected clients.

Database module
-

WebSocketAPI is tightly coupled to the **`observer`**, **`notification`**, **`notice`**, **`message`**, and **`log`** modules of [db-platform](https://github.com/apostoldevel/db-platform).

The C++ module handles WebSocket transport and session routing. All subscription state, publisher registration, and event data live entirely in the database:

| db-platform module | Purpose |
|--------------------|---------|
| `observer` | Publisher/subscriber registry: stores publishers (`observer.publisher`) and active listener subscriptions (`observer.listener`) per session |
| `notification` | Source of `notify` publisher events — fires whenever a user interacts with a system object (create/update/delete/transition) |
| `notice` | Source of `notice` publisher events — system-level notices grouped by category |
| `message` | Source of `message` publisher events — inbox and outbox message records from the `message` entity |
| `log` | Source of `log` publisher events — event log entries (M/W/E/D) from the system log |

Key database objects:

| Object | Purpose |
|--------|---------|
| `observer.publisher` | Registered publishers (`notify`, `notice`, `message`, `log`, `geo`) |
| `observer.listener` | Active subscriptions: session → publisher with filter and params |
| `api.observer_subscribe(publisher, filter, params)` | Creates or updates a listener for the current session |
| `api.observer_unsubscribe(publisher)` | Removes the listener for the current session |
| `api.observer_publisher(code)` | Returns publisher metadata |
| `api.observer_listener(publisher, session)` | Returns listener state for a session |

Configuration
-

```ini
[module/WebSocketAPI]
enable=true
```

Installation
-

Follow the build and installation instructions for [Apostol](https://github.com/apostoldevel/apostol#building-and-installation).

Client Connection
-

To establish a WebSocket connection the client must perform an Opening Handshake as described in [RFC 6455, Section 4](https://tools.ietf.org/html/rfc6455#section-4).

The server imposes additional constraints on the WebSocket URL, described below.

### Connection URL

The WebSocket connection is scoped to a previously created session. A session is created after successful user authentication, which yields an access token, a session code, and a secret key.

The connection URL contains the session code and an optional identity that distinguishes multiple connections within the same session.

URL format:

```
ws[s]://[ws.]example.com/session/<code>[/<identity>]
```

Where:
- `<code>` — **Required.** Session code (40 characters).
- `<identity>` — **Optional.** Connection identity within the session. Used to maintain multiple simultaneous connections to the same session.

Examples:

```
wss://ws.example.com/session/c83b2f85321f95341707624546ca6ac4fa6d1115
```

```
wss://ws.example.com/session/c83b2f85321f95341707624546ca6ac4fa6d1115/user1
```

RPC Protocol
-

The WebSocket protocol itself does not provide request/response semantics. To enable this, a small JSON-based RPC protocol is layered on top of WebSocket.

### JSON Frame Fields

Key | Name | Type | Description
--- | ---- | ---- | -----------
`t` | MessageTypeId | INTEGER | Message type (see below).
`u` | UniqueId | UUID | Unique message identifier. When a server message is a reply to a client request, both share the same UniqueId.
`a` | Action | STRING | API endpoint route.
`c` | ErrorCode | INTEGER | Error code.
`m` | ErrorMessage | STRING | Error description.
`p` | Payload | JSON | Message payload.

### Message Types (MessageTypeId)

Type | Number | Direction | Description
---- | ------ | --------- | -----------
`OPEN` | 0 | Client → Server | Authorize an existing session.
`CLOSE` | 1 | Client → Server | Close the session (sign out).
`CALL` | 2 | Client ↔ Server | Request or server-initiated push.
`CALLRESULT` | 3 | Server → Client | Successful response to a `CALL`.
`CALLERROR` | 4 | Server → Client | Error response to a `CALL`.

Authorization
-

After connecting, the client must authorize before sending API requests.

Authorization can be performed automatically during the handshake if the following HTTP headers are provided:

```
Authorization: Bearer <token>
```

Or:

```
Session: <session>
Secret: <secret>
```

If the client framework prevents setting custom HTTP headers during the WebSocket handshake, authorization is performed by sending an `OPEN` message with credentials issued by the [AuthServer](https://github.com/apostoldevel/module-AuthServer). Either an access token (`token`) or a session secret (`secret`) may be used.

After successful authorization, `CALL` messages can be sent. The API endpoint is specified in the `Action` field (`a`) and the JSON request body in the `Payload` field (`p`).

Attempting to send a `CALL` before authorization results in a `CALLERROR` response.

**Example — session code not found or session closed:**

```json
{"t":4,"u":"<uuid>","c":400,"m":"Session code not found."}
```

### Authorization via secret key

Request:

```json
{"t":0,"u":"<uuid>","p":{"secret": "MWCJ14k/RJyiHskQB8DoVbliiwDeNGKsgsAMugp3OZt+M0Zj44hDykwRuFoWEwuG"}}
```

Success response:

```json
{"t":3,"u":"<uuid>","p":{"authorized": true, "code": "amAJmzkxvDE+ad7KwkRtZU1qkUod+3XuycBbxRqHOOjBdeOkkR+lSExI4L8LAcb+", "message": "Success."}}
```

Where `code` is a new [authorization code](https://github.com/apostoldevel/module-AuthServer) for obtaining an access token (not to be confused with the session secret).

Error response:

```json
{"t":4,"u":"<uuid>","c":401,"m":"Sign out. Session secret failed verification."}
```

**Note:** If incorrect authorization credentials are supplied, the session is closed but the WebSocket connection remains open.

### Authorization via access token

Request:

```json
{"t":0,"u":"<uuid>","p":{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiIDogImFjY291bnRzLnBsdWdtZS5ydSIsICJhdWQiIDogInNlcnZpY2UtcGx1Z21lLnJ1IiwgInN1YiIgOiAiYzgzYjJmODUzMjFmOTUzNDE3MDc2MjQ1NDZjYTZhYzRmYTZkMTExNSIsICJpYXQiIDogMTYwNjIxMDcwNiwgImV4cCIgOiAxNjA2MjE0MzA2fQ.ZI82FKXAgA1CZm3gx9XCpgpq_WyZJvwqYI4nOdccVts"}}
```

**Note:** Access tokens have a limited lifetime.

Success response:

```json
{"t":3,"u":"<uuid>","p":{"authorized": true, "message": "Success."}}
```

Error response:

```json
{"t":4,"u":"<uuid>","c":403,"m":"Verification failed: Token expired."}
```

Pushing Data to Clients
-

Arbitrary data can be pushed to a connected WebSocket client via a REST API call:

```
POST /ws/<code>[/<identity>]

<anydata>
```

Where:
- `<code>` — **Required.** Session code of the target WebSocket connection.
- `<identity>` — **Optional.** Connection identity within the session (if applicable).
- `<anydata>` — **Optional.** Any data in any format.

The data is delivered to the client as a `CALL` message with `Action` set to `/ws` and `Payload` containing the body of the REST request.

**Example request:**

```http
POST /ws/8c98085f34c83a0eea5f40791218fbf80f1858d3 HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[...].9GI82ffkIhbUeWR8if3a8q78nfXAL4AFOMp3kWDTHOA
Content-Type: application/json

{"anydata":null}
```

Success response:

```json
{"sent": true, "status": "Success"}
```

Error response:

```json
{"sent": false, "status": "Session not found"}
```

Event Subscription
-

To receive server-initiated data without polling, a client subscribes to events from a **publisher**.

To subscribe, choose a publisher and configure a listener (filter and parameters).

Publishers
-

## Notifications (`notify`)

The `notify` publisher delivers system events that are raised whenever a user interacts with an object in the system.

### Filter

```json
{
  "entities": ["<code>", ...],
  "classes":  ["<code>", ...],
  "actions":  ["<code>", ...],
  "methods":  ["<code>", ...],
  "objects":  [<id>, ...]
}
```

Field | Type | Description
----- | ---- | -----------
`entities` | JSON array of strings | **Optional.** Entity codes.
`classes` | JSON array of strings | **Optional.** Class codes.
`actions` | JSON array of strings | **Optional.** Action codes.
`methods` | JSON array of strings | **Optional.** Method codes.
`objects` | JSON array of integers | **Optional.** Object IDs.

**Important:** Fields are combined with AND logic; multiple values within a field use OR logic. Fields with no values specified are ignored.

### Parameters

```json
{
  "type": "notify | object | mixed | hook",
  "hook": { ... }
}
```

Field | Type | Values | Description
----- | ---- | ------ | -----------
`type` | STRING | `notify`, `object`, `mixed`, `hook` | **Optional.** Response type.
`hook` | JSON | Hook object | **Required** when `type` is `hook`.

- `notify` — deliver the raw notification.
- `object` — deliver the object data as returned by a `/get` request.
- `mixed` — deliver both the notification and the object data.
- `hook` — deliver the result of the API request defined in `hook`.

### Hook

A hook defines an API request to execute each time the subscription condition is met.

```json
{
  "method": "POST | GET",
  "path":   "<api-path>",
  "payload": { ... }
}
```

Field | Type | Description
----- | ---- | -----------
`method` | STRING | **Optional.** HTTP method (`POST` or `GET`).
`path` | STRING | **Required.** REST API path.
`payload` | JSON | **Optional.** Request payload. Depends on the endpoint.

## Notices (`notice`)

The `notice` publisher delivers system notices.

### Filter

```json
{
  "categories": ["<code>", ...]
}
```

Field | Type | Description
----- | ---- | -----------
`categories` | JSON array of strings | **Optional.** Category codes.

### Parameters

```json
{
  "type": "notify"
}
```

Field | Type | Description
----- | ---- | -----------
`type` | STRING | **Optional.** Response type. Currently `notify`.

## Messages (`message`)

The `message` publisher delivers inbound and outbound messages.

### Filter

```json
{
  "classes":   ["inbox", "outbox"],
  "types":     ["<code>", ...],
  "agents":    ["<code>", ...],
  "codes":     ["<code>", ...],
  "profiles":  ["<value>", ...],
  "addresses": ["<value>", ...],
  "subjects":  ["<value>", ...]
}
```

Field | Type | Description
----- | ---- | -----------
`classes` | JSON array | **Optional.** Message direction: `inbox` or `outbox`.
`types` | JSON array of strings | **Optional.** Agent type codes.
`agents` | JSON array of strings | **Optional.** Agent codes.
`codes` | JSON array of strings | **Optional.** Message codes.
`profiles` | JSON array | **Optional.** Settings profile or sender address.
`addresses` | JSON array | **Optional.** Recipient address (for API requests — the REST route).
`subjects` | JSON array | **Optional.** Message subject.

### Parameters

```json
{
  "type": "notify"
}
```

Field | Type | Description
----- | ---- | -----------
`type` | STRING | **Optional.** Response type. Currently `notify`.

## Event Log (`log`)

The `log` publisher delivers event log entries.

### Filter

```json
{
  "types":      ["M", "W", "E", "D"],
  "codes":      [<integer>, ...],
  "categories": ["<code>", ...]
}
```

Field | Type | Description
----- | ---- | -----------
`types` | JSON array of strings | **Optional.** Log level: `M` (Message), `W` (Warning), `E` (Error), `D` (Debug).
`codes` | JSON array of integers | **Optional.** Numeric log codes.
`categories` | JSON array of strings | **Optional.** Category codes.

### Parameters

```json
{
  "type": "notify"
}
```

Field | Type | Description
----- | ---- | -----------
`type` | STRING | **Optional.** Response type. Currently `notify`.

## Geolocation (`geo`)

The `geo` publisher delivers incoming geolocation data.

### Filter

```json
{
  "codes":   ["<code>", ...],
  "objects": [<id>, ...]
}
```

Field | Type | Description
----- | ---- | -----------
`codes` | JSON array of strings | **Optional.** Coordinate group codes (locations). Defaults to `default`.
`objects` | JSON array of integers | **Optional.** Object IDs.

### Parameters

```json
{
  "type": "notify"
}
```

Field | Type | Description
----- | ---- | -----------
`type` | STRING | **Optional.** Response type. Currently `notify`.

Observer API
-

## Subscribe

```
POST /api/v1/observer/subscribe
```

Subscribe to a publisher's events.

**Request fields:**

Field | Type | Values | Description
----- | ---- | ------ | -----------
`publisher` | STRING | `notify`, `notice`, `message`, `log`, `geo` | **Required.** Publisher code.
`filter` | JSON | | **Optional.** Event filter.
`params` | JSON | | **Optional.** Listener parameters.

**Examples:**

Subscribe to all events from the `notify` publisher:

```json
{"t":2,"u":"<uuid>","a":"/observer/subscribe","p":{"publisher":"notify"}}
```

Subscribe with a filter (classes: `client`, `device`) and response type `object`:

```json
{"t":2,"u":"<uuid>","a":"/observer/subscribe","p":{"publisher":"notify","filter":{"classes":["client","device"]},"params":{"type":"object"}}}
```

Subscribe to all incoming messages:

```json
{"t":2,"u":"observer","a":"/observer/subscribe","p":{"publisher":"notify","filter":{"entities":["message"],"classes":["inbox"],"actions":["create"]},"params":{"type":"object"}}}
```

Catch new client creation and receive the result as a client list:

```json
{"t":2,"u":"<uuid>","a":"/observer/subscribe","p":{"publisher":"notify","filter":{"classes":["client"],"actions":["create"]},"params":{"type":"hook","hook":{"path":"/api/v1/client/list","payload":{}}}}}
```

## Unsubscribe

```
POST /api/v1/observer/unsubscribe
```

Unsubscribe from a publisher's events.

**Request fields:**

Field | Type | Values | Description
----- | ---- | ------ | -----------
`publisher` | STRING | `notify`, `notice`, `message`, `log`, `geo` | **Required.** Publisher code.

**Example:**

```json
{"t":2,"u":"<uuid>","a":"/observer/unsubscribe","p":{"publisher":"notify"}}
```

Publisher API
-

## Get publisher data

```
POST /api/v1/observer/publisher
```

**Request fields:**

Field | Type | Values | Description
----- | ---- | ------ | -----------
`code` | STRING | `notify`, `notice`, `message`, `log`, `geo` | **Required.** Publisher code.
`fields` | JSON array | | **Optional.** Array of field names to return. If omitted, all fields are returned.

## Get publisher by code

```
POST /api/v1/observer/publisher/get
```

**Request fields:**

Field | Type | Values | Description
----- | ---- | ------ | -----------
`code` | STRING | `notify`, `notice`, `message`, `log`, `geo` | **Required.** Publisher code.
`fields` | JSON array | | **Optional.** Array of field names to return. If omitted, all fields are returned.

## Count publishers

```
POST /api/v1/observer/publisher/count
```

**Request fields:** [Common list query parameters](https://github.com/apostoldevel/db-platform#common-list-query-parameters)

## List publishers

```
POST /api/v1/observer/publisher/list
```

**Request fields:** [Common list query parameters](https://github.com/apostoldevel/db-platform#common-list-query-parameters)

Listener API
-

## Get listener data

```
POST /api/v1/observer/listener
```

**Request fields:**

Field | Type | Values | Description
----- | ---- | ------ | -----------
`publisher` | STRING | `notify`, `notice`, `message`, `log`, `geo` | **Required.** Publisher code.
`session` | STRING | | **Optional.** Session code.
`fields` | JSON array | | **Optional.** Array of field names to return. If omitted, all fields are returned.

## Set listener

```
POST /api/v1/observer/listener/set
```

**Request fields:**

Field | Type | Description
----- | ---- | -----------
`publisher` | STRING | **Required.** Publisher identifier.
`session` | STRING | **Optional.** Session code.
`filter` | JSON | **Optional.** Event filter.
`params` | JSON | **Optional.** Listener parameters.

## Get listener by publisher

```
POST /api/v1/observer/listener/get
```

**Request fields:**

Field | Type | Description
----- | ---- | -----------
`publisher` | STRING | **Required.** Publisher code.
`session` | STRING | **Optional.** Session code.
`fields` | JSON array | **Optional.** Array of field names to return. If omitted, all fields are returned.

## Count listeners

```
POST /api/v1/observer/listener/count
```

**Request fields:** [Common list query parameters](https://github.com/apostoldevel/db-platform#common-list-query-parameters)

## List listeners

```
POST /api/v1/observer/listener/list
```

**Request fields:** [Common list query parameters](https://github.com/apostoldevel/db-platform#common-list-query-parameters)

Examples
-

**Who am I:**

```json
{"t":2,"u":"<uuid>","a":"/whoami"}
```

**Query entities:**

```json
{"t":2,"u":"<uuid>","a":"/entity","p":{"fields":["id","code","name"]}}
```

**Query classes:**

```json
{"t":2,"u":"<uuid>","a":"/class","p":{"fields":["id","entity","entitycode","entityname","code","label"]}}
```

**Query actions:**

```json
{"t":2,"u":"<uuid>","a":"/action","p":{"fields":["id","code","name"]}}
```

**Query methods:**

```json
{"t":2,"u":"<uuid>","a":"/method","p":{"fields":["id","class","classcode","classlabel","action","actioncode","actionname","code","label"]}}
```

[^crm]: **Apostol CRM** is an abstract term, not a standalone product. It refers to any project that uses both the [Apostol](https://github.com/apostoldevel/apostol) C++ framework and [db-platform](https://github.com/apostoldevel/db-platform) together through purpose-built modules and processes. Each framework can be used independently; combined, they form a full-stack backend platform.
