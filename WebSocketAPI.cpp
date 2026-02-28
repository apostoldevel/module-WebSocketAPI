#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "WebSocketAPI.hpp"
#include "apostol/application.hpp"

#include "apostol/base64.hpp"
#include "apostol/http_utils.hpp"
#include "apostol/pg_utils.hpp"

#include <algorithm>
#include <chrono>
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <string>

namespace apostol
{

// ─── JSON-RPC message types ─────────────────────────────────────────────────

namespace
{

enum class MsgType : int
{
    open        = 0,
    close       = 1,
    call        = 2,
    call_result = 3,
    call_error  = 4,
};

/// Generate a unique ID (hex microseconds) for server-initiated messages.
std::string make_unique_id()
{
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return fmt::format("{:x}", static_cast<uint64_t>(us));
}

/// Build JSON-RPC call message: {"t":2, "u":"<uid>", "a":"<action>", "p":<payload>}
std::string build_call_msg(std::string_view action, const std::string& payload)
{
    nlohmann::json msg;
    msg["t"] = static_cast<int>(MsgType::call);
    msg["u"] = make_unique_id();
    msg["a"] = action;

    try {
        msg["p"] = nlohmann::json::parse(payload);
    } catch (...) {
        msg["p"] = payload;
    }

    return msg.dump();
}

/// Build JSON-RPC call_result message: {"t":3, "u":"<uid>", "p":<payload>}
std::string build_result_msg(std::string_view unique_id,
                             const std::string& payload)
{
    nlohmann::json msg;
    msg["t"] = static_cast<int>(MsgType::call_result);
    msg["u"] = unique_id;

    try {
        msg["p"] = nlohmann::json::parse(payload);
    } catch (...) {
        msg["p"] = payload;
    }

    return msg.dump();
}

/// Build JSON-RPC call_error message: {"t":4, "u":"<uid>", "c":<code>, "m":"<msg>"}
std::string build_error_msg(std::string_view unique_id,
                            int code, std::string_view message)
{
    nlohmann::json msg;
    msg["t"] = static_cast<int>(MsgType::call_error);
    msg["u"] = unique_id;
    msg["c"] = code;
    msg["m"] = message;
    return msg.dump();
}

/// Default receive window for signed_fetch (milliseconds).
constexpr int kReceiveWindowMs = 60000;

} // anonymous namespace

// ─── Construction ───────────────────────────────────────────────────────────

WebSocketAPI::WebSocketAPI(Application& app)
    : pool_(app.db_pool())
    , loop_(app.worker_loop())
    , providers_(app.providers())
    , enabled_(true)
{
    add_allowed_header("Authorization");
    add_allowed_header("Session");
    add_allowed_header("Secret");

    load_allowed_origins(providers_);
}

// ─── check_location ─────────────────────────────────────────────────────────

bool WebSocketAPI::check_location(const HttpRequest& req) const
{
    // HTTP endpoints: /ws/*
    return req.path.substr(0, 4) == "/ws/" || req.path == "/ws";
}

// ─── init_methods ───────────────────────────────────────────────────────────

void WebSocketAPI::init_methods()
{
    add_method("GET",  [this](auto& req, auto& resp) { do_get(req, resp); });
    add_method("POST", [this](auto& req, auto& resp) { do_post(req, resp); });
}

// ─── heartbeat ──────────────────────────────────────────────────────────────

void WebSocketAPI::heartbeat(std::chrono::system_clock::time_point now)
{
    if (now < next_check_)
        return;

    next_check_ = now + std::chrono::seconds(60);

    // Initialize LISTEN on first heartbeat (pool is ready by then)
    if (!listen_initialized_) {
        init_listen();
        listen_initialized_ = true;
    }
}

// ─── parse_session_path ─────────────────────────────────────────────────────

std::pair<std::string, std::string>
WebSocketAPI::parse_session_path(std::string_view path)
{
    // Expected: /session/<code>[/<identity>]
    // or: /ws/<code>[/<identity>] (for POST push)

    // Find the prefix: skip "/session/" or "/ws/"
    std::string_view rest;
    if (path.substr(0, 9) == "/session/")
        rest = path.substr(9);
    else if (path.substr(0, 4) == "/ws/")
        rest = path.substr(4);
    else
        return {};

    if (rest.empty())
        return {};

    auto slash = rest.find('/');
    if (slash == std::string_view::npos)
        return {std::string(rest), "main"};

    auto code = rest.substr(0, slash);
    auto identity = rest.substr(slash + 1);

    return {std::string(code),
            identity.empty() ? std::string("main") : std::string(identity)};
}

// ─── normalize_action ───────────────────────────────────────────────────────

std::string WebSocketAPI::normalize_action(std::string_view action)
{
    if (action.empty())
        return "/api/v1";

    if (action.substr(0, 8) == "/api/v1/" || action == "/api/v1")
        return std::string(action);

    return fmt::format("/api/v1{}", action);
}

// ─── Session management ─────────────────────────────────────────────────────

std::shared_ptr<WebSocketAPI::WsSession>
WebSocketAPI::find_session(int fd)
{
    auto it = sessions_by_fd_.find(fd);
    return it != sessions_by_fd_.end() ? it->second : nullptr;
}

std::shared_ptr<WebSocketAPI::WsSession>
WebSocketAPI::add_session(WsConnection ws,
                          std::string session,
                          std::string identity)
{
    auto s = std::make_shared<WsSession>();
    s->session  = std::move(session);
    s->identity = std::move(identity);
    s->ws       = std::make_shared<WsConnection>(std::move(ws));

    int fd = s->ws->fd();
    sessions_by_fd_[fd] = s;
    sessions_by_code_.emplace(s->session, s);

    return s;
}

void WebSocketAPI::remove_session(int fd)
{
    auto it = sessions_by_fd_.find(fd);
    if (it == sessions_by_fd_.end())
        return;

    auto session = it->second;

    // Don't delete while observer queries are in-flight
    if (session->update_count > 0)
        return;

    sessions_by_fd_.erase(it);

    // Remove from secondary index
    auto range = sessions_by_code_.equal_range(session->session);
    for (auto it2 = range.first; it2 != range.second; ) {
        if (it2->second.get() == session.get())
            it2 = sessions_by_code_.erase(it2);
        else
            ++it2;
    }

    loop_.remove_io(fd);
}

// ─── on_ws_upgrade ──────────────────────────────────────────────────────────

void WebSocketAPI::on_ws_upgrade(EventLoop& loop, WsConnection ws,
                                 const HttpRequest& req)
{
    auto [code, identity] = parse_session_path(req.path);
    if (code.empty()) {
        ws.send_close(1008, "Invalid session path");
        return;
    }

    auto session = add_session(std::move(ws), std::move(code),
                               std::move(identity));
    session->agent = get_user_agent(req);
    session->ip    = get_real_ip(req);

    // Check handshake-level authorization (headers)
    check_session_auth(req, *session);

    int fd = session->ws->fd();
    loop.add_io(fd, EPOLLIN, [this, session](uint32_t) {
        bool ok = session->ws->on_readable(
            [this, session](uint8_t opcode, const std::string& payload) {
                on_ws_message(session, opcode, payload);
            },
            [this, session]() {
                remove_session(session->ws->fd());
            }
        );
        if (!ok) {
            remove_session(session->ws->fd());
        }
    });
}

// ─── check_session_auth ─────────────────────────────────────────────────────

int WebSocketAPI::check_session_auth(const HttpRequest& req, WsSession& session)
{
    // Priority 1: Authorization header (Bearer or Basic)
    auto auth_header = req.header("Authorization");
    if (!auth_header.empty()) {
        session.auth = parse_authorization(auth_header);

        if (session.auth.schema == Authorization::Schema::bearer) {
            try {
                auto claims = verify_jwt(session.auth.token, providers_);
                // Verify sub matches session code
                if (!claims.sub.empty() && claims.sub != session.session) {
                    session.authorized = false;
                    return -1;
                }
                session.authorized = true;
                return 1;
            } catch (const JwtExpiredError&) {
                session.authorized = false;
                return -1;
            } catch (const JwtVerificationError&) {
                session.authorized = false;
                return -1;
            }
        }

        if (session.auth.schema == Authorization::Schema::basic) {
            session.authorized = true;
            return 1;
        }
    }

    // Priority 2: Session + Secret headers
    auto sess_hdr   = req.header("Session");
    auto secret_hdr = req.header("Secret");

    if (!sess_hdr.empty() && !secret_hdr.empty()) {
        session.secret = std::move(secret_hdr);
        session.authorized = true;
        return 1;
    }

    // No auth — must OPEN later
    session.authorized = false;
    return 0;
}

// ─── on_ws_message ──────────────────────────────────────────────────────────

void WebSocketAPI::on_ws_message(std::shared_ptr<WsSession> session,
                                 uint8_t opcode, const std::string& payload)
{
    if (opcode != WS_OP_TEXT)
        return;

    nlohmann::json msg;
    try {
        msg = nlohmann::json::parse(payload);
    } catch (const nlohmann::json::exception&) {
        send_call_error(*session->ws, "", 400, "Invalid JSON");
        return;
    }

    int type = msg.value("t", -1);
    std::string unique_id = msg.value("u", "");
    std::string action    = msg.value("a", "");
    nlohmann::json p = msg.contains("p") ? msg["p"] : nlohmann::json::object();

    switch (static_cast<MsgType>(type)) {
        case MsgType::open:
            handle_open(session, unique_id, p);
            break;
        case MsgType::close:
            handle_close(session, unique_id);
            break;
        case MsgType::call:
            handle_call(session, unique_id, action, p);
            break;
        default:
            send_call_error(*session->ws, unique_id, 400,
                            "Unknown message type");
            break;
    }
}

// ─── handle_open ────────────────────────────────────────────────────────────

void WebSocketAPI::handle_open(std::shared_ptr<WsSession> session,
                               const std::string& unique_id,
                               const nlohmann::json& payload)
{
    std::string secret = payload.value("secret", "");
    std::string token  = payload.value("token", "");

    if (!secret.empty()) {
        // Authenticate via session+secret
        session->secret     = secret;
        session->authorized = false;

        // Build payload for unauthorized_fetch
        nlohmann::json auth_payload;
        auth_payload["session"] = session->session;
        auth_payload["secret"]  = secret;
        auth_payload["agent"]   = session->agent;
        auth_payload["host"]    = session->ip;

        unauthorized_fetch(session, unique_id,
                           "/api/v1/authenticate",
                           auth_payload.dump());
    } else if (!token.empty()) {
        // Authenticate via JWT token
        try {
            auto claims = verify_jwt(token, providers_);
            // Check that sub matches session
            if (!claims.sub.empty() && claims.sub != session->session) {
                send_call_error(*session->ws, unique_id, 401,
                                "Token subject does not match session.");
                return;
            }
        } catch (const JwtExpiredError&) {
            send_call_error(*session->ws, unique_id, 401, "Token expired.");
            return;
        } catch (const JwtVerificationError& e) {
            send_call_error(*session->ws, unique_id, 401, e.what());
            return;
        }

        session->auth.schema = Authorization::Schema::bearer;
        session->auth.token  = token;
        session->authorized  = false;

        nlohmann::json auth_payload;
        auth_payload["session"] = session->session;
        auth_payload["agent"]   = session->agent;
        auth_payload["host"]    = session->ip;

        unauthorized_fetch(session, unique_id,
                           "/api/v1/authorize",
                           auth_payload.dump());
    } else {
        send_call_error(*session->ws, unique_id, 400,
                        "OPEN requires 'secret' or 'token'.");
    }
}

// ─── handle_close ───────────────────────────────────────────────────────────

void WebSocketAPI::handle_close(std::shared_ptr<WsSession> session,
                                const std::string& unique_id)
{
    if (!session->authorized) {
        send_call_error(*session->ws, unique_id, 401, "Unauthorized.");
        return;
    }

    // Sign out via CALL to /api/v1/sign/out
    handle_call(session, unique_id, "/api/v1/sign/out",
                nlohmann::json::object());
}

// ─── handle_call ────────────────────────────────────────────────────────────

void WebSocketAPI::handle_call(std::shared_ptr<WsSession> session,
                               const std::string& unique_id,
                               const std::string& action,
                               const nlohmann::json& payload)
{
    if (!session->authorized) {
        send_call_error(*session->ws, unique_id, 401, "Unauthorized.");
        return;
    }

    auto normalized = normalize_action(action);
    auto payload_str = payload.dump();

    if (session->auth.schema == Authorization::Schema::bearer) {
        authorized_fetch(session, unique_id, normalized, payload_str);
    } else if (session->auth.schema == Authorization::Schema::basic) {
        authorized_fetch(session, unique_id, normalized, payload_str);
    } else if (!session->secret.empty()) {
        signed_fetch(session, unique_id, normalized, payload_str);
    } else {
        unauthorized_fetch(session, unique_id, normalized, payload_str);
    }
}

// ─── WebSocket response helpers ─────────────────────────────────────────────

void WebSocketAPI::send_call(WsConnection& ws, std::string_view action,
                             const std::string& payload)
{
    ws.send_text(build_call_msg(action, payload));
}

void WebSocketAPI::send_call_result(WsConnection& ws,
                                    std::string_view unique_id,
                                    const std::string& payload)
{
    ws.send_text(build_result_msg(unique_id, payload));
}

void WebSocketAPI::send_call_error(WsConnection& ws,
                                   std::string_view unique_id,
                                   int code, std::string_view message)
{
    ws.send_text(build_error_msg(unique_id, code, message));
}

// ─── Fetch dispatch ─────────────────────────────────────────────────────────

void WebSocketAPI::unauthorized_fetch(std::shared_ptr<WsSession> session,
                                      const std::string& unique_id,
                                      const std::string& action,
                                      const std::string& payload)
{
    auto action_q  = pq_quote_literal(action);
    auto payload_q = (payload.empty() || payload == "{}" || payload == "[]")
                         ? std::string("null")
                         : pq_quote_literal(payload);
    auto agent_q   = pq_quote_literal(session->agent);
    auto host_q    = pq_quote_literal(session->ip);

    auto sql = fmt::format(
        "SELECT * FROM daemon.unauthorized_fetch('POST', {}, {}::jsonb, {}, {})",
        action_q, payload_q, agent_q, host_q);

    session->update_count++;
    pool_.execute(std::move(sql),
        [this, session, unique_id, action](std::vector<PgResult> results) {
            session->update_count--;
            on_fetch_result(session, unique_id, action, std::move(results));
        },
        [this, session, unique_id](std::string_view error) {
            session->update_count--;
            send_call_error(*session->ws, unique_id, 500,
                            std::string(error));
        });
}

void WebSocketAPI::authorized_fetch(std::shared_ptr<WsSession> session,
                                    const std::string& unique_id,
                                    const std::string& action,
                                    const std::string& payload)
{
    auto method_q  = pq_quote_literal("POST");
    auto action_q  = pq_quote_literal(action);
    auto payload_q = (payload.empty() || payload == "{}" || payload == "[]")
                         ? std::string("null")
                         : pq_quote_literal(payload);
    auto agent_q   = pq_quote_literal(session->agent);
    auto host_q    = pq_quote_literal(session->ip);

    std::string sql;

    if (session->auth.schema == Authorization::Schema::bearer) {
        sql = fmt::format(
            "SELECT * FROM daemon.fetch({}, {}, {}, {}::jsonb, {}, {})",
            pq_quote_literal(session->auth.token), method_q,
            action_q, payload_q, agent_q, host_q);
    } else if (session->auth.schema == Authorization::Schema::basic) {
        // Session+Secret headers or Basic auth
        if (!session->auth.username.empty() && !session->auth.password.empty()
            && session->auth.username != session->session) {
            // True Basic auth (username/password)
            sql = fmt::format(
                "SELECT * FROM daemon.authorized_fetch({}, {}, {}, {}, {}::jsonb, {}, {})",
                pq_quote_literal(session->auth.username),
                pq_quote_literal(session->auth.password),
                method_q, action_q, payload_q, agent_q, host_q);
        } else {
            // Session fetch
            sql = fmt::format(
                "SELECT * FROM daemon.session_fetch({}, {}, {}, {}, {}::jsonb, {}, {})",
                pq_quote_literal(session->session),
                pq_quote_literal(session->secret),
                method_q, action_q, payload_q, agent_q, host_q);
        }
    }

    if (sql.empty())
        return;

    session->update_count++;
    pool_.execute(std::move(sql),
        [this, session, unique_id, action](std::vector<PgResult> results) {
            session->update_count--;
            on_fetch_result(session, unique_id, action, std::move(results));
        },
        [this, session, unique_id](std::string_view error) {
            session->update_count--;
            send_call_error(*session->ws, unique_id, 500,
                            std::string(error));
        });
}

void WebSocketAPI::signed_fetch(std::shared_ptr<WsSession> session,
                                const std::string& unique_id,
                                const std::string& action,
                                const std::string& payload)
{
    // Nonce = microsecond epoch as string
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto nonce = std::to_string(us);

    // HMAC input: action + nonce + payload (or "null")
    auto sig_payload = (payload.empty() || payload == "{}" || payload == "[]")
                           ? std::string("null")
                           : payload;
    auto data = action + nonce + sig_payload;
    auto signature = hmac_sha256_hex(session->secret, data);

    auto method_q    = pq_quote_literal("POST");
    auto action_q    = pq_quote_literal(action);
    auto payload_q   = (payload.empty() || payload == "{}" || payload == "[]")
                           ? std::string("null")
                           : pq_quote_literal(payload);
    auto session_q   = pq_quote_literal(session->session);
    auto nonce_q     = pq_quote_literal(nonce);
    auto signature_q = pq_quote_literal(signature);
    auto agent_q     = pq_quote_literal(session->agent);
    auto host_q      = pq_quote_literal(session->ip);

    auto sql = fmt::format(
        "SELECT * FROM daemon.signed_fetch({}, {}, {}::json, {}, {}, {}, {}, {}, "
        "INTERVAL '{} milliseconds')",
        method_q, action_q, payload_q, session_q, nonce_q,
        signature_q, agent_q, host_q, kReceiveWindowMs);

    session->update_count++;
    pool_.execute(std::move(sql),
        [this, session, unique_id, action](std::vector<PgResult> results) {
            session->update_count--;
            on_fetch_result(session, unique_id, action, std::move(results));
        },
        [this, session, unique_id](std::string_view error) {
            session->update_count--;
            send_call_error(*session->ws, unique_id, 500,
                            std::string(error));
        });
}

// ─── PG result handling ─────────────────────────────────────────────────────

void WebSocketAPI::on_fetch_result(std::shared_ptr<WsSession> session,
                                   const std::string& unique_id,
                                   const std::string& action,
                                   std::vector<PgResult> results)
{
    if (results.empty() || !results[0].ok()) {
        std::string err = results.empty()
            ? "no result"
            : (results[0].error_message()
                ? results[0].error_message() : "unknown error");
        send_call_error(*session->ws, unique_id, 500, err);
        return;
    }

    const auto& res = results[0];
    if (res.rows() == 0 || res.columns() == 0) {
        send_call_result(*session->ws, unique_id, "{}");
        return;
    }

    // Build JSON from result
    std::string body;
    if (res.rows() == 1) {
        const char* val = res.value(0, 0);
        body = val ? val : "null";
    } else {
        // Multiple rows: build array of first-column values
        nlohmann::json arr = nlohmann::json::array();
        for (int r = 0; r < res.rows(); ++r) {
            const char* val = res.value(r, 0);
            if (val) {
                try {
                    arr.push_back(nlohmann::json::parse(val));
                } catch (...) {
                    arr.push_back(val);
                }
            }
        }
        body = arr.dump();
    }

    // Check for application-level error
    std::string error_message;
    int error_code = check_pg_error(body, error_message);
    if (error_code != 0) {
        int status = static_cast<int>(error_code_to_status(error_code));
        send_call_error(*session->ws, unique_id, status, error_message);

        // De-authorize on 401
        if (status == 401) {
            session->secret.clear();
            session->auth = Authorization{};
            session->authorized = false;
        }
        return;
    }

    // Update session state based on action
    try {
        auto j = nlohmann::json::parse(body);
        after_query(*session, action, j);
    } catch (...) {
        // Non-JSON result — still send it
    }

    send_call_result(*session->ws, unique_id, body);
}

// ─── after_query ────────────────────────────────────────────────────────────

void WebSocketAPI::after_query(WsSession& session, std::string_view action,
                               const nlohmann::json& payload)
{
    if (action == "/api/v1/sign/in") {
        session.session    = payload.value("session", session.session);
        session.secret     = payload.value("secret", session.secret);
        session.authorized = true;
    } else if (action == "/api/v1/sign/out") {
        session.secret.clear();
        session.auth = Authorization{};
        session.authorized = false;
    } else if (action == "/api/v1/authenticate" ||
               action == "/api/v1/authorize") {
        bool auth_ok = payload.value("authorized", false);
        if (auth_ok) {
            session.authorized = true;
        } else {
            session.secret.clear();
            session.auth = Authorization{};
            session.authorized = false;
        }
    }
}

// ─── Observer (LISTEN/NOTIFY) ───────────────────────────────────────────────

void WebSocketAPI::init_listen()
{
    // First: execute daemon.init_listen() to set up PG notification channels
    pool_.execute("SELECT daemon.init_listen()",
        [this](std::vector<PgResult>) {
            // Then subscribe to "notify" channel
            pool_.listen("notify",
                [this](std::string_view channel, std::string_view data) {
                    on_notify(channel, data);
                });
        },
        [](std::string_view) {
            // init_listen failed — will retry on next heartbeat
        },
        true);  // quiet
}

void WebSocketAPI::on_notify(std::string_view /*channel*/,
                             std::string_view data)
{
    // data is JSON with at least a "publisher" field
    std::string publisher;
    std::string notify_data(data);

    try {
        auto j = nlohmann::json::parse(data);
        publisher = j.value("publisher", "");
    } catch (...) {
        return;
    }

    if (publisher.empty())
        return;

    // Queue observer dispatch for each active session
    for (auto& [fd, session] : sessions_by_fd_) {
        if (!session->authorized)
            continue;

        observer_queue_.push_back(
            ObserverTask{session, publisher, notify_data});
    }

    unload_queue();
}

void WebSocketAPI::unload_queue()
{
    while (!observer_queue_.empty() &&
           observer_progress_ < max_observer_queue_) {
        auto task = std::move(observer_queue_.front());
        observer_queue_.pop_front();
        dispatch_observer(std::move(task));
    }
}

void WebSocketAPI::dispatch_observer(ObserverTask task)
{
    auto session = task.session;
    auto publisher = task.publisher;

    auto sql = fmt::format(
        "SELECT * FROM daemon.observer({}, {}, {}, {}::jsonb, {}, {})",
        pq_quote_literal(publisher),
        pq_quote_literal(session->session),
        pq_quote_literal(session->identity),
        pq_quote_literal(task.data),
        pq_quote_literal(session->agent),
        pq_quote_literal(session->ip));

    observer_progress_++;
    session->update_count++;

    pool_.execute(std::move(sql),
        [this, session, publisher](std::vector<PgResult> results) {
            session->update_count--;
            observer_progress_--;

            if (!results.empty() && results[0].ok() &&
                results[0].rows() > 0 && results[0].columns() > 0) {

                const char* val = results[0].value(0, 0);
                if (val) {
                    std::string body(val);

                    // Check for error (401 = de-authorize)
                    std::string error_message;
                    int error_code = check_pg_error(body, error_message);
                    if (error_code != 0) {
                        int status = static_cast<int>(
                            error_code_to_status(error_code));
                        if (status == 401) {
                            session->authorized = false;
                        }
                    } else {
                        send_call(*session->ws,
                                  fmt::format("/{}", publisher), body);
                    }
                }
            }

            unload_queue();
        },
        [this, session](std::string_view) {
            session->update_count--;
            observer_progress_--;
            unload_queue();
        },
        true);  // quiet
}

// ─── HTTP handlers ──────────────────────────────────────────────────────────

void WebSocketAPI::do_get(const HttpRequest& req, HttpResponse& resp)
{
    // GET /ws/list — list active sessions
    if (req.path == "/ws/list") {
        nlohmann::json arr = nlohmann::json::array();

        for (const auto& [fd, session] : sessions_by_fd_) {
            nlohmann::json s;
            s["session"]    = session->session;
            s["identity"]   = session->identity;
            s["authorized"] = session->authorized;
            s["ip"]         = session->ip;
            s["agent"]      = session->agent;
            arr.push_back(std::move(s));
        }

        resp.set_status(HttpStatus::ok)
            .set_body(arr.dump(), "application/json");
        return;
    }

    reply_error(resp, HttpStatus::not_found, "Not found.");
}

void WebSocketAPI::do_post(const HttpRequest& req, HttpResponse& resp)
{
    // POST /ws/<code>[/<identity>] — push data to WS clients
    auto [code, identity] = parse_session_path(req.path);

    if (code.empty() || code == "list") {
        reply_error(resp, HttpStatus::bad_request,
                    "POST /ws/<session_code>[/<identity>]");
        return;
    }

    // Verify Bearer token
    auto auth_header = req.header("Authorization");
    if (auth_header.empty()) {
        reply_error(resp, HttpStatus::unauthorized, "Authorization required.");
        return;
    }

    auto auth = parse_authorization(auth_header);
    if (auth.schema != Authorization::Schema::bearer) {
        reply_error(resp, HttpStatus::unauthorized,
                    "Bearer token required.");
        return;
    }

    try {
        verify_jwt(auth.token, providers_);
    } catch (const JwtExpiredError&) {
        reply_error(resp, HttpStatus::unauthorized, "Token expired.");
        return;
    } catch (const JwtVerificationError& e) {
        reply_error(resp, HttpStatus::unauthorized, e.what());
        return;
    }

    // Find matching sessions and push the message
    bool sent = false;
    auto range = sessions_by_code_.equal_range(code);
    for (auto it = range.first; it != range.second; ++it) {
        auto& session = it->second;
        if (identity != "main" && session->identity != identity)
            continue;

        send_call(*session->ws, "/ws", req.body);
        sent = true;
    }

    nlohmann::json result;
    result["sent"]   = sent;
    result["status"] = sent ? "Success" : "Session not found";

    resp.set_status(HttpStatus::ok)
        .set_body(result.dump(), "application/json");
}

} // namespace apostol

#endif // defined(WITH_POSTGRESQL) && defined(WITH_SSL)
