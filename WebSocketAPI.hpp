#pragma once

#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "apostol/apostol_module.hpp"
#include "apostol/event_loop.hpp"
#include "apostol/http.hpp"
#include "apostol/jwt.hpp"
#include "apostol/logger.hpp"
#include "apostol/oauth_providers.hpp"
#include "apostol/pg.hpp"
#include "apostol/websocket.hpp"

#include <chrono>
#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

namespace apostol
{

class Application;

// ─── WebSocketAPI ──────────────────────────────────────────────────────────
//
// Worker module for real-time WebSocket API. Implements JSON-RPC protocol
// over WebSocket, observer/pub-sub via PostgreSQL LISTEN/NOTIFY, and
// REST endpoints for push messaging and session listing.
//
// WebSocket path: /session/<code>[/<identity>]
// HTTP paths:     POST /ws/<code>[/<identity>], GET /ws/list
//
// Mirrors v1 CWebSocketAPI from apostol-crm.
//
class WebSocketAPI final : public ApostolModule
{
public:
    explicit WebSocketAPI(Application& app);

    std::string_view name() const override { return "WebSocketAPI"; }
    bool enabled() const override { return enabled_; }
    bool check_location(const HttpRequest& req) const override;
    void heartbeat(std::chrono::system_clock::time_point now) override;

    /// Called from ws_handler lambda — handles new WebSocket upgrades.
    void on_ws_upgrade(EventLoop& loop, WsConnection ws, const HttpRequest& req);

protected:
    void init_methods() override;

private:
    // ── Session ──────────────────────────────────────────────────────────────

    struct WsSession
    {
        std::string session;              // 40-char session code (from URL)
        std::string identity;             // connection identity ("main" default)
        std::shared_ptr<WsConnection> ws; // WebSocket connection
        Authorization auth;               // cached auth state
        std::string secret;               // session secret (for signed fetch)
        std::string agent;                // User-Agent
        std::string ip;                   // client IP
        bool authorized{false};
        // Set when the server sent Close (observer 401). From then on the
        // session takes no messages and gets no data; check_sessions() drops
        // it if the peer never answers. send_close() alone does not mark the
        // connection closed().
        std::chrono::steady_clock::time_point close_sent{};
    };

    std::unordered_map<int, std::shared_ptr<WsSession>> sessions_by_fd_;
    std::unordered_multimap<std::string, std::shared_ptr<WsSession>> sessions_by_code_;

    std::shared_ptr<WsSession> add_session(WsConnection ws,
                                           std::string session,
                                           std::string identity);
    void remove_session(int fd);
    // Change the session code and move the sessions_by_code_ entry with it.
    void rekey_session(WsSession& session, std::string code);

    // ── WebSocket message handling ───────────────────────────────────────────

    void on_ws_message(std::shared_ptr<WsSession> session,
                       uint8_t opcode, const std::string& payload);
    void handle_open(std::shared_ptr<WsSession> session,
                     const std::string& unique_id,
                     const nlohmann::json& payload);
    void handle_close(std::shared_ptr<WsSession> session,
                      const std::string& unique_id);
    void handle_call(std::shared_ptr<WsSession> session,
                     const std::string& unique_id,
                     const std::string& action,
                     const nlohmann::json& payload);

    // ── WebSocket responses ──────────────────────────────────────────────────

    static void send_call(WsConnection& ws, std::string_view action,
                          const std::string& payload);
    static void send_call_result(WsConnection& ws, std::string_view unique_id,
                                 const std::string& payload);
    static void send_call_error(WsConnection& ws, std::string_view unique_id,
                                int code, std::string_view message);

    // ── PG result handling ───────────────────────────────────────────────────

    void on_fetch_result(std::shared_ptr<WsSession> session,
                         const std::string& unique_id,
                         const std::string& action,
                         std::vector<PgResult> results);

    void after_query(WsSession& session, std::string_view action,
                     const nlohmann::json& payload);

    // ── Authorization ────────────────────────────────────────────────────────

    int check_session_auth(const HttpRequest& req, WsSession& session);

    // ── Session cleanup ─────────────────────────────────────────────────────

    void check_sessions();

    // ── Fetch dispatch ───────────────────────────────────────────────────────

    void unauthorized_fetch(std::shared_ptr<WsSession> session,
                            const std::string& unique_id,
                            const std::string& action,
                            const std::string& payload);

    void authorized_fetch(std::shared_ptr<WsSession> session,
                          const std::string& unique_id,
                          const std::string& action,
                          const std::string& payload);

    void signed_fetch(std::shared_ptr<WsSession> session,
                      const std::string& unique_id,
                      const std::string& action,
                      const std::string& payload);

    // ── Observer (LISTEN/NOTIFY) ─────────────────────────────────────────────

    void init_listen();
    void on_notify(std::string_view channel, std::string_view data);

    struct ObserverTask
    {
        std::shared_ptr<WsSession> session;
        std::string publisher;
        std::string data;
    };

    void dispatch_observer(ObserverTask task);
    void unload_queue();

    std::deque<ObserverTask> observer_queue_;
    std::size_t observer_progress_{0};
    static constexpr std::size_t max_observer_queue_ = 32;

    // ── HTTP handlers ────────────────────────────────────────────────────────

    void do_get(const HttpRequest& req, HttpResponse& resp);
    void do_post(const HttpRequest& req, HttpResponse& resp);

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Parse session code and identity from URL path.
    /// E.g. "/session/abc123/main" -> ("abc123", "main")
    static std::pair<std::string, std::string>
    parse_session_path(std::string_view path);

    /// Ensure action has /api/v1 prefix.
    static std::string normalize_action(std::string_view action);

    // ── State ────────────────────────────────────────────────────────────────

    PgPool&               pool_;         // worker pool (daemon) for queries
    EventLoop&            loop_;
    const OAuthProviders& providers_;
    bool                  enabled_;
    Logger&               log_;
    bool                  listen_initialized_{false};
    // A publisher_list() query is in flight. Without it heartbeat() can issue a
    // second one while the first is still queued — fail_inflight_query()
    // re-queues rather than fails, so a query can outlive the 60s tick — and
    // both then succeed. PgPool::listen() is NOT idempotent: it push_back's a
    // second handler for the same channel and dispatch_notify() calls every
    // one, so every notification would be delivered twice, then three times.
    bool                  listen_pending_{false};
    std::chrono::system_clock::time_point next_check_{};
};

} // namespace apostol

#endif // defined(WITH_POSTGRESQL) && defined(WITH_SSL)
