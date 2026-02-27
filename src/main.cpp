// C++ Voice Agent Starter - Backend Server
//
// Simple WebSocket proxy to Deepgram's Voice Agent API using Crow (HTTP/WS)
// and Boost.Beast (outbound WS client). Forwards all messages (JSON and binary)
// bidirectionally between client and Deepgram.
//
// Routes:
//
//   GET  /api/session       - Issue signed session token
//   GET  /api/metadata      - Project metadata from deepgram.toml
//   GET  /health            - Health check
//   WS   /api/voice-agent   - WebSocket proxy to Deepgram Agent API (auth required)

#include <crow.h>
#include <nlohmann/json.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace beast     = boost::beast;
namespace websocket = beast::websocket;
namespace net       = boost::asio;
namespace ssl       = net::ssl;
using tcp           = net::ip::tcp;

// ============================================================================
// CONFIGURATION
// ============================================================================

struct AppConfig {
    std::string deepgram_api_key;
    std::string deepgram_agent_host = "agent.deepgram.com";
    std::string deepgram_agent_path = "/v1/agent/converse";
    int         port                = 8081;
    std::string host                = "0.0.0.0";
    std::string session_secret;
};

static AppConfig config;

// ============================================================================
// HELPERS - Environment & file utilities
// ============================================================================

/// Read an environment variable with an optional default.
static std::string env_or(const char* name, const std::string& fallback) {
    const char* val = std::getenv(name);
    return (val && val[0]) ? std::string(val) : fallback;
}

/// Load KEY=VALUE pairs from a .env file into the process environment.
static void load_dotenv(const std::string& path = ".env") {
    std::ifstream f(path);
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        // Strip optional surrounding quotes
        if (val.size() >= 2 &&
            ((val.front() == '"' && val.back() == '"') ||
             (val.front() == '\'' && val.back() == '\''))) {
            val = val.substr(1, val.size() - 2);
        }
        ::setenv(key.c_str(), val.c_str(), 0); // 0 = don't overwrite existing
    }
}

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

using json = nlohmann::json;

/** JWT expiry duration in seconds (1 hour). */
static const int JWT_EXPIRY_SECONDS = 3600;

#include <openssl/hmac.h>
#include <openssl/rand.h>

/// Base64url-encode raw bytes (no padding).
static std::string base64url_encode(const unsigned char* data, size_t len) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(4 * ((len + 2) / 3));
    for (size_t i = 0; i < len; i += 3) {
        unsigned int n = static_cast<unsigned int>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<unsigned int>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<unsigned int>(data[i + 2]);
        result.push_back(table[(n >> 18) & 0x3F]);
        result.push_back(table[(n >> 12) & 0x3F]);
        result.push_back((i + 1 < len) ? table[(n >> 6) & 0x3F] : '=');
        result.push_back((i + 2 < len) ? table[n & 0x3F] : '=');
    }
    // Convert to base64url: replace + with -, / with _, strip padding
    for (auto& c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    result.erase(std::remove(result.begin(), result.end(), '='), result.end());
    return result;
}

/// Base64url-encode a string.
static std::string base64url_encode(const std::string& input) {
    return base64url_encode(
        reinterpret_cast<const unsigned char*>(input.data()), input.size());
}

/// Base64url-decode a string to raw bytes.
static std::string base64url_decode(const std::string& input) {
    std::string padded = input;
    // Convert base64url back to base64
    for (auto& c : padded) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    // Add padding
    while (padded.size() % 4 != 0) padded.push_back('=');

    static const int decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    std::string result;
    result.reserve(padded.size() * 3 / 4);
    for (size_t i = 0; i < padded.size(); i += 4) {
        int a = decode_table[static_cast<unsigned char>(padded[i])];
        int b = decode_table[static_cast<unsigned char>(padded[i + 1])];
        int c = decode_table[static_cast<unsigned char>(padded[i + 2])];
        int d = decode_table[static_cast<unsigned char>(padded[i + 3])];
        if (a < 0 || b < 0) break;
        result.push_back(static_cast<char>((a << 2) | (b >> 4)));
        if (c >= 0) result.push_back(static_cast<char>(((b & 0x0F) << 4) | (c >> 2)));
        if (d >= 0) result.push_back(static_cast<char>(((c & 0x03) << 6) | d));
    }
    return result;
}

/// Sign data with HMAC-SHA256 and return base64url-encoded signature.
static std::string hmac_sha256(const std::string& key, const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int  len = 0;
    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()),
         data.size(), result, &len);
    return base64url_encode(result, len);
}

/// Generate a cryptographically-random hex string (32 bytes / 64 hex chars).
static std::string generate_session_secret() {
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf));
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; ++i)
        oss << std::setw(2) << static_cast<int>(buf[i]);
    return oss.str();
}

/// Generate a JWT token (HS256) with a 1-hour expiry.
static std::string create_session_token() {
    auto now = std::time(nullptr);
    auto exp = now + JWT_EXPIRY_SECONDS;

    json header  = {{"alg", "HS256"}, {"typ", "JWT"}};
    json payload = {{"iat", now}, {"exp", exp}};

    std::string header_enc  = base64url_encode(header.dump());
    std::string payload_enc = base64url_encode(payload.dump());
    std::string signing_input = header_enc + "." + payload_enc;
    std::string signature = hmac_sha256(config.session_secret, signing_input);

    return signing_input + "." + signature;
}

/// Validate a JWT token. Returns true if signature is valid and not expired.
static bool validate_session_token(const std::string& token) {
    // Split token into 3 parts: header.payload.signature
    size_t dot1 = token.find('.');
    if (dot1 == std::string::npos) return false;
    size_t dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return false;

    std::string header_enc  = token.substr(0, dot1);
    std::string payload_enc = token.substr(dot1 + 1, dot2 - dot1 - 1);
    std::string signature   = token.substr(dot2 + 1);

    // Verify HMAC-SHA256 signature
    std::string signing_input = header_enc + "." + payload_enc;
    std::string expected_sig  = hmac_sha256(config.session_secret, signing_input);
    if (signature != expected_sig) return false;

    // Verify header algorithm
    try {
        std::string header_json = base64url_decode(header_enc);
        json header = json::parse(header_json);
        if (header.value("alg", "") != "HS256") return false;
    } catch (...) {
        return false;
    }

    // Verify expiration
    try {
        std::string payload_json = base64url_decode(payload_enc);
        json payload = json::parse(payload_json);
        auto now = std::time(nullptr);
        if (payload.contains("exp") && payload["exp"].get<int64_t>() < now)
            return false;
    } catch (...) {
        return false;
    }

    return true;
}

/// Validate a JWT from WebSocket subprotocol header: "access_token.<jwt>".
/// Returns the full protocol string if valid, empty string if invalid.
static std::string validate_ws_token(const std::string& protocols) {
    if (protocols.empty()) return "";
    // Protocols may be comma-separated
    std::istringstream stream(protocols);
    std::string proto;
    while (std::getline(stream, proto, ',')) {
        // Trim whitespace
        auto start = proto.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        proto = proto.substr(start);
        auto end = proto.find_last_not_of(" \t");
        if (end != std::string::npos) proto = proto.substr(0, end + 1);

        const std::string prefix = "access_token.";
        if (proto.rfind(prefix, 0) == 0) {
            std::string token = proto.substr(prefix.size());
            if (validate_session_token(token))
                return proto;
        }
    }
    return "";
}

// ============================================================================
// METADATA - deepgram.toml parser (minimal TOML subset)
// ============================================================================

/// Parse the [meta] section from deepgram.toml and return it as a JSON string.
/// Only supports simple key = "value" and key = [...] entries.
static std::string read_meta_json(const std::string& path = "deepgram.toml") {
    std::ifstream f(path);
    if (!f.is_open()) return "";

    bool in_meta = false;
    crow::json::wvalue meta;
    std::string line;
    while (std::getline(f, line)) {
        // Trim leading whitespace
        auto pos = line.find_first_not_of(" \t");
        if (pos == std::string::npos) continue;
        line = line.substr(pos);

        // Section header
        if (line.front() == '[') {
            in_meta = (line.find("[meta]") == 0);
            continue;
        }
        if (!in_meta) continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        // Trim
        key.erase(key.find_last_not_of(" \t") + 1);
        key.erase(0, key.find_first_not_of(" \t"));
        val.erase(0, val.find_first_not_of(" \t"));

        if (val.front() == '"') {
            // String value
            val = val.substr(1);
            auto end_quote = val.rfind('"');
            if (end_quote != std::string::npos) val = val.substr(0, end_quote);
            meta[key] = val;
        } else if (val.front() == '[') {
            // Array of strings
            std::vector<std::string> arr;
            auto close = val.find(']');
            std::string inner = val.substr(1, close - 1);
            std::istringstream ss(inner);
            std::string item;
            while (std::getline(ss, item, ',')) {
                auto qs = item.find('"');
                auto qe = item.rfind('"');
                if (qs != std::string::npos && qe != qs)
                    arr.push_back(item.substr(qs + 1, qe - qs - 1));
            }
            std::vector<crow::json::wvalue> jarr;
            for (auto& s : arr) jarr.emplace_back(s);
            meta[key] = std::move(jarr);
        }
    }
    return meta.dump();
}

// ============================================================================
// DEEPGRAM PROXY SESSION - Boost.Beast outbound WebSocket client
// ============================================================================

/// Represents a single bidirectional proxy session between a Crow client
/// WebSocket and a Deepgram Agent WebSocket via Boost.Beast.
class DeepgramSession : public std::enable_shared_from_this<DeepgramSession> {
public:
    DeepgramSession(crow::websocket::connection& client_conn)
        : client_conn_(client_conn),
          ioc_(),
          ssl_ctx_(ssl::context::tlsv12_client),
          resolver_(ioc_),
          ws_(ioc_, ssl_ctx_) {
        ssl_ctx_.set_default_verify_paths();
        ssl_ctx_.set_verify_mode(ssl::verify_peer);
    }

    ~DeepgramSession() { stop(); }

    /// Start the outbound connection to Deepgram in a background thread.
    void start() {
        auto self = shared_from_this();
        thread_ = std::thread([self]() { self->run(); });
    }

    /// Send a message from the client to Deepgram.
    void send_to_deepgram(const std::string& data, bool is_binary) {
        std::lock_guard<std::mutex> lock(write_mutex_);
        if (!connected_) return;
        try {
            ws_.binary(is_binary);
            ws_.write(net::buffer(data));
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error forwarding to Deepgram: " << e.what();
        }
    }

    /// Gracefully close the Deepgram connection.
    void stop() {
        running_ = false;
        try {
            if (connected_) {
                connected_ = false;
                // Cancel the underlying socket to interrupt the blocking read,
                // rather than calling ws_.close() which triggers a Boost Beast
                // assertion (!impl.wr_close) when a read is in progress.
                beast::get_lowest_layer(ws_).cancel();
            }
        } catch (...) {}
        if (thread_.joinable()) thread_.join();
    }

    bool is_connected() const { return connected_; }

private:
    void run() {
        try {
            // Resolve Deepgram host
            auto const results = resolver_.resolve(
                config.deepgram_agent_host, "443");

            // Connect TCP
            beast::get_lowest_layer(ws_).connect(results);

            // Set SNI hostname for TLS
            if (!SSL_set_tlsext_host_name(
                    ws_.next_layer().native_handle(),
                    config.deepgram_agent_host.c_str())) {
                throw beast::system_error(
                    beast::error_code(static_cast<int>(::ERR_get_error()),
                                      net::error::get_ssl_category()),
                    "Failed to set SNI hostname");
            }

            // TLS handshake
            ws_.next_layer().handshake(ssl::stream_base::client);

            // WebSocket handshake with auth header
            ws_.set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::authorization,
                            "Token " + config.deepgram_api_key);
                    req.set(beast::http::field::user_agent,
                            "cpp-voice-agent/1.0");
                }));

            ws_.handshake(config.deepgram_agent_host, config.deepgram_agent_path);

            connected_ = true;
            CROW_LOG_INFO << "Connected to Deepgram Agent API";

            // Read loop: forward Deepgram messages to client
            while (running_ && connected_) {
                beast::flat_buffer buffer;
                ws_.read(buffer);

                bool is_bin = ws_.got_binary();
                std::string payload(
                    static_cast<const char*>(buffer.data().data()),
                    buffer.data().size());

                try {
                    if (is_bin)
                        client_conn_.send_binary(payload);
                    else
                        client_conn_.send_text(payload);
                } catch (const std::exception& e) {
                    CROW_LOG_ERROR << "Error forwarding to client: " << e.what();
                    break;
                }
            }
        } catch (const beast::system_error& se) {
            if (se.code() == websocket::error::closed) {
                CROW_LOG_INFO << "Deepgram connection closed normally";
            } else {
                CROW_LOG_ERROR << "Deepgram connection error: " << se.what();
            }
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Deepgram session error: " << e.what();
        }

        connected_ = false;

        // Notify the client that the upstream closed (only if the client
        // didn't initiate the close — running_ is set false by stop())
        if (running_) {
            try {
                client_conn_.close("Deepgram disconnected");
            } catch (...) {}
        }
    }

    crow::websocket::connection& client_conn_;

    net::io_context                                               ioc_;
    ssl::context                                                  ssl_ctx_;
    tcp::resolver                                                 resolver_;
    websocket::stream<beast::ssl_stream<beast::tcp_stream>>       ws_;

    std::thread thread_;
    std::mutex  write_mutex_;
    std::atomic<bool> running_{true};
    std::atomic<bool> connected_{false};
};

// ============================================================================
// ACTIVE CONNECTIONS - Track all proxy sessions for graceful shutdown
// ============================================================================

static std::mutex                                         sessions_mutex;
static std::set<std::shared_ptr<DeepgramSession>>         active_sessions;

static void register_session(std::shared_ptr<DeepgramSession> s) {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    active_sessions.insert(s);
}

static void unregister_session(std::shared_ptr<DeepgramSession> s) {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    active_sessions.erase(s);
}

static void close_all_sessions() {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    CROW_LOG_INFO << "Closing " << active_sessions.size()
                  << " active session(s)";
    for (auto& s : active_sessions) {
        s->stop();
    }
    active_sessions.clear();
}

// ============================================================================
// MAIN
// ============================================================================

int main() {
    // Load .env file (if present) before reading env vars
    load_dotenv();

    // ---- Load configuration from environment variables ----
    config.deepgram_api_key = env_or("DEEPGRAM_API_KEY", "");
    if (config.deepgram_api_key.empty()) {
        std::cerr << "ERROR: DEEPGRAM_API_KEY environment variable is required\n"
                  << "Please copy sample.env to .env and add your API key\n";
        return 1;
    }

    config.port           = std::stoi(env_or("PORT", "8081"));
    config.host           = env_or("HOST", "0.0.0.0");
    config.session_secret = env_or("SESSION_SECRET", "");
    if (config.session_secret.empty())
        config.session_secret = generate_session_secret();

    // ---- Set up Crow application ----
    crow::SimpleApp app;

    // Per-connection session map (keyed by raw pointer of crow::websocket::connection)
    std::mutex conn_map_mutex;
    std::unordered_map<crow::websocket::connection*,
                       std::shared_ptr<DeepgramSession>> conn_map;

    // ---- GET /api/session - Issue signed session token ----
    CROW_ROUTE(app, "/api/session")
        .methods(crow::HTTPMethod::GET, crow::HTTPMethod::OPTIONS)
    ([](const crow::request& req) {
        crow::response res;
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");

        if (req.method == crow::HTTPMethod::OPTIONS) {
            res.code = 200;
            return res;
        }

        crow::json::wvalue body;
        body["token"] = create_session_token();
        res.set_header("Content-Type", "application/json");
        res.body = body.dump();
        return res;
    });

    // ---- GET /api/metadata - Project metadata from deepgram.toml ----
    CROW_ROUTE(app, "/api/metadata")
        .methods(crow::HTTPMethod::GET, crow::HTTPMethod::OPTIONS)
    ([](const crow::request& req) {
        crow::response res;
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");

        if (req.method == crow::HTTPMethod::OPTIONS) {
            res.code = 200;
            return res;
        }

        std::string meta = read_meta_json();
        if (meta.empty() || meta == "null") {
            res.code = 500;
            res.set_header("Content-Type", "application/json");
            res.body = R"({"error":"INTERNAL_SERVER_ERROR","message":"Failed to read metadata from deepgram.toml"})";
            return res;
        }

        res.set_header("Content-Type", "application/json");
        res.body = meta;
        return res;
    });

    // ---- GET /health - Health check ----
    CROW_ROUTE(app, "/health")
        .methods(crow::HTTPMethod::GET, crow::HTTPMethod::OPTIONS)
    ([](const crow::request& req) {
        crow::response res;
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");

        if (req.method == crow::HTTPMethod::OPTIONS) {
            res.code = 200;
            return res;
        }

        res.set_header("Content-Type", "application/json");
        res.body = R"({"status":"ok"})";
        return res;
    });

    // ---- WS /api/voice-agent - WebSocket proxy to Deepgram Agent API ----
    CROW_WEBSOCKET_ROUTE(app, "/api/voice-agent")
        .mirrorprotocols()
        .onaccept([](const crow::request& req, void**) -> bool {
            // Validate session token from Sec-WebSocket-Protocol subprotocol
            std::string protocols = req.get_header_value("Sec-WebSocket-Protocol");
            std::string valid = validate_ws_token(protocols);
            if (valid.empty()) {
                CROW_LOG_WARNING << "WebSocket auth failed: invalid or missing token";
                return false;
            }
            return true;
        })
        .onopen([&conn_map, &conn_map_mutex](crow::websocket::connection& conn) {
            CROW_LOG_INFO << "Client connected to /api/voice-agent";

            // Create outbound Deepgram session
            auto session = std::make_shared<DeepgramSession>(conn);
            register_session(session);
            {
                std::lock_guard<std::mutex> lock(conn_map_mutex);
                conn_map[&conn] = session;
            }

            // Start the outbound connection in a background thread
            session->start();
        })
        .onmessage([&conn_map, &conn_map_mutex](
                        crow::websocket::connection& conn,
                        const std::string& data, bool is_binary) {
            std::shared_ptr<DeepgramSession> session;
            {
                std::lock_guard<std::mutex> lock(conn_map_mutex);
                auto it = conn_map.find(&conn);
                if (it != conn_map.end()) session = it->second;
            }
            if (session && session->is_connected()) {
                session->send_to_deepgram(data, is_binary);
            }
        })
        .onclose([&conn_map, &conn_map_mutex](
                     crow::websocket::connection& conn,
                     const std::string& reason, uint16_t) {
            CROW_LOG_INFO << "Client disconnected: " << reason;

            std::shared_ptr<DeepgramSession> session;
            {
                std::lock_guard<std::mutex> lock(conn_map_mutex);
                auto it = conn_map.find(&conn);
                if (it != conn_map.end()) {
                    session = it->second;
                    conn_map.erase(it);
                }
            }
            if (session) {
                session->stop();
                unregister_session(session);
            }
        });

    // ---- Start server ----
    std::string sep(70, '=');
    CROW_LOG_INFO << sep;
    CROW_LOG_INFO << "Backend API Server running at http://localhost:"
                  << config.port;
    CROW_LOG_INFO << "";
    CROW_LOG_INFO << "GET  /api/session";
    CROW_LOG_INFO << "WS   /api/voice-agent (auth required)";
    CROW_LOG_INFO << "GET  /api/metadata";
    CROW_LOG_INFO << "GET  /health";
    CROW_LOG_INFO << sep;

    app.bindaddr(config.host)
       .port(config.port)
       .multithreaded()
       .signal_clear()     // Let us handle signals ourselves
       .run();

    // Graceful shutdown on server stop
    close_all_sessions();

    return 0;
}
