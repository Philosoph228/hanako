#include <iostream>
#include <array>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <numeric>
#include <ranges>
#include <regex>
#include <unordered_set>

namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
using udp = net::ip::udp;
using net::use_awaitable;
using namespace std::chrono_literals;
using namespace net::experimental::awaitable_operators;

static constexpr char const* DEFAULT_UPSTREAM_ADDR = "1.1.1.1";
static constexpr unsigned short DEFAULT_UPSTREAM_PORT = 53;
static constexpr auto UPSTREAM_TIMEOUT = 3s;    // wait up to 3 seconds for UPD reply

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Read exactly N bytes from stream into buffer
net::awaitable<void> async_read_exact(ssl::stream<tcp::socket>& s, net::mutable_buffer buf) {
    std::size_t bytes_total = 0;
    auto ex = co_await net::this_coro::executor;
    while (bytes_total < buf.size()) {
        std::size_t n = co_await s.async_read_some(
            net::buffer(static_cast<char*>(buf.data()) + bytes_total, buf.size()),
            use_awaitable);
        if (n == 0) throw std::runtime_error("peer closed");
        bytes_total += n;
    }
}

// Forward DNS query (wire format) to upstream UDP resolver and get reply.
// Returns empty vector on timeout or error.
net::awaitable<std::vector<uint8_t>>
forward_to_upstream(net::any_io_executor ex,
                    const std::vector<uint8_t>& q,
                    const std::string& upstream_addr,
                    unsigned short upstream_port)
{
    // create a temporary UDP socket bound to ephemeral port on the executor
    udp::socket sock(ex, udp::endpoint(udp::v4(), 0));
    udp::resolver resolver(ex);

    // resolve -> returns resolver_results (a range)
    auto results = co_await resolver.async_resolve(
        udp::v4(), upstream_addr, std::to_string(upstream_port), use_awaitable);

    auto it = results.begin();
    if (it == results.end()) co_return std::vector<uint8_t>{};
    udp::endpoint upstream_ep = *it;    // dereference iterator -> udp::endpoint

    // send query
    co_await sock.async_send_to(net::buffer(q), upstream_ep, use_awaitable);

    // prepare for receive with timeout
    std::vector<uint8_t> resp(1024);
    net::steady_timer timer(ex);
    timer.expires_after(UPSTREAM_TIMEOUT);

    try {
        // race: receive OR timer
        auto winner = co_await (
            sock.async_receive_from(net::buffer(resp), upstream_ep, use_awaitable)
            || timer.async_wait(use_awaitable)
        );

        if (std::holds_alternative<std::size_t>(winner)) {
            std::size_t len = std::get<std::size_t>(winner);
            resp.resize(len);
            co_return resp;
        }
        else {
            // timer fired
            co_return std::vector<uint8_t>{};
        }
    }
    catch (const std::exception& /*e*/) {
        // network error
        co_return std::vector<uint8_t>{};
    }
}

// Parse a domain name from `msg` (length msg_len).
// `offset` is updated to the position *after* the name (unless a jump/pointer is used
// - in that case the offset is advanced by 2 where the pointer was encountered).
// On success returns true and sets `out_name`.
bool parse_name(const uint8_t* msg, size_t msg_len, size_t& offset, std::string& out_name)
{
    out_name.clear();
    if (offset >= msg_len) return false;

    size_t cur = offset;
    bool jumped = false;
    const size_t max_jumps = 128;   // avoid infinite loops
    size_t jumps = 0;

    while (true) {
        if (cur >= msg_len) return false;
        uint8_t len = msg[cur];

        // Pointer: two high bits set
        if ((len & 0xC0) == 0xC0) {
            if (cur + 1 >= msg_len) return false;
            uint16_t ptr = ((uint16_t)(len & 0x3F) << 8) | msg[cur + 1];
            if (ptr >= msg_len) return false; // sanity
            if (!jumped) {
                // advance original offset by 2 (pointer takes two bytes)
                offset = cur + 2;
            }
            cur = ptr;
            jumped = true;

            if (++jumps > max_jumps) return false;
            continue;
        }

        // End of name
        if (len == 0) {
            if (!jumped) {
                offset = cur + 1; // skip the 0 byte
            }
            break;
        }

        // Label
        if (cur + 1 + len > msg_len) return false; // OOB
        cur++; // move to label bytes
        if (!out_name.empty()) out_name.push_back('.');
        out_name.append(reinterpret_cast<const char*>(msg + cur), len);
        cur += len;
        if (!jumped) {
            offset = cur; // update offset to after this label
        }
    }

    return true;
}

using ipv4_t = std::array<uint8_t, 4>;

// hasher for ipv4_t
struct ipv4_hasher {
    std::size_t operator()(ipv4_t const& a) const noexcept {
        // pack into uint32_t in network order (big-endian) for hashing
        uint32_t v = (uint32_t(a[0]) << 24) | (uint32_t(a[1]) << 16) |
                     (uint32_t(a[2]) << 8) | (uint32_t(a[3]));
        return std::hash<uint32_t>{}(v);
    }
};

static std::string ipv4_to_string(ipv4_t const& ip) {
    std::ostringstream ss;
    ss << unsigned(ip[0]) << '.' << unsigned(ip[1]) << '.'
       << unsigned(ip[2]) << '.' << unsigned(ip[3]);
    return ss.str();
}

static ipv4_t ipv4_from_bytes(const uint8_t* b) noexcept {
    return ipv4_t{ b[0], b[1], b[2], b[3] };
}

static std::mutex g_cache_mutex;
static std::unordered_map<std::string, std::unordered_set<ipv4_t, ipv4_hasher>> g_a_cache;
static std::vector<std::regex> g_watch_patterns;    // Compiled at startup

// returns IPv4 addresses as dotted strings found in the ANSWER section
static std::vector<ipv4_t> extract_a_records(const std::vector<uint8_t>& resp) {
    std::vector<ipv4_t> out;
    if (resp.size() < sizeof(dns_header)) return out;

    dns_header hdr;
    std::memcpy(&hdr, resp.data(), sizeof(hdr));
    uint16_t ancount = ntohs(hdr.ancount);
    uint16_t qdcount = ntohs(hdr.qdcount);

    const uint8_t* msg = resp.data();
    size_t msg_len = resp.size();
    size_t offset = sizeof(dns_header);

    // skip questions
    for (uint16_t q = 0; q < qdcount; ++q) {
        std::string tmp;
        if (!parse_name(msg, msg_len, offset, tmp)) return out;
        if (offset + 4 > msg_len) return out;
        offset += 4;
    }

    // parse answers
    for (uint16_t a = 0; a < ancount; ++a) {
        std::string aname;
        if (!parse_name(msg, msg_len, offset, aname)) return out;
        if (offset + 10 > msg_len) return out;

        uint16_t atype = (uint16_t(msg[offset]) << 8) | uint16_t(msg[offset + 1]);
        uint16_t rdlen = (uint16_t(msg[offset + 8]) << 8) | uint16_t(msg[offset + 9]);
        offset += 10;

        if (offset + rdlen > msg_len) return out;

        if (atype == 1 && rdlen == 4) { // A record
            out.push_back(ipv4_from_bytes(msg + offset));
        }

        offset += rdlen;
    }

    return out;
}

inline bool match_any_watchlist(std::string_view qname) {
    if (g_watch_patterns.empty()) return false;
    std::string s(qname);   // std::regex APIs take string/char*
    for (auto const& re : g_watch_patterns) {
        if (std::regex_match(s, re)) return true;
    }
    return false;
}

static std::string canonicalize_qname(std::string_view q) {
    std::string s(q);
    // lower-case (DNS is case-insensitive)
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    // optionally strip trailing dot
    if (!s.empty() && s.back() == '.') s.pop_back();
    return s;
}

net::awaitable<void> handle_tls_session(ssl::stream<tcp::socket> stream,
                                        const std::string& upstream_addr,
                                        unsigned short upstream_port) {
    // keep stream alive across co_await points
    auto s = std::make_shared<ssl::stream<tcp::socket>>(std::move(stream));
    auto ex = co_await net::this_coro::executor;
    
    try {
        // Perform the server-side TLS handshake
        co_await s->async_handshake(ssl::stream_base::server, use_awaitable);

        // NOTE: RFC 7858 uses the standard DNS-over-TCP framing:
        //   first two bytes: networ-order (big-endian) unsigned 16-bit length of DNS message,
        //   followed immediately by that many octets of DNS message.
        // std::array<char, 1024> buffer;
        for (;;) {
            std::array<uint8_t, 2> lenbuf{};
            co_await async_read_exact(*s, net::buffer(lenbuf));
            uint16_t qlen = (uint16_t(lenbuf[0]) << 8 | uint16_t(lenbuf[1]));
            if (qlen == 0) {
                // protocol error or keepalive; treat as close
                break;
            }
            if (qlen > 65535) throw std::runtime_error("query length too big");

            // read full DNS query
            std::vector<uint8_t> query(qlen);
            co_await async_read_exact(*s, net::buffer(query.data(), qlen));

            // Safely copy header to avoid alignment/aliasing UB
            if (query.size() < sizeof(dns_header)) {
                std::cerr << "  truncated packet (no header)\n";
                break;
            }

            dns_header hdr;
            std::memcpy(&hdr, query.data(), sizeof(hdr));
            uint16_t packet_id = ntohs(hdr.id);
            uint16_t query_count = ntohs(hdr.qdcount);

            std::cout << "Packet ID: " << packet_id << "\n";
            std::cout << "Question count: " << query_count << "\n";

            const uint8_t* msg = query.data();
            size_t msg_len = query.size();
            size_t offset = sizeof(dns_header);

            // per-request matched names (canonicalized)
            std::vector<std::string> matched_names;

            uint16_t to_parse = std::min<uint16_t>(query_count, 256);
            for (uint16_t i = 0; i < to_parse; ++i) {
                std::cout << "Query #" << i << ":\n";

                std::string qname;
                if (!parse_name(msg, msg_len, offset, qname)) {
                    std::cerr << "  failed to parse name at question " << i << "\n";
                    goto close_session;
                }

                if (offset + 4 > msg_len) {
                    std::cerr << "  truncated question (missing QTYPE/QCLASS)\n";
                    goto close_session;
                }

                uint16_t qtype = (uint16_t(msg[offset]) << 8) | uint16_t(msg[offset + 1]);
                uint16_t qclass = (uint16_t(msg[offset + 2]) << 8) | uint16_t(msg[offset + 3]);
                offset += 4;

                // canonicalize and test against watchlist (fast: precompiled regexes)
                std::string qcanon = canonicalize_qname(qname);
                if (match_any_watchlist(qcanon)) {
                    matched_names.push_back(qcanon);
                }

                std::cout << "  Name : " << qname << "\n";
                std::cout << "  QTYPE: " << qtype << "  QCLASS: " << qclass << "\n";
            }
            
            // Forward to upstream
            auto upstream_resp = co_await forward_to_upstream(ex, query, upstream_addr, upstream_port);

            if (upstream_resp.empty()) {
                // On timeout or error, reply with SERVFAIL (optional).
                // For simplicity here, close connection.
                std::cerr << "[DoT] upstream timeout or error - closing session\n";
                break;
            }

            // Parse A records as 4-byte blobs (ipv4_t = std::array<uint8_t, 4>)
            auto a_ips = extract_a_records(upstream_resp);

            // Insert into global cache (thread-safe)
            // only if we have matches and A records
            if (!a_ips.empty() && !matched_names.empty()) {
                std::scoped_lock lock(g_cache_mutex);   // C++17/C++23 scoped lock
                for (auto const& name : matched_names) {
                    auto &set_ref = g_a_cache[name];    // default-constructs unordered_set if needed
                    for (auto const& ip : a_ips) {
                        auto [it, inserted] = set_ref.insert(ip);
                        if (inserted) {
                            std::cout << "[cache] inserted " << ipv4_to_string(ip)
                                      << " for " << name << '\n';
                        }
                    }
                }
            }

            // send back framed response: 2-byte length + payload
            uint16_t rlen = static_cast<uint16_t>(upstream_resp.size());
            std::vector<uint8_t> out;
            out.resize(2 + upstream_resp.size());
            out[0] = static_cast<uint8_t>((rlen >> 8) & 0xFF);
            out[1] = static_cast<uint8_t>(rlen & 0xFF);
            std::copy(upstream_resp.begin(), upstream_resp.end(), out.begin() + 2);

            // write full reply
            std::size_t written = co_await net::async_write(*s, net::buffer(out), use_awaitable);
            (void)written;
        }

close_session:
        ;
    }
    catch (const std::exception& e) {
        // connection-level error (client disconnects, etc.)
        std::cerr << "[DoT session] exception: " << e.what() << '\n';
    }
    // socket closes when shared_ptr goes out of scope
}

// Parse newline-separated patterns. LInes starting with '#' or empty are ignored.
// Throws std::regex_error on invalid regex (with message including line).
std::vector<std::regex>
compile_regex_list(
    std::string_view patterns_text,
    std::regex_constants::syntax_option_type opts =
        std::regex_constants::ECMAScript |
        std::regex_constants::icase |
        std::regex_constants::optimize)
{
    std::vector<std::regex> out;
    std::string line;
    std::istringstream ss{std::string(patterns_text)};  // copy -> istringstream
    size_t lineno = 0;
    while (std::getline(ss, line)) {
        ++lineno;
        // trim whitespace (simple)
        auto first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        auto last = line.find_last_not_of(" \t\r\n");
        std::string_view trimmed(line.c_str() + first, last - first + 1);

        if (trimmed.empty() || trimmed.front() == '#') continue;

        try {
            // construct std::regex from std::string to avoid any string_view overload issues
            out.emplace_back(std::string(trimmed), opts);
        }
        catch (const std::regex_error& ex) {
            std::ostringstream e;
            e << "regex compile error on line " << lineno << ": " << ex.what()
              << " (pattern: \"" << std::string(trimmed) << "\")";
            throw std::runtime_error(e.str());
        }
    }
    return out;
}

// Load from file convenience
std::vector<std::regex>
compile_regex_list_from_file(
    std::string_view path,
    std::regex_constants::syntax_option_type opts =
        std::regex_constants::ECMAScript |
        std::regex_constants::icase |
        std::regex_constants::optimize) {
    std::ifstream ifs{ std::string(path) };
    if (!ifs) throw std::runtime_error("cannot open regex file");
    std::ostringstream buf;
    buf << ifs.rdbuf();
    return compile_regex_list(buf.str(), opts);
}

int main(int argc, char** argv)
{
    std::cout << "hanako started" << std::endl;

    const std::string regex_list_text = R"(# domains to monitor
^.*\.?google\.com$
^.*\.?openai\.com$
^.*\.?chatgpt\.com$)";

    try {
        g_watch_patterns = compile_regex_list(regex_list_text);
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to compile regex list: " << e.what() << '\n';
        std::exit(1);
    }

    try {
        std::string upstream_addr = DEFAULT_UPSTREAM_ADDR;
        unsigned short upstream_port = DEFAULT_UPSTREAM_PORT;
        if (argc >= 4) {
            upstream_addr = argv[2];
            upstream_port = static_cast<unsigned short>(std::stoi(argv[3]));
        }

        net::io_context ioc{ static_cast<int>(std::thread::hardware_concurrency()) };

        // Create SSL context for TLS server
        ssl::context ctx{ ssl::context::tls_server };

        // Recommended options:
        ctx.set_options(
            ssl::context::default_workarounds
            | ssl::context::no_sslv2
            | ssl::context::no_sslv3
            | ssl::context::no_tlsv1
            | ssl::context::no_tlsv1_1
        );
        
        // Load certificate and key (PEM)
        ctx.use_certificate_chain_file("server.crt");
        ctx.use_private_key_file("server.key", ssl::context::pem);

        // Force TLS 1.3 only
        // Set both min and max to TLS1_3_VERSION to prevent downgrade
        SSL_CTX* native = ctx.native_handle();
        if (native == nullptr) {
            throw std::runtime_error("unable to get native SSL_CTX");
        }

        // Set TLS 1.3 as min and max
        if (!SSL_CTX_set_min_proto_version(native, TLS1_3_VERSION) ||
            !SSL_CTX_set_max_proto_version(native, TLS1_3_VERSION)) {
            throw std::runtime_error("failed to set TLS protocol version to TLS1.3");
        }

        // Set preferred TLS 1.3 cipher suites
        if (!SSL_CTX_set_ciphersuites(native,
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")) {
            throw std::runtime_error("failed to set TLS 1.3 ciphersuites");
        }

        // (Optional) disable session tickets or configure as desired:
        // SSL_CTX_set_options(native, SSL_OP_NO_TICKET);

        // Spawn acceptor coroutine
        net::co_spawn(ioc,
            [&ctx, upstream_addr, upstream_port]() -> net::awaitable<void> {
                auto ex = co_await net::this_coro::executor;

                tcp::acceptor acceptor(ex, {tcp::v4(), 854});
                acceptor.set_option(net::socket_base::reuse_address(true));
                std::cout << "DoT listening on port 853" << "\n";

                for (;;) {
                    // accept a socket (co_await)
                    tcp::socket socket = co_await acceptor.async_accept(use_awaitable);
                    
                    // construct ssl stream for the accepted socket
                    ssl::stream<tcp::socket> ssl_stream(std::move(socket), ctx);

                    // spawn a detached coroutine to handle the encrypted session
                    net::co_spawn(ex,
                                handle_tls_session(std::move(ssl_stream), upstream_addr, upstream_port),
                                net::detached);
                }
            }(),
            net::detached);

        // handle SIGINT/SIGTERM to stop gracefully
        net::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto){
            std::cout << "Shutting down DoT server\n";
            ioc.stop();
        });

        // run io_context on a thread pool
        std::vector<std::thread> threads;
        auto thread_count = std::max(1u, std::thread::hardware_concurrency());
        threads.reserve(thread_count);
        for (unsigned i = 0; i < thread_count; ++i)
            threads.emplace_back([&](){ ioc.run(); });

        std::cout << "TLS echo server running on port 854 (threads: " << thread_count << ")\n";

        for (auto &t : threads) t.join();
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << '\n';
        return 1;
    }
    
    return 0;
}