#include <iostream>
#include <array>
#include <vector>
#include <thread>
#include <chrono>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

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

            // Forward to upstream UDP resolver (simple behavior)
            auto upstream_resp = co_await forward_to_upstream(ex, query, upstream_addr, upstream_port);

            if (upstream_resp.empty()) {
                // On timeout or error, reply with SERVFAIL (optional).
                // For simplicity here, close connection.
                std::cerr << "[DoT] upstream timeout or error - closing session\n";
                break;
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
    }
    catch (const std::exception& e) {
        // connection-level error (client disconnects, etc.)
        std::cerr << "[DoT session] exception: " << e.what() << '\n';
    }
    // socket closes when shared_ptr goes out of scope
}

int main(int argc, char** argv)
{
    std::cout << "hanako started" << std::endl;
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