#include <iostream>
#include <array>
#include <vector>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
using net::use_awaitable;

net::awaitable<void> handle_tls_session(ssl::stream<tcp::socket> stream) {
    // keep stream alive across co_await points
    auto s = std::make_shared<ssl::stream<tcp::socket>>(std::move(stream));
    
    try {
        // Perform the server-side TLS handshake
        co_await s->async_handshake(ssl::stream_base::server, use_awaitable);

        std::array<char, 1024> buffer;
        for (;;) {
            // read some data (co_await yields control)
            std::size_t n = co_await s->async_read_some(net::buffer(buffer), use_awaitable);

            if (n == 0) {
                // connection closed
                break;
            }

            // echo it back
            co_await net::async_write(*s, net::buffer(buffer.data(), n), use_awaitable);
        }
    }
    catch (const std::exception& e) {
        // connection-level error (client disconnects, etc.)
        std::cerr << "[session] exception: " << e.what() << '\n';
    }
    // socket closes when shared_ptr goes out of scope
}

int main()
{
    std::cout << "hanako started" << std::endl;
    try {
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
            [&ioc, &ctx]() -> net::awaitable<void> {
                auto ex = co_await net::this_coro::executor;

                tcp::acceptor acceptor(ex, {tcp::v4(), 854});
                acceptor.set_option(net::socket_base::reuse_address(true));

                for (;;) {
                    // accept a socket (co_await)
                    tcp::socket socket = co_await acceptor.async_accept(use_awaitable);
                    
                    // construct ssl stream for the accepted socket
                    ssl::stream<tcp::socket> ssl_stream(std::move(socket), ctx);

                    // spawn a detached coroutine to handle the encrypted session
                    net::co_spawn(ioc,
                                handle_tls_session(std::move(ssl_stream)),
                                net::detached);
                }
            }(),
            net::detached);

        // handle SIGINT/SIGTERM to stop gracefully
        net::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto){
            std::cout << "Shutting down...\n";
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