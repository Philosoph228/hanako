#include <iostream>
#include <array>
#include <vector>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace net = boost::asio;
using tcp = net::ip::tcp;
using net::use_awaitable;

net::awaitable<void> handle_session(tcp::socket sock0) {
    // keep socket alive across co_await points
    auto socket = std::make_shared<tcp::socket>(std::move(sock0));
    
    try {
        std::array<char, 1024> buffer;
        for (;;) {
            // read some data (co_await yields control)
            std::size_t n = co_await socket->async_read_some(net::buffer(buffer), use_awaitable);

            if (n == 0) {
                // connection closed
                break;
            }

            // echo it back
            co_await net::async_write(*socket, net::buffer(buffer.data(), n), use_awaitable);
        }
    }
    catch (const std::exception& e) {
        // connection-level error (client disconnects, etc.)
        std::cerr << "[session] exception: " << e.what() << '\n';
    }
}

int main()
{
    std::cout << "hanako started" << std::endl;
    try {
        net::io_context ioc{ static_cast<int>(std::thread::hardware_concurrency()) };
    
        net::co_spawn(ioc,
            [&]() -> net::awaitable<void>
            {
                auto ex = co_await net::this_coro::executor;

                tcp::acceptor acceptor(ex, {tcp::v4(), 854});
                acceptor.set_option(net::socket_base::reuse_address(true));

                for (;;) {
                    // accept a socket (co_await)
                    tcp::socket socket = co_await acceptor.async_accept(use_awaitable);
                    
                    // spawn session
                    net::co_spawn(ioc,
                                handle_session(std::move(socket)),
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

        std::cout << "Echo server running on port 854 (threads: " << thread_count << ")\n";

        for (auto &t : threads) t.join();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Fatal: " << e.what() << '\n';
        return 1;
    }
    
    return 0;
}