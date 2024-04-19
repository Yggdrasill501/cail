#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <cstdlib>
#include <iostream>
#include <string>

namespace beast = boost::beast;         // Namespace from Boost.Beast
namespace http = beast::http;           // From Boost.Beast.HTTP
namespace asio = boost::asio;           
namespace ssl = asio::ssl;              // From Boost.Asio.SSL
using tcp = asio::ip::tcp;              // From Boost.Asio.IP.TCP

// This function creates and returns an SSL stream wrapped around a TCP socket.
ssl::stream<tcp::socket> create_ssl_socket(asio::io_context& ioc, ssl::context& ctx, const std::string& host, const std::string& port) {
    tcp::resolver resolver{ioc};
    ssl::stream<tcp::socket> stream{ioc, ctx};

    // Set SNI Hostname (many hosts need this to handshake successfully)
    if(!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str())) {
        beast::error_code ec{static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category()};
        throw beast::system_error{ec};
    }

    auto const results = resolver.resolve(host, port);
    asio::connect(stream.next_layer(), results.begin(), results.end());
    stream.handshake(ssl::stream_base::client);
    return stream;
}

int main(int argc, char** argv) {
    try {
        auto const host = "example.com";
        auto const port = "443";
        auto const target = "/";
        int version = 11;  // HTTP 1.1

        asio::io_context ioc;
        ssl::context ctx{ssl::context::sslv23_client};

        // This sets the root certificates and loads them to verify the server
        ctx.set_default_verify_paths();

        // Open the connection
        auto stream = create_ssl_socket(ioc, ctx, host, port);

        // Set up an HTTP GET request message
        http::request<http::string_body> req{http::verb::get, target, version};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        // Send the HTTP request to the remote host
        http::write(stream, req);

        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the HTTP response
        http::read(stream, buffer, res);

        // Write the message to cout
        std::cout << res << std::endl;

        // Gracefully close the stream
        beast::error_code ec;
        stream.shutdown(ec);
        if(ec == asio::error::eof) {
            // Rationale:
            // http://www.boost.org/doc/libs/1_65_0/doc/html/boost_asio/reference.html#boost_asio.reference.boost_asio.error.eof
            ec = {};
        }
        if(ec)
            throw beast::system_error{ec};
    } catch(std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
