#include "ephemeralnet/relay/EventLoop.hpp"
#include "ephemeralnet/relay/RelayServer.hpp"

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>

namespace {

using ephemeralnet::relay::EventLoop;
using ephemeralnet::relay::RelayServer;
using ephemeralnet::relay::RelayServerConfig;

EventLoop* g_loop = nullptr;

void handle_signal(int) {
    if (g_loop) {
        g_loop->stop();
    }
}

void install_signal_handlers() {
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
}

struct CliConfig {
    RelayServerConfig config;
    bool show_help{false};
    bool valid{true};
    std::string error;
};

std::optional<std::pair<std::string, std::uint16_t>> parse_listen_endpoint(const std::string& text) {
    const auto pos = text.find(':');
    if (pos == std::string::npos) {
        return std::nullopt;
    }
    std::string host = text.substr(0, pos);
    std::string port_text = text.substr(pos + 1);
    if (host.empty() || port_text.empty()) {
        return std::nullopt;
    }
    char* end = nullptr;
    const auto port_value = std::strtoul(port_text.c_str(), &end, 10);
    if (!end || *end != '\0' || port_value == 0 || port_value > 65535) {
        return std::nullopt;
    }
    return std::make_pair(host, static_cast<std::uint16_t>(port_value));
}

CliConfig parse_arguments(int argc, char** argv) {
    CliConfig parsed;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            parsed.show_help = true;
            continue;
        }
        if (arg == "--listen") {
            if (i + 1 >= argc) {
                parsed.valid = false;
                parsed.error = "--listen requires host:port";
                break;
            }
            const std::string value = argv[++i];
            auto endpoint = parse_listen_endpoint(value);
            if (!endpoint) {
                parsed.valid = false;
                parsed.error = "Invalid --listen value";
                break;
            }
            parsed.config.listen_host = endpoint->first;
            parsed.config.listen_port = endpoint->second;
            continue;
        }
        parsed.valid = false;
        parsed.error = "Unknown argument: " + arg;
        break;
    }
    return parsed;
}

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [--listen host:port]\n";
    std::cout << "Options:\n";
    std::cout << "  --listen host:port   Address to bind (default 0.0.0.0:9750)\n";
    std::cout << "  -h, --help           Show this message\n";
}

}  // namespace

int main(int argc, char** argv) {
    const auto cli = parse_arguments(argc, argv);
    if (!cli.valid) {
        std::cerr << cli.error << "\n";
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (cli.show_help) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    install_signal_handlers();

    EventLoop loop;
    g_loop = &loop;
    RelayServer server(loop, cli.config);
    if (!server.start()) {
        g_loop = nullptr;
        return EXIT_FAILURE;
    }

    loop.run();

    server.stop();
    g_loop = nullptr;
    return EXIT_SUCCESS;
}
