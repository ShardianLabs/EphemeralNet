#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <csignal>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

class WinsockRuntime {
public:
#if defined(_WIN32)
    WinsockRuntime() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
    }

    ~WinsockRuntime() {
        WSACleanup();
    }
#else
    WinsockRuntime() = default;
    ~WinsockRuntime() = default;
#endif
};

struct CommandResult {
    int exit_code;
    std::string output;
};

CommandResult run_cli(const std::string& executable, const std::string& arguments) {
#if defined(_WIN32)
    const std::string command = "cmd /C \"\"" + executable + "\" " + arguments + " 2>&1\"";
    FILE* pipe = _popen(command.c_str(), "r");
#else
    const std::string command = executable + " " + arguments + " 2>&1";
    FILE* pipe = popen(command.c_str(), "r");
#endif
    if (!pipe) {
        throw std::runtime_error("Failed to open a pipe to the CLI");
    }

    std::string output;
    std::array<char, 256> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        output.append(buffer.data());
    }

#if defined(_WIN32)
    const int status = _pclose(pipe);
    return CommandResult{status, output};
#else
    const int status = pclose(pipe);
    int exit_code = status;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    }
    return CommandResult{exit_code, output};
#endif
}

bool expect_contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

std::string quote(const std::string& value) {
    return "\"" + value + "\"";
}

std::string quote(const std::filesystem::path& value) {
    return quote(value.string());
}

bool can_bind_port(std::uint16_t port) {
#if defined(_WIN32)
    SOCKET handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle == INVALID_SOCKET) {
        return false;
    }

    BOOL exclusive = TRUE;
    ::setsockopt(handle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    const bool bound = ::bind(handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    ::closesocket(handle);
    return bound;
#else
    int handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle < 0) {
        return false;
    }

    int reuse = 1;
    ::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    const bool bound = ::bind(handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    ::close(handle);
    return bound;
#endif
}

bool wait_for_port_release(std::uint16_t port, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (can_bind_port(port)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool wait_for_status(const std::string& executable,
                     const std::string& base_options,
                     std::chrono::milliseconds timeout,
                     bool expect_up) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto status = run_cli(executable, base_options + " status");
        const bool up = status.exit_code == 0 && expect_contains(status.output, "Daemon active");
        if (expect_up == up) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    return false;
}

std::uint64_t unique_suffix() {
#if defined(_WIN32)
    return static_cast<std::uint64_t>(::GetTickCount64());
#else
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
#endif
}

int main() {
    WinsockRuntime winsock_runtime;

    const char* executable_env = std::getenv("EPH_CLI_EXECUTABLE");
    if (!executable_env) {
        std::cerr << "EPH_CLI_EXECUTABLE is not defined" << std::endl;
        return 1;
    }

    const std::filesystem::path executable_path(executable_env);
    const auto temp_root = std::filesystem::temp_directory_path();
    const auto test_dir = temp_root / ("eph-cli-interleaved-" + std::to_string(unique_suffix()));
    std::filesystem::create_directories(test_dir);

    const auto cleanup = [&]() {
        std::error_code ec;
        std::filesystem::remove_all(test_dir, ec);
    };

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> port_dist(40000, 50000);
    const int control_port = port_dist(gen);
    int transport_port = port_dist(gen);
    while (transport_port == control_port) {
        transport_port = port_dist(gen);
    }

    const std::string options_string = std::string(" --storage-dir ") + quote(test_dir) +
                                     " --control-host 127.0.0.1 --control-port " + std::to_string(control_port) +
                                     " --transport-port " + std::to_string(transport_port) +
                                     " --yes";

    bool daemon_started = false;

    auto ensure_stop = [&]() {
        if (!daemon_started) {
            return;
        }
        // Use interleaved options for stop as well
        const auto stop_res = run_cli(executable_path.string(), "stop" + options_string);
        (void)stop_res;
        wait_for_status(executable_path.string(), options_string, std::chrono::seconds(3), false);
        wait_for_port_release(static_cast<std::uint16_t>(transport_port), std::chrono::seconds(3));
        daemon_started = false;
    };

    try {
        // Test interleaved options: eph start --control-port ...
        const std::string start_command = "start" + options_string;
        const auto start_res = run_cli(executable_path.string(), start_command);
        if (start_res.exit_code != 0 || !expect_contains(start_res.output, "Daemon started in the background")) {
            std::cerr << "Failed to start daemon with interleaved options\n" << start_res.output << "Command: " << start_command << std::endl;
            cleanup();
            return 1;
        }
        daemon_started = true;

        if (!wait_for_status(executable_path.string(), options_string, std::chrono::seconds(20), true)) {
            std::cerr << "Daemon did not respond within the expected time" << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        // Test interleaved options: eph list --control-port ...
        const auto list_initial = run_cli(executable_path.string(), "list" + options_string);
        if (list_initial.exit_code != 0 || !expect_contains(list_initial.output, "Local chunks: 0")) {
            std::cerr << "Unexpected initial listing with interleaved options\n" << list_initial.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        const auto input_file = test_dir / "payload.bin";
        const std::string payload = "ephemeral payload";
        {
            std::ofstream out(input_file, std::ios::binary);
            out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        }

        // Test interleaved options: eph store [options] <file>
        // Note: Global options must come before positional arguments if the command takes positional arguments,
        // because the global parser stops at the first positional argument (the file).
        // However, options can come after the command name.
        const auto store_res = run_cli(executable_path.string(), "store" + options_string + " " + quote(input_file));
        if (store_res.exit_code != 0 || !expect_contains(store_res.output, "File stored")) {
            std::cerr << "Failed to store payload with interleaved options\n" << store_res.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        // Test interleaved options: eph store --control-port ... <file>
        // This should also work now because we backtrack if we see unknown option (which --control-port is NOT, it is known global).
        // Wait, if we put global options BEFORE the file, they are parsed as global options.
        // eph store --control-port ... <file>
        // store: command.
        // --control-port: global option. Parsed.
        // <file>: positional arg for store.
        // This should work.
        
        // Let's test: eph store --ttl 3600 <file>
        // store: command.
        // --ttl: unknown global option. Backtrack.
        // store handler called.
        // store handler sees --ttl.
        // store handler expects file path first.
        // store handler will fail?
        // "store expects the path to a file"
        // So `eph store --ttl 3600 <file>` will fail with "File not found: --ttl".
        // This is expected behavior for now as we didn't change store handler.
        
        ensure_stop();
        cleanup();
        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "Exception during CLI interleaved flow test: " << ex.what() << std::endl;
        ensure_stop();
        cleanup();
        return 1;
    }
}
