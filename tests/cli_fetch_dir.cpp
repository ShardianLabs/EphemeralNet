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
#if defined(_WIN32)
    WinsockRuntime winsock_runtime;
#endif

    const char* executable_env = std::getenv("EPH_CLI_EXECUTABLE");
    if (!executable_env) {
        std::cerr << "EPH_CLI_EXECUTABLE is not defined" << std::endl;
        return 1;
    }

    const std::filesystem::path executable_path(executable_env);
    const auto temp_root = std::filesystem::temp_directory_path();
    const auto test_dir = temp_root / ("eph-cli-fetch-" + std::to_string(unique_suffix()));
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

    const std::string base_options = std::string("--storage-dir ") + quote(test_dir) +
                                     " --control-host 127.0.0.1 --control-port " + std::to_string(control_port) +
                                     " --transport-port " + std::to_string(transport_port) +
                                     " --yes";

    bool daemon_started = false;

    auto ensure_stop = [&]() {
        if (!daemon_started) {
            return;
        }
        const auto stop_res = run_cli(executable_path.string(), base_options + " stop");
        (void)stop_res;
        wait_for_status(executable_path.string(), base_options, std::chrono::seconds(3), false);
        daemon_started = false;
    };

    try {
        const std::string start_command = base_options + " start";
        const auto start_res = run_cli(executable_path.string(), start_command);
        if (start_res.exit_code != 0 || !expect_contains(start_res.output, "Daemon started in the background")) {
            std::cerr << "Failed to start daemon\n" << start_res.output << std::endl;
            cleanup();
            return 1;
        }
        daemon_started = true;

        if (!wait_for_status(executable_path.string(), base_options, std::chrono::seconds(10), true)) {
            std::cerr << "Daemon did not respond within the expected time" << std::endl;
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

        const auto store_res = run_cli(executable_path.string(), base_options + " store " + quote(input_file));
        if (store_res.exit_code != 0 || !expect_contains(store_res.output, "File stored")) {
            std::cerr << "Failed to store payload\n" << store_res.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        const std::string manifest_prefix = "  Manifest: ";
        const auto manifest_pos = store_res.output.find(manifest_prefix);
        if (manifest_pos == std::string::npos) {
            std::cerr << "Manifest not found in output\n" << store_res.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }
        const auto manifest_end = store_res.output.find('\n', manifest_pos);
        const std::string manifest = store_res.output.substr(
            manifest_pos + manifest_prefix.size(),
            manifest_end == std::string::npos ? std::string::npos : manifest_end - manifest_pos - manifest_prefix.size());

        // Test 1: Fetch to existing directory
        const auto existing_dir = test_dir / "existing_dir";
        std::filesystem::create_directories(existing_dir);
        
        const auto fetch_res1 = run_cli(executable_path.string(),
                                       base_options + " fetch " + quote(manifest) + " --out " + quote(existing_dir));
        if (fetch_res1.exit_code != 0 || !expect_contains(fetch_res1.output, "File retrieved")) {
            std::cerr << "Failed to fetch to existing directory\n" << fetch_res1.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }
        
        if (!std::filesystem::exists(existing_dir / "payload.bin")) {
             std::cerr << "File not found in existing directory" << std::endl;
             ensure_stop();
             cleanup();
             return 1;
        }

        // Test 2: Fetch to non-existing directory with trailing slash
        // Note: On Windows, quote("dir/") might be tricky if backslash is used.
        // We use forward slash for the test string to avoid escaping issues with trailing backslash and quote.
        const auto new_dir = test_dir / "new_dir";
        std::string new_dir_str = new_dir.string();
        
        // Replace backslashes with forward slashes to avoid \" being interpreted as escaped quote
        std::replace(new_dir_str.begin(), new_dir_str.end(), '\\', '/');
        
        if (new_dir_str.back() != '/') {
            new_dir_str += "/";
        }
        
        const auto fetch_res2 = run_cli(executable_path.string(),
                                       base_options + " fetch " + quote(manifest) + " --out " + quote(new_dir_str));
        if (fetch_res2.exit_code != 0 || !expect_contains(fetch_res2.output, "File retrieved")) {
            std::cerr << "Failed to fetch to new directory with slash\n" << fetch_res2.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        if (!std::filesystem::exists(new_dir / "payload.bin")) {
             std::cerr << "File not found in new directory" << std::endl;
             ensure_stop();
             cleanup();
             return 1;
        }

        ensure_stop();
        cleanup();
        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "Exception during CLI flow test: " << ex.what() << std::endl;
        ensure_stop();
        cleanup();
        return 1;
    }
}
