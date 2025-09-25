#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#include <iterator>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

struct CommandResult {
    int exit_code{};
    std::string output;
};

CommandResult run_cli(const std::string& executable, const std::string& arguments) {
#if defined(_WIN32)
    const std::string command = "cmd /C \"\"" + executable + "\" " + arguments + " 2>&1\"";
    FILE* pipe = _popen(command.c_str(), "r");
#else
    const std::string command = "\"" + executable + "\" " + arguments + " 2>&1";
    FILE* pipe = popen(command.c_str(), "r");
#endif
    if (!pipe) {
        throw std::runtime_error("Failed to launch CLI process");
    }

    std::string output;
    std::array<char, 256> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        output.append(buffer.data());
    }

#if defined(_WIN32)
    const int status = _pclose(pipe);
    const int exit_code = status;
#else
    const int status = pclose(pipe);
    int exit_code = -1;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    }
#endif

    return CommandResult{exit_code, output};
}

std::string quote(const std::filesystem::path& value) {
    return "\"" + value.string() + "\"";
}

std::string quote(const std::string& value) {
    return "\"" + value + "\"";
}

bool expect_contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

bool wait_for_status(const std::string& executable,
                     const std::string& base_options,
                     std::chrono::milliseconds timeout,
                     bool expect_up) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto status = run_cli(executable, base_options + " status");
        const bool up = status.exit_code == 0 && expect_contains(status.output, "Daemon active");
        if (up == expect_up) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    return false;
}

#if defined(_WIN32)
std::string unique_suffix() {
    return std::to_string(::GetTickCount64());
}
#else
std::string unique_suffix() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::to_string(now);
}
#endif

}  // namespace

int main() {
    const char* executable_env = std::getenv("EPH_CLI_EXECUTABLE");
    if (!executable_env) {
        std::cerr << "EPH_CLI_EXECUTABLE is not defined" << std::endl;
        return 1;
    }

    const std::filesystem::path executable_path(executable_env);
    const auto temp_root = std::filesystem::temp_directory_path();
    const auto test_dir = temp_root / ("eph-bootstrap-" + unique_suffix());
    std::error_code ec;
    std::filesystem::create_directories(test_dir, ec);
    if (ec) {
        std::cerr << "Failed to create temp directory: " << ec.message() << std::endl;
        return 1;
    }

    auto cleanup = [&]() {
        std::error_code remove_ec;
        std::filesystem::remove_all(test_dir, remove_ec);
    };

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> port_dist(36000, 59000);
    const int control_port = port_dist(gen);

    const std::string base_options = std::string("--storage-dir ") + quote(test_dir) +
                                     " --control-host 127.0.0.1 --control-port " + std::to_string(control_port) +
                                     " --yes";

    bool daemon_started = false;
    auto ensure_stop = [&]() {
        if (!daemon_started) {
            return;
        }
        const auto stop_res = run_cli(executable_path.string(), base_options + " stop");
        (void)stop_res;
        wait_for_status(executable_path.string(), base_options, std::chrono::seconds(5), false);
        daemon_started = false;
    };

    try {
        const auto start_res = run_cli(executable_path.string(), base_options + " start");
        if (start_res.exit_code != 0 || !expect_contains(start_res.output, "Daemon started")) {
            std::cerr << "Failed to start daemon\n" << start_res.output << std::endl;
            cleanup();
            return 1;
        }
        daemon_started = true;

        if (!wait_for_status(executable_path.string(), base_options, std::chrono::seconds(10), true)) {
            std::cerr << "Daemon did not become ready" << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        const auto payload_path = test_dir / "bootstrap_payload.bin";
        const std::string payload = "bootstrap-manifest-test";
        {
            std::ofstream out(payload_path, std::ios::binary);
            out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        }

        const auto store_res = run_cli(executable_path.string(), base_options + " store " + quote(payload_path));
        if (store_res.exit_code != 0 || !expect_contains(store_res.output, "File stored")) {
            std::cerr << "Failed to store payload\n" << store_res.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        const std::string manifest_prefix = "  Manifest: ";
        const auto manifest_pos = store_res.output.find(manifest_prefix);
        if (manifest_pos == std::string::npos) {
            std::cerr << "Manifest missing in store output" << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }
        const auto manifest_end = store_res.output.find('\n', manifest_pos);
        const std::string manifest = store_res.output.substr(
            manifest_pos + manifest_prefix.size(),
            manifest_end == std::string::npos ? std::string::npos : manifest_end - manifest_pos - manifest_prefix.size());

        const auto output_path = test_dir / "bootstrap_result.bin";
        const auto fetch_command = base_options + " fetch " + quote(manifest) +
                                   " --bootstrap-max-attempts 100000 --out " + quote(output_path);
        const auto fetch_res = run_cli(executable_path.string(), fetch_command);
        if (fetch_res.exit_code != 0 ||
            !expect_contains(fetch_res.output, "Falling back to swarm discovery") ||
            !expect_contains(fetch_res.output, "File retrieved")) {
            std::cerr << "Fetch command failed\n" << fetch_res.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        std::ifstream recovered(output_path, std::ios::binary);
        std::string recovered_data((std::istreambuf_iterator<char>(recovered)), std::istreambuf_iterator<char>());
        if (recovered_data != payload) {
            std::cerr << "Recovered data mismatch" << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        const auto stop_res = run_cli(executable_path.string(), base_options + " stop");
        if (stop_res.exit_code != 0 || !expect_contains(stop_res.output, "Daemon stopped")) {
            std::cerr << "Failed to stop daemon\n" << stop_res.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }
        daemon_started = false;

        cleanup();
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Exception in bootstrap CLI test: " << ex.what() << std::endl;
        ensure_stop();
        cleanup();
        return 1;
    }
}
