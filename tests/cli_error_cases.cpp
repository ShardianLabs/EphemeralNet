#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

#if !defined(_WIN32)
#include <sys/wait.h>
#endif

namespace {

struct CommandResult {
    int exit_code;
    std::string output;
};

CommandResult run_cli(const std::string& executable, const std::string& arguments) {
#if defined(_WIN32)
    const std::string command = "\"" + executable + "\" " + arguments + " 2>&1";
    FILE* pipe = _popen(command.c_str(), "r");
#else
    const std::string command = "\"" + executable + "\" " + arguments + " 2>&1";
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

bool expect_contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

int main() {
    const char* executable_env = std::getenv("EPH_CLI_EXECUTABLE");
    if (!executable_env) {
        std::cerr << "EPH_CLI_EXECUTABLE is not defined" << std::endl;
        return 1;
    }

    const std::string executable = std::filesystem::path(executable_env).string();

    try {
        const auto help = run_cli(executable, "--help");
        if (help.exit_code != 0 || !expect_contains(help.output, "Usage: eph")) {
            std::cerr << "Failure on --help. exit=" << help.exit_code << "\n" << help.output << std::endl;
            return 1;
        }

        const auto status = run_cli(executable, "status");
        if (status.exit_code == 0 || !expect_contains(status.output, "Could not contact the daemon.")) {
            std::cerr << "Failure on status without daemon. exit=" << status.exit_code << "\n" << status.output << std::endl;
            return 1;
        }

        const auto store = run_cli(executable, "store");
        if (store.exit_code == 0 || !expect_contains(store.output, "store expects the path to a file")) {
            std::cerr << "Failure on store without arguments. exit=" << store.exit_code << "\n" << store.output << std::endl;
            return 1;
        }

        const auto fetch = run_cli(executable, "fetch eph://deadbeef");
        if (fetch.exit_code == 0 || !expect_contains(fetch.output, "Could not contact the daemon.")) {
            std::cerr << "Failure on fetch without --out. exit=" << fetch.exit_code << "\n" << fetch.output << std::endl;
            return 1;
        }

#if !defined(_WIN32)
        const auto invalid_dir = run_cli(executable, "--storage-dir \"\" status");
        if (invalid_dir.exit_code == 0 || !expect_contains(invalid_dir.output, "--storage-dir cannot be empty")) {
            std::cerr << "Failure on empty --storage-dir. exit=" << invalid_dir.exit_code << "\n" << invalid_dir.output << std::endl;
            return 1;
        }
#endif

        const auto store_dir = run_cli(executable, "store .");
        if (store_dir.exit_code == 0 || !expect_contains(store_dir.output, "store expects a regular file")) {
            std::cerr << "Failure on store directory. exit=" << store_dir.exit_code << "\n" << store_dir.output << std::endl;
            return 1;
        }

        const auto fetch_dir_out = run_cli(executable, "fetch eph://deadbeef --out .");
        if (fetch_dir_out.exit_code == 0 || !expect_contains(fetch_dir_out.output, "Could not contact the daemon.")) {
            std::cerr << "Failure on fetch with directory output. exit=" << fetch_dir_out.exit_code << "\n" << fetch_dir_out.output << std::endl;
            return 1;
        }

        const auto invalid_port = run_cli(executable, "--control-port 0 status");
        if (invalid_port.exit_code == 0 || !expect_contains(invalid_port.output, "--control-port must be between 1 and 65535")) {
            std::cerr << "Failure on invalid --control-port. exit=" << invalid_port.exit_code << "\n" << invalid_port.output << std::endl;
            return 1;
        }

        const auto invalid_default_ttl = run_cli(executable, "--default-ttl 0 status");
        if (invalid_default_ttl.exit_code == 0 || !expect_contains(invalid_default_ttl.output, "--default-ttl must be a positive integer")) {
            std::cerr << "Failure on invalid --default-ttl. exit=" << invalid_default_ttl.exit_code << "\n" << invalid_default_ttl.output << std::endl;
            return 1;
        }

    } catch (const std::exception& ex) {
        std::cerr << "Exception during CLI tests: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
