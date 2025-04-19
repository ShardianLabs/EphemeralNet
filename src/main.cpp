#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/core/Node.hpp"
#include "ephemeralnet/crypto/Sha256.hpp"
#include "ephemeralnet/daemon/ControlPlane.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

namespace {

using namespace std::chrono_literals;

struct GlobalOptions {
    bool persistent{false};
    bool persistent_set{false};
    bool wipe{true};
    bool wipe_set{false};
    std::uint8_t wipe_passes{1};
    bool wipe_passes_set{false};
    std::optional<std::string> storage_dir{};
    std::optional<std::uint32_t> identity_seed{};
    std::optional<std::string> peer_id_hex{};
    std::optional<std::uint64_t> default_ttl_seconds{};
    std::optional<std::string> control_host{};
    std::optional<std::uint16_t> control_port{};
    bool assume_yes{false};
};

class CliException : public std::exception {
public:
    CliException(std::string code, std::string message, std::string hint = {})
        : code_(std::move(code)), message_(std::move(message)), hint_(std::move(hint)) {
        formatted_ = code_.empty() ? message_ : ("[" + code_ + "] " + message_);
    }

    const char* what() const noexcept override {
        return formatted_.c_str();
    }

    const std::string& code() const noexcept { return code_; }
    const std::string& message() const noexcept { return message_; }
    const std::string& hint() const noexcept { return hint_; }

private:
    std::string code_;
    std::string message_;
    std::string hint_;
    std::string formatted_;
};

[[noreturn]] void throw_cli_error(std::string code, std::string message, std::string hint = {}) {
    throw CliException(std::move(code), std::move(message), std::move(hint));
}

[[noreturn]] void throw_daemon_unreachable() {
    throw_cli_error("E_DAEMON_UNREACHABLE",
                    "Could not contact the daemon.",
                    "Start it with 'eph start' (Windows) or 'eph serve' in another terminal, and verify --control-host/--control-port");
}

std::string trim(std::string value) {
    const auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](unsigned char ch) { return !is_space(ch); }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [&](unsigned char ch) { return !is_space(ch); }).base(), value.end());
    return value;
}

std::string to_lower(std::string value);

bool has_whitespace(std::string_view text) {
    return text.find_first_of(" \t\r\n") != std::string_view::npos;
}

bool stdin_is_interactive() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return ::isatty(STDIN_FILENO) != 0;
#endif
}

bool confirm_action(const std::string& prompt, bool default_yes, bool assume_yes) {
    if (assume_yes || !stdin_is_interactive()) {
        return default_yes;
    }

    const std::string suffix = default_yes ? " [Y/n]: " : " [y/N]: ";
    while (true) {
        std::cout << prompt << suffix;
        std::cout.flush();
        std::string input;
        if (!std::getline(std::cin, input)) {
            return default_yes;
        }
        input = to_lower(trim(input));
        if (input.empty()) {
            return default_yes;
        }
        if (input == "y" || input == "yes" || input == "s" || input == "si" || input == "sí") {
            return true;
        }
        if (input == "n" || input == "no") {
            return false;
        }
        std::cout << "Unrecognized answer. Type 'y' for yes or 'n' for no." << std::endl;
    }
}

void print_cli_error(const CliException& ex) {
    std::cerr << "Error";
    if (!ex.code().empty()) {
        std::cerr << " [" << ex.code() << ']';
    }
    std::cerr << ": " << ex.message() << std::endl;
    if (!ex.hint().empty()) {
        std::cerr << "Hint: " << ex.hint() << std::endl;
    }
}

void print_daemon_failure(const ephemeralnet::daemon::ControlResponse& response) {
    const auto code_it = response.fields.find("CODE");
    const auto message_it = response.fields.find("MESSAGE");
    const auto hint_it = response.fields.find("HINT");

    const std::string code = code_it != response.fields.end() && !code_it->second.empty()
                                 ? code_it->second
                                 : std::string{"ERR_DAEMON_UNKNOWN"};
    const std::string message = message_it != response.fields.end() && !message_it->second.empty()
                                    ? message_it->second
                                    : std::string{"Daemon operation failed"};

    std::cerr << "Daemon error [" << code << "]: " << message << std::endl;
    if (hint_it != response.fields.end() && !hint_it->second.empty()) {
        std::cerr << "Hint: " << hint_it->second << std::endl;
    }
}

std::atomic_bool g_run_loop{true};

void signal_handler(int) {
    g_run_loop.store(false);
}

void print_usage() {
    std::cout << "EphemeralNet CLI" << std::endl;
    std::cout << "Usage: eph [options] <command> [args]\n\n";
    std::cout << "Global options:\n"
              << "  --storage-dir <path>      Directory for persistent chunks (default ./storage)\n"
              << "  --persistent              Enable persistent storage\n"
              << "  --no-persistent           Disable persistent storage\n"
              << "  --no-wipe                 Disable secure wipe on expiry\n"
              << "  --wipe-passes <n>         Number of passes for secure wipe (>=1)\n"
              << "  --identity-seed <n>       Deterministic seed for node identity\n"
              << "  --peer-id <hex>           Node identifier (64 hexadecimal characters)\n"
              << "  --default-ttl <sec>       Default TTL for new chunks\n"
              << "  --control-host <host>     Control socket host (default 127.0.0.1)\n"
              << "  --control-port <port>     Control socket port (default 47777)\n"
              << "  --help                    Print this help message\n\n";
    std::cout << "Commands:\n"
              << "  start                     Launch the daemon in the background\n"
              << "  stop                      Ask the daemon to shut down\n"
              << "  status                    Query daemon status\n"
              << "  store <file> [--ttl <sec>]\n"
              << "                           Ask the daemon to store a file and return eph://\n"
              << "  fetch <eph://...> --out <file>\n"
              << "                           Retrieve a file using an eph:// manifest\n"
              << "  list                      List chunks stored locally\n"
              << "  serve                     Start the daemon in the foreground (Ctrl+C to exit)\n"
              << "  help                      Alias for --help\n";
}

bool parse_uint64(std::string_view text, std::uint64_t& value) {
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end;
}

bool parse_uint32(std::string_view text, std::uint32_t& value) {
    std::uint64_t temp{};
    if (!parse_uint64(text, temp) || temp > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    value = static_cast<std::uint32_t>(temp);
    return true;
}

bool parse_uint16(std::string_view text, std::uint16_t& value) {
    std::uint64_t temp{};
    if (!parse_uint64(text, temp) || temp > std::numeric_limits<std::uint16_t>::max()) {
        return false;
    }
    value = static_cast<std::uint16_t>(temp);
    return true;
}

std::optional<std::uint8_t> parse_hex_byte(char high, char low) {
    auto hex_to_int = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    const int hi = hex_to_int(high);
    const int lo = hex_to_int(low);
    if (hi < 0 || lo < 0) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>((hi << 4) | lo);
}

template <typename ArrayType>
std::optional<ArrayType> parse_hex_array(const std::string& hex) {
    if (hex.size() != ArrayType{}.size() * 2) {
        return std::nullopt;
    }
    ArrayType result{};
    for (std::size_t i = 0; i < result.size(); ++i) {
        const auto byte = parse_hex_byte(hex[2 * i], hex[2 * i + 1]);
        if (!byte.has_value()) {
            return std::nullopt;
        }
        result[i] = *byte;
    }
    return result;
}

std::string strip_quotes(std::string value) {
    if (value.size() >= 2) {
        const char first = value.front();
        const char last = value.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            return value.substr(1, value.size() - 2);
        }
    }
    return value;
}

void validate_global_options(GlobalOptions& options) {
    if (options.storage_dir) {
        auto raw = strip_quotes(*options.storage_dir);
        raw = trim(raw);
        if (raw.empty()) {
            throw_cli_error("E_INVALID_STORAGE_DIR",
                            "--storage-dir cannot be empty",
                            "Provide a directory path, e.g. --storage-dir ./data");
        }
        if (has_whitespace(raw)) {
            throw_cli_error("E_INVALID_STORAGE_DIR",
                            "--storage-dir must not contain whitespace",
                            "Wrap the path in quotes or use a path without spaces");
        }
        std::filesystem::path absolute;
        try {
            absolute = std::filesystem::absolute(std::filesystem::path(raw));
        } catch (const std::exception&) {
            throw_cli_error("E_INVALID_STORAGE_DIR",
                            "Failed to resolve --storage-dir",
                            "Ensure the path is valid on this platform and try again");
        }
        if (std::filesystem::exists(absolute) && !std::filesystem::is_directory(absolute)) {
            throw_cli_error("E_INVALID_STORAGE_DIR",
                            "--storage-dir points to a file",
                            "Select a directory or remove the existing file at " + absolute.string());
        }
        const auto parent = absolute.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            throw_cli_error("E_INVALID_STORAGE_DIR",
                            "Parent directory does not exist for --storage-dir",
                            "Create " + parent.string() + " first or choose an existing location");
        }
        options.storage_dir = absolute.string();
    }

    if (options.control_host) {
        auto host = strip_quotes(*options.control_host);
        host = trim(host);
        if (host.empty()) {
            throw_cli_error("E_INVALID_CONTROL_HOST",
                            "--control-host cannot be empty",
                            "Use an IP address or hostname, e.g. --control-host 127.0.0.1");
        }
        if (has_whitespace(host)) {
            throw_cli_error("E_INVALID_CONTROL_HOST",
                            "--control-host must not contain spaces",
                            "If you need to specify an IPv6 address, wrap it in [brackets]");
        }
        options.control_host = host;
    }

    if (options.control_port) {
        if (*options.control_port == 0) {
            throw_cli_error("E_INVALID_CONTROL_PORT",
                            "--control-port must be between 1 and 65535",
                            "Choose a TCP port greater than zero, e.g. --control-port 47777");
        }
    }

    if (options.peer_id_hex) {
        auto candidate = strip_quotes(*options.peer_id_hex);
        candidate = trim(candidate);
        if (candidate.size() != ephemeralnet::PeerId{}.size() * 2) {
            throw_cli_error("E_INVALID_PEER_ID",
                            "--peer-id must be exactly 64 hexadecimal characters",
                            "Example: --peer-id 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        }
        for (char ch : candidate) {
            if (!std::isxdigit(static_cast<unsigned char>(ch))) {
                throw_cli_error("E_INVALID_PEER_ID",
                                "--peer-id accepts hexadecimal characters only",
                                "Remove invalid characters or omit --peer-id to auto-generate one");
            }
        }
        options.peer_id_hex = candidate;
    }
}

ephemeralnet::PeerId make_peer_id(const GlobalOptions& options) {
    if (options.peer_id_hex) {
        if (auto parsed = parse_hex_array<ephemeralnet::PeerId>(*options.peer_id_hex)) {
            return *parsed;
        }
        throw_cli_error("E_INVALID_PEER_ID",
                        "--peer-id must be exactly 64 hexadecimal characters",
                        "Example: --peer-id 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    }

    if (options.identity_seed) {
        std::array<std::uint8_t, 4> seed_bytes{};
        const auto seed = *options.identity_seed;
        seed_bytes[0] = static_cast<std::uint8_t>((seed >> 24) & 0xFF);
        seed_bytes[1] = static_cast<std::uint8_t>((seed >> 16) & 0xFF);
        seed_bytes[2] = static_cast<std::uint8_t>((seed >> 8) & 0xFF);
        seed_bytes[3] = static_cast<std::uint8_t>(seed & 0xFF);

        const auto digest = ephemeralnet::crypto::Sha256::digest(std::span<const std::uint8_t>(seed_bytes.data(), seed_bytes.size()));
        ephemeralnet::PeerId id{};
        std::copy(digest.begin(), digest.end(), id.begin());
        return id;
    }

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<std::uint32_t> distribution(0, std::numeric_limits<std::uint32_t>::max());
    ephemeralnet::PeerId id{};
    for (auto& byte : id) {
        byte = static_cast<std::uint8_t>(distribution(generator) & 0xFF);
    }
    return id;
}

ephemeralnet::Config build_config(const GlobalOptions& options) {
    ephemeralnet::Config config;
    if (options.persistent_set) {
        config.storage_persistent_enabled = options.persistent;
    }
    if (options.wipe_set) {
        config.storage_wipe_on_expiry = options.wipe;
    }
    if (options.wipe_passes_set) {
        config.storage_wipe_passes = options.wipe_passes;
    }
    if (options.storage_dir) {
        config.storage_directory = strip_quotes(*options.storage_dir);
    }
    if (options.identity_seed) {
        config.identity_seed = options.identity_seed;
    }
    if (options.default_ttl_seconds) {
        config.default_chunk_ttl = std::chrono::seconds(*options.default_ttl_seconds);
    }
    if (options.control_host) {
        config.control_host = strip_quotes(*options.control_host);
    }
    if (options.control_port) {
        config.control_port = *options.control_port;
    }
    return config;
}

std::vector<std::string> build_daemon_arguments(const GlobalOptions& options) {
    std::vector<std::string> args;
    if (options.storage_dir) {
        args.emplace_back("--storage-dir");
        args.emplace_back(strip_quotes(*options.storage_dir));
    }
    if (options.persistent_set) {
        args.emplace_back(options.persistent ? "--persistent" : "--no-persistent");
    }
    if (options.wipe_set && !options.wipe) {
        args.emplace_back("--no-wipe");
    }
    if (options.wipe_passes_set) {
        args.emplace_back("--wipe-passes");
        args.emplace_back(std::to_string(options.wipe_passes));
    }
    if (options.identity_seed) {
        args.emplace_back("--identity-seed");
        args.emplace_back(std::to_string(*options.identity_seed));
    }
    if (options.peer_id_hex) {
        args.emplace_back("--peer-id");
        args.emplace_back(strip_quotes(*options.peer_id_hex));
    }
    if (options.default_ttl_seconds) {
        args.emplace_back("--default-ttl");
        args.emplace_back(std::to_string(*options.default_ttl_seconds));
    }
    if (options.control_host) {
        args.emplace_back("--control-host");
        args.emplace_back(strip_quotes(*options.control_host));
    }
    if (options.control_port) {
        args.emplace_back("--control-port");
        args.emplace_back(std::to_string(*options.control_port));
    }
    args.emplace_back("serve");
    return args;
}

std::filesystem::path executable_path() {
#ifdef _WIN32
    std::wstring buffer(512, L'\0');
    DWORD length = 0;
    while (true) {
        length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            throw std::runtime_error("Could not resolve executable path");
        }
        if (length < buffer.size() - 1) {
            buffer.resize(length);
            break;
        }
        buffer.resize(buffer.size() * 2);
    }
    return std::filesystem::path(buffer);
#else
    return std::filesystem::canonical("/proc/self/exe");
#endif
}

bool launch_detached(const std::filesystem::path& exe, const std::vector<std::string>& args) {
#ifdef _WIN32
    auto widen = [](const std::string& input) -> std::wstring {
        if (input.empty()) {
            return std::wstring{};
        }
        int length = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (length == 0) {
            length = MultiByteToWideChar(CP_ACP, 0, input.c_str(), -1, nullptr, 0);
            if (length == 0) {
                throw std::runtime_error("Could not convert argument to UTF-16");
            }
            std::wstring result(static_cast<std::size_t>(length - 1), L'\0');
            MultiByteToWideChar(CP_ACP, 0, input.c_str(), -1, result.data(), length);
            return result;
        }
        std::wstring result(static_cast<std::size_t>(length - 1), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, result.data(), length);
        return result;
    };

    auto quote_argument = [](const std::wstring& argument) -> std::wstring {
        if (argument.empty()) {
            return L"\"\"";
        }
        bool needs_quotes = argument.find_first_of(L" \t\"") != std::wstring::npos;
        if (!needs_quotes) {
            return argument;
        }
        std::wstring quoted;
        quoted.reserve(argument.size() + 2);
        quoted.push_back(L'"');
        unsigned backslashes = 0;
        for (wchar_t ch : argument) {
            if (ch == L'\\') {
                ++backslashes;
            } else if (ch == L'"') {
                quoted.append(backslashes * 2 + 1, L'\\');
                quoted.push_back(L'"');
                backslashes = 0;
            } else {
                if (backslashes > 0) {
                    quoted.append(backslashes, L'\\');
                    backslashes = 0;
                }
                quoted.push_back(ch);
            }
        }
        if (backslashes > 0) {
            quoted.append(backslashes * 2, L'\\');
        }
        quoted.push_back(L'"');
        return quoted;
    };

    std::wstring application = exe.wstring();
    std::wstring command_line = quote_argument(application);
    for (const auto& arg : args) {
        command_line.push_back(L' ');
        command_line += quote_argument(widen(arg));
    }

    std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup_info{};
    startup_info.cb = sizeof(startup_info);
    PROCESS_INFORMATION process_info{};

    BOOL created = CreateProcessW(
        application.empty() ? nullptr : application.data(),
        mutable_command.data(),
        nullptr,
        nullptr,
        FALSE,
        DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT,
        nullptr,
        nullptr,
        &startup_info,
        &process_info);

    if (created) {
        CloseHandle(process_info.hThread);
        CloseHandle(process_info.hProcess);
    } else {
        const DWORD error = GetLastError();
        LPWSTR message_buffer = nullptr;
        const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
        if (FormatMessageW(flags,
                           nullptr,
                           error,
                           0,
                           reinterpret_cast<LPWSTR>(&message_buffer),
                           0,
                           nullptr) && message_buffer) {
            std::wcerr << message_buffer;
            LocalFree(message_buffer);
        }
    }

    return created != FALSE;
#else
    (void)exe;
    (void)args;
    return false;
#endif
}

bool wait_for_daemon(ephemeralnet::daemon::ControlClient& client, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (auto response = client.send("PING"); response && response->success) {
            return true;
        }
        std::this_thread::sleep_for(200ms);
    }
    return false;
}

bool wait_for_daemon_shutdown(ephemeralnet::daemon::ControlClient& client, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (auto response = client.send("PING"); !response || !response->success) {
            return true;
        }
        std::this_thread::sleep_for(200ms);
    }
    return false;
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

void print_list_response(const ephemeralnet::daemon::ControlResponse& response) {
    const auto count_it = response.fields.find("COUNT");
    const auto entries_it = response.fields.find("ENTRIES");
    std::vector<std::array<std::string, 4>> entries;

    if (entries_it != response.fields.end() && !entries_it->second.empty()) {
        std::istringstream lines(entries_it->second);
        std::string line;
        while (std::getline(lines, line)) {
            if (line.empty()) {
                continue;
            }
            std::vector<std::string> tokens;
            std::size_t start = 0;
            while (start <= line.size()) {
                const auto pos = line.find(',', start);
                if (pos == std::string::npos) {
                    tokens.emplace_back(line.substr(start));
                    break;
                }
                tokens.emplace_back(line.substr(start, pos - start));
                start = pos + 1;
            }
            if (tokens.size() == 4) {
                entries.push_back({tokens[0], tokens[1], tokens[2], tokens[3]});
            }
        }
    }

    std::optional<std::size_t> reported_count;
    if (count_it != response.fields.end()) {
        try {
            reported_count = static_cast<std::size_t>(std::stoull(count_it->second));
        } catch (...) {
            reported_count.reset();
        }
    }

    const std::size_t entry_count = entries.size();
    const std::size_t display_count = reported_count.has_value() && *reported_count == entry_count
                                          ? *reported_count
                                          : entry_count;

    std::cout << "Local chunks: " << display_count << std::endl;
    if (entries.empty()) {
        return;
    }
    for (const auto& entry : entries) {
        std::cout << "  ID=" << entry[0]
                  << " size=" << entry[1] << " bytes"
                  << ", state=" << entry[2]
                  << ", ttl=" << entry[3] << "s" << std::endl;
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        std::vector<std::string_view> args;
        args.reserve(static_cast<std::size_t>(argc));
        for (int i = 1; i < argc; ++i) {
            args.emplace_back(argv[i]);
        }

        GlobalOptions options{};
        std::size_t index = 0;

        auto require_value = [&](std::string_view option) -> std::string {
            if (index >= args.size()) {
                throw_cli_error("E_MISSING_VALUE",
                                std::string(option) + " requires a value",
                                "Provide an argument immediately after " + std::string(option));
            }
            return std::string(args[index++]);
        };

        while (index < args.size() && args[index].starts_with("--")) {
            const auto opt = args[index++];
            if (opt == "--help" || opt == "-h") {
                print_usage();
                return 0;
            }
            if (opt == "--yes" || opt == "-y") {
                options.assume_yes = true;
                continue;
            }
            if (opt == "--storage-dir") {
                options.storage_dir = require_value(opt);
                continue;
            }
            if (opt == "--persistent") {
                options.persistent = true;
                options.persistent_set = true;
                continue;
            }
            if (opt == "--no-persistent") {
                options.persistent = false;
                options.persistent_set = true;
                continue;
            }
            if (opt == "--no-wipe") {
                options.wipe = false;
                options.wipe_set = true;
                continue;
            }
            if (opt == "--wipe-passes") {
                const auto value = require_value(opt);
                std::uint64_t parsed{};
                if (!parse_uint64(value, parsed) || parsed == 0 || parsed > 255) {
                    throw_cli_error("E_INVALID_WIPE_PASSES",
                                    "--wipe-passes must be between 1 and 255",
                                    "Use a small positive integer, e.g. --wipe-passes 3");
                }
                options.wipe_passes = static_cast<std::uint8_t>(parsed);
                options.wipe_passes_set = true;
                continue;
            }
            if (opt == "--identity-seed") {
                const auto value = require_value(opt);
                std::uint32_t seed{};
                if (!parse_uint32(value, seed)) {
                    throw_cli_error("E_INVALID_IDENTITY_SEED",
                                    "--identity-seed must be an unsigned integer",
                                    "For example: --identity-seed 123456");
                }
                options.identity_seed = seed;
                continue;
            }
            if (opt == "--peer-id") {
                options.peer_id_hex = require_value(opt);
                continue;
            }
            if (opt == "--default-ttl") {
                const auto value = require_value(opt);
                std::uint64_t ttl{};
                if (!parse_uint64(value, ttl) || ttl == 0) {
                    throw_cli_error("E_INVALID_DEFAULT_TTL",
                                    "--default-ttl must be a positive integer",
                                    "Provide the TTL in seconds, for example --default-ttl 3600");
                }
                options.default_ttl_seconds = ttl;
                continue;
            }
            if (opt == "--control-host") {
                options.control_host = require_value(opt);
                continue;
            }
            if (opt == "--control-port") {
                const auto value = require_value(opt);
                std::uint16_t port{};
                if (!parse_uint16(value, port)) {
                    throw_cli_error("E_INVALID_CONTROL_PORT",
                                    "--control-port must be an integer between 1 and 65535",
                                    "For example: --control-port 47777");
                }
                options.control_port = port;
                continue;
            }

            throw_cli_error("E_UNKNOWN_OPTION",
                            "Unknown option: " + std::string(opt),
                            "Run 'eph --help' to view available options");
        }

        validate_global_options(options);

        if (index >= args.size()) {
            print_usage();
            return 1;
        }

        std::string command = to_lower(std::string(args[index++]));
        if (command == "help") {
            print_usage();
            return 0;
        }

        const auto config = build_config(options);

        if (command == "serve") {
            const auto peer_id = make_peer_id(options);
            ephemeralnet::Node node(peer_id, config);

            std::mutex node_mutex;
            ephemeralnet::daemon::ControlServer control_server(node, node_mutex, []() { g_run_loop.store(false); });
            control_server.start(config.control_host, config.control_port);

            std::signal(SIGINT, signal_handler);
            std::signal(SIGTERM, signal_handler);

            {
                std::scoped_lock lock(node_mutex);
                node.start_transport(0);
            }

            std::cout << "Daemon running. Control at " << config.control_host << ':' << config.control_port << std::endl;
            std::cout << "Transport port: " << node.transport_port() << std::endl;
            std::cout << "Press Ctrl+C or run 'eph stop' to exit." << std::endl;

            while (g_run_loop.load()) {
                {
                    std::scoped_lock lock(node_mutex);
                    node.tick();
                }
                std::this_thread::sleep_for(1s);
            }

            {
                std::scoped_lock lock(node_mutex);
                node.stop_transport();
            }
            control_server.stop();
            std::cout << "Daemon stopped." << std::endl;
            return 0;
        }

        ephemeralnet::daemon::ControlClient client(config.control_host, config.control_port);

        if (command == "start") {
            if (auto ping = client.send("PING"); ping && ping->success) {
                std::cout << "Daemon is already running." << std::endl;
                return 0;
            }

#ifdef _WIN32
            const auto exe = executable_path();
            const auto args_to_launch = build_daemon_arguments(options);
            if (!launch_detached(exe, args_to_launch)) {
                std::cerr << "Failed to launch the daemon in the background." << std::endl;
                return 1;
            }

            if (!wait_for_daemon(client, 5s)) {
                std::cerr << "Daemon did not respond after startup." << std::endl;
                return 1;
            }

            std::cout << "Daemon started in the background." << std::endl;
            return 0;
#else
            std::cerr << "The start command is only supported on Windows in this release." << std::endl;
            return 1;
#endif
        }

        if (command == "stop") {
            const auto response = client.send("STOP");
            if (!response) {
                throw_daemon_unreachable();
            }
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }
            const auto message_it = response->fields.find("MESSAGE");
            if (message_it != response->fields.end() && !message_it->second.empty()) {
                std::cout << message_it->second << std::endl;
            }

            if (!wait_for_daemon_shutdown(client, 5s)) {
                std::cerr << "Daemon did not shut down cleanly." << std::endl;
                return 1;
            }

            std::cout << "Daemon stopped" << std::endl;
            return 0;
        }

        if (command == "status") {
            const auto response = client.send("STATUS");
            if (!response) {
                throw_daemon_unreachable();
            }
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }
            const auto peers = response->fields.contains("PEERS") ? response->fields.at("PEERS") : "0";
            const auto chunks = response->fields.contains("CHUNKS") ? response->fields.at("CHUNKS") : "0";
            const auto port = response->fields.contains("TRANSPORT_PORT") ? response->fields.at("TRANSPORT_PORT") : "0";
            std::cout << "Daemon active" << std::endl;
            std::cout << "  Connected peers:  " << peers << std::endl;
            std::cout << "  Local chunks:     " << chunks << std::endl;
            std::cout << "  Transport port:   " << port << std::endl;
            return 0;
        }

        if (command == "list") {
            const auto response = client.send("LIST");
            if (!response) {
                throw_daemon_unreachable();
            }
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }
            print_list_response(*response);
            return 0;
        }

        if (command == "store") {
            if (index >= args.size()) {
                throw_cli_error("E_STORE_MISSING_PATH",
                                "store expects the path to a file",
                                "Example: eph store ./file.txt --ttl 3600");
            }
            const auto input_path = std::filesystem::absolute(std::filesystem::path(args[index++]));
            if (!std::filesystem::exists(input_path)) {
                throw_cli_error("E_STORE_FILE_NOT_FOUND",
                                "File not found: " + input_path.string(),
                                "Check the path or provide an absolute path");
            }
            if (!std::filesystem::is_regular_file(input_path)) {
                throw_cli_error("E_STORE_INVALID_FILE",
                                "store expects a regular file",
                                "Provide a path to a readable file, not a directory or device");
            }

            std::optional<std::uint64_t> ttl_override;
            while (index < args.size()) {
                const auto opt = args[index++];
                if (opt == "--ttl") {
                    if (index >= args.size()) {
                        throw_cli_error("E_STORE_MISSING_TTL",
                                        "--ttl requires a value",
                                        "Example: --ttl 3600 for one hour");
                    }
                    std::uint64_t ttl{};
                    if (!parse_uint64(args[index++], ttl)) {
                        throw_cli_error("E_STORE_INVALID_TTL",
                                        "--ttl must be a positive integer",
                                        "Use a positive number of seconds, e.g. 3600");
                    }
                    ttl_override = ttl;
                    continue;
                }
                throw_cli_error("E_STORE_UNKNOWN_OPTION",
                                "Unknown option for store: " + std::string(opt),
                                "Run 'eph store --help' to see valid modifiers");
            }

            const auto file_size = std::filesystem::file_size(input_path);
            if (!confirm_action("Store " + input_path.filename().string() + " (" + std::to_string(file_size) +
                                    " bytes). Continue?",
                                true,
                                options.assume_yes)) {
                std::cout << "Operation cancelled by the user." << std::endl;
                return 0;
            }

            ephemeralnet::daemon::ControlFields fields{{"PATH", input_path.string()}};
            if (ttl_override) {
                fields["TTL"] = std::to_string(*ttl_override);
            }

            const auto response = client.send("STORE", fields);
            if (!response) {
                throw_daemon_unreachable();
            }
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }

            const auto manifest = response->fields.contains("MANIFEST") ? response->fields.at("MANIFEST") : "";
            const auto size = response->fields.contains("SIZE") ? response->fields.at("SIZE") : "0";
            const auto ttl = response->fields.contains("TTL") ? response->fields.at("TTL") : "0";
            std::cout << "File stored" << std::endl;
            std::cout << "  Size: " << size << " bytes" << std::endl;
            std::cout << "  Remaining TTL: " << ttl << " seconds" << std::endl;
            std::cout << "  Manifest: " << manifest << std::endl;
            return 0;
        }

        if (command == "fetch") {
            if (index >= args.size()) {
                throw_cli_error("E_FETCH_MISSING_MANIFEST",
                                "fetch expects an eph:// manifest",
                                "Example: eph fetch eph://... --out ./file.bin");
            }
            const std::string manifest_uri(args[index++]);
            if (manifest_uri.rfind("eph://", 0) != 0) {
                throw_cli_error("E_FETCH_INVALID_MANIFEST",
                                "fetch requires a manifest prefixed with eph://",
                                "Make sure you paste the full URI generated by 'store'");
            }

            std::optional<std::filesystem::path> output_path;
            while (index < args.size()) {
                const auto opt = args[index++];
                if (opt == "--out") {
                    if (index >= args.size()) {
                        throw_cli_error("E_FETCH_MISSING_OUT",
                                        "--out requires a path",
                                        "Example: --out ./download.bin");
                    }
                    output_path = std::filesystem::absolute(std::filesystem::path(args[index++]));
                    continue;
                }
                throw_cli_error("E_FETCH_UNKNOWN_OPTION",
                                "Unknown option for fetch: " + std::string(opt),
                                "Run 'eph --help' to see permitted modifiers");
            }

            if (!output_path) {
                throw_cli_error("E_FETCH_OUT_REQUIRED",
                                "fetch requires --out to specify the destination file",
                                "Use --out ./file.bin");
            }

            if (std::filesystem::exists(*output_path) && std::filesystem::is_directory(*output_path)) {
                throw_cli_error("E_FETCH_OUT_IS_DIRECTORY",
                                "--out must point to a file, not a directory",
                                "Choose a filename such as --out ./output.bin");
            }

            if (const auto parent = output_path->parent_path(); !parent.empty() && !std::filesystem::exists(parent)) {
                throw_cli_error("E_FETCH_OUT_PARENT_MISSING",
                                "Destination directory does not exist",
                                "Create " + parent.string() + " or choose an existing path");
            }

            if (std::filesystem::exists(*output_path) &&
                !confirm_action("File " + output_path->string() + " already exists. Overwrite?",
                                false,
                                options.assume_yes)) {
                std::cout << "Operation cancelled by the user." << std::endl;
                return 0;
            }

            ephemeralnet::daemon::ControlFields fields{{"MANIFEST", manifest_uri},
                                                        {"OUT", output_path->string()}};

            const auto response = client.send("FETCH", fields);
            if (!response) {
                throw_daemon_unreachable();
            }
            if (!response->success) {
                print_daemon_failure(*response);
                return 1;
            }

            const auto output = response->fields.contains("OUTPUT") ? response->fields.at("OUTPUT") : output_path->string();
            const auto size = response->fields.contains("SIZE") ? response->fields.at("SIZE") : "0";
            std::cout << "File retrieved to " << output << " (" << size << " bytes)" << std::endl;
            return 0;
        }

        throw_cli_error("E_UNKNOWN_COMMAND",
                        "Unknown command: " + command,
                        "Run 'eph --help' to see the list of available commands");

    } catch (const CliException& ex) {
        print_cli_error(ex);
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "Error [E_UNEXPECTED]: " << ex.what() << std::endl;
        return 1;
    }
}
