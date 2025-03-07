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
};

std::atomic_bool g_run_loop{true};

void signal_handler(int) {
    g_run_loop.store(false);
}

void print_usage() {
    std::cout << "EphemeralNet CLI" << std::endl;
    std::cout << "Uso: eph [opciones] <comando> [args]\n\n";
    std::cout << "Opciones globales:\n"
              << "  --storage-dir <ruta>       Directorio para chunks persistentes (por defecto ./storage)\n"
              << "  --persistent              Activa almacenamiento persistente\n"
              << "  --no-persistent           Desactiva almacenamiento persistente\n"
              << "  --no-wipe                 Desactiva el borrado seguro al expirar\n"
              << "  --wipe-passes <n>         Número de pasadas del borrado seguro (>=1)\n"
              << "  --identity-seed <n>       Semilla determinista para la identidad del nodo\n"
              << "  --peer-id <hex>           Identificador de nodo (64 caracteres hex)\n"
              << "  --default-ttl <seg>       TTL por defecto para nuevos chunks\n"
              << "  --control-host <host>     Host del socket de control (por defecto 127.0.0.1)\n"
              << "  --control-port <puerto>   Puerto del socket de control (por defecto 47777)\n"
              << "  --help                    Muestra esta ayuda\n\n";
    std::cout << "Comandos:\n"
              << "  start                     Lanza el daemon en segundo plano\n"
              << "  stop                      Solicita al daemon que se detenga\n"
              << "  status                    Consulta el estado del daemon\n"
              << "  store <archivo> [--ttl <seg>]\n"
              << "                           Pide al daemon almacenar un archivo y devuelve eph://\n"
              << "  fetch <eph://...> --out <archivo>\n"
              << "                           Recupera un archivo usando un manifiesto eph://\n"
              << "  list                      Lista chunks almacenados localmente\n"
              << "  serve                     Inicia el daemon en primer plano (Ctrl+C para salir)\n"
              << "  help                      Alias de --help\n";
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

ephemeralnet::PeerId make_peer_id(const GlobalOptions& options) {
    if (options.peer_id_hex) {
        if (auto parsed = parse_hex_array<ephemeralnet::PeerId>(*options.peer_id_hex)) {
            return *parsed;
        }
        throw std::runtime_error("Peer ID inválido: se espera cadena hex de 64 caracteres");
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
            throw std::runtime_error("No se pudo resolver la ruta del ejecutable");
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
                throw std::runtime_error("No se pudo convertir argumento a UTF-16");
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

    std::cout << "Chunks locales: " << display_count << std::endl;
    if (entries.empty()) {
        return;
    }
    for (const auto& entry : entries) {
        std::cout << "  ID=" << entry[0]
                  << " tamaño=" << entry[1] << " bytes"
                  << ", estado=" << entry[2]
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
                throw std::runtime_error(std::string(option) + " requiere un valor");
            }
            return std::string(args[index++]);
        };

        while (index < args.size() && args[index].starts_with("--")) {
            const auto opt = args[index++];
            if (opt == "--help" || opt == "-h") {
                print_usage();
                return 0;
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
                    throw std::runtime_error("--wipe-passes debe estar entre 1 y 255");
                }
                options.wipe_passes = static_cast<std::uint8_t>(parsed);
                options.wipe_passes_set = true;
                continue;
            }
            if (opt == "--identity-seed") {
                const auto value = require_value(opt);
                std::uint32_t seed{};
                if (!parse_uint32(value, seed)) {
                    throw std::runtime_error("--identity-seed debe ser un entero sin signo");
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
                if (!parse_uint64(value, ttl)) {
                    throw std::runtime_error("--default-ttl debe ser un entero positivo");
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
                    throw std::runtime_error("--control-port debe ser un entero entre 1 y 65535");
                }
                options.control_port = port;
                continue;
            }

            throw std::runtime_error("Opción desconocida: " + std::string(opt));
        }

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

            std::cout << "Daemon en ejecución. Control en " << config.control_host << ':' << config.control_port << std::endl;
            std::cout << "Puerto de transporte: " << node.transport_port() << std::endl;
            std::cout << "Pulse Ctrl+C o ejecute 'eph stop' para detener." << std::endl;

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
            std::cout << "Daemon detenido." << std::endl;
            return 0;
        }

        ephemeralnet::daemon::ControlClient client(config.control_host, config.control_port);

        if (command == "start") {
            if (auto ping = client.send("PING"); ping && ping->success) {
                std::cout << "El daemon ya está en ejecución." << std::endl;
                return 0;
            }

#ifdef _WIN32
            const auto exe = executable_path();
            const auto args_to_launch = build_daemon_arguments(options);
            if (!launch_detached(exe, args_to_launch)) {
                std::cerr << "No se pudo lanzar el daemon en segundo plano." << std::endl;
                return 1;
            }

            if (!wait_for_daemon(client, 5s)) {
                std::cerr << "El daemon no respondió tras el arranque." << std::endl;
                return 1;
            }

            std::cout << "Daemon iniciado en segundo plano." << std::endl;
            return 0;
#else
            std::cerr << "El comando start solo está soportado en Windows en esta versión." << std::endl;
            return 1;
#endif
        }

        if (command == "stop") {
            const auto response = client.send("STOP");
            if (!response) {
                std::cerr << "No se pudo contactar con el daemon." << std::endl;
                return 1;
            }
            if (!response->success) {
                const auto message = response->fields.contains("MESSAGE") ? response->fields.at("MESSAGE") : "Fallo al detener";
                std::cerr << message << std::endl;
                return 1;
            }
            const auto message_it = response->fields.find("MESSAGE");
            if (message_it != response->fields.end() && !message_it->second.empty()) {
                std::cout << message_it->second << std::endl;
            }

            if (!wait_for_daemon_shutdown(client, 5s)) {
                std::cerr << "El daemon no se detuvo correctamente." << std::endl;
                return 1;
            }

            std::cout << "Daemon detenido" << std::endl;
            return 0;
        }

        if (command == "status") {
            const auto response = client.send("STATUS");
            if (!response) {
                std::cerr << "No se pudo contactar con el daemon." << std::endl;
                return 1;
            }
            if (!response->success) {
                const auto message = response->fields.contains("MESSAGE") ? response->fields.at("MESSAGE") : "Estado no disponible";
                std::cerr << message << std::endl;
                return 1;
            }
            const auto peers = response->fields.contains("PEERS") ? response->fields.at("PEERS") : "0";
            const auto chunks = response->fields.contains("CHUNKS") ? response->fields.at("CHUNKS") : "0";
            const auto port = response->fields.contains("TRANSPORT_PORT") ? response->fields.at("TRANSPORT_PORT") : "0";
            std::cout << "Daemon activo" << std::endl;
            std::cout << "  Peers conectados: " << peers << std::endl;
            std::cout << "  Chunks locales:   " << chunks << std::endl;
            std::cout << "  Puerto transporte: " << port << std::endl;
            return 0;
        }

        if (command == "list") {
            const auto response = client.send("LIST");
            if (!response) {
                std::cerr << "No se pudo contactar con el daemon." << std::endl;
                return 1;
            }
            if (!response->success) {
                const auto message = response->fields.contains("MESSAGE") ? response->fields.at("MESSAGE") : "No se pudo obtener el listado";
                std::cerr << message << std::endl;
                return 1;
            }
            print_list_response(*response);
            return 0;
        }

        if (command == "store") {
            if (index >= args.size()) {
                throw std::runtime_error("store requiere la ruta de un archivo");
            }
            const auto input_path = std::filesystem::absolute(std::filesystem::path(args[index++]));
            if (!std::filesystem::exists(input_path)) {
                throw std::runtime_error("El archivo no existe: " + input_path.string());
            }

            std::optional<std::uint64_t> ttl_override;
            while (index < args.size()) {
                const auto opt = args[index++];
                if (opt == "--ttl") {
                    if (index >= args.size()) {
                        throw std::runtime_error("--ttl requiere un valor");
                    }
                    std::uint64_t ttl{};
                    if (!parse_uint64(args[index++], ttl)) {
                        throw std::runtime_error("--ttl debe ser un entero positivo");
                    }
                    ttl_override = ttl;
                    continue;
                }
                throw std::runtime_error("Opción desconocida para store: " + std::string(opt));
            }

            ephemeralnet::daemon::ControlFields fields{{"PATH", input_path.string()}};
            if (ttl_override) {
                fields["TTL"] = std::to_string(*ttl_override);
            }

            const auto response = client.send("STORE", fields);
            if (!response) {
                std::cerr << "No se pudo contactar con el daemon." << std::endl;
                return 1;
            }
            if (!response->success) {
                const auto message = response->fields.contains("MESSAGE") ? response->fields.at("MESSAGE") : "Fallo al almacenar";
                std::cerr << message << std::endl;
                return 1;
            }

            const auto manifest = response->fields.contains("MANIFEST") ? response->fields.at("MANIFEST") : "";
            const auto size = response->fields.contains("SIZE") ? response->fields.at("SIZE") : "0";
            const auto ttl = response->fields.contains("TTL") ? response->fields.at("TTL") : "0";
            std::cout << "Archivo almacenado" << std::endl;
            std::cout << "  Tamaño: " << size << " bytes" << std::endl;
            std::cout << "  TTL restante: " << ttl << " segundos" << std::endl;
            std::cout << "  Manifiesto: " << manifest << std::endl;
            return 0;
        }

        if (command == "fetch") {
            if (index >= args.size()) {
                throw std::runtime_error("fetch requiere un manifiesto eph://");
            }
            const std::string manifest_uri(args[index++]);
            if (manifest_uri.rfind("eph://", 0) != 0) {
                throw std::runtime_error("fetch requiere un manifiesto con prefijo eph://");
            }

            std::optional<std::filesystem::path> output_path;
            while (index < args.size()) {
                const auto opt = args[index++];
                if (opt == "--out") {
                    if (index >= args.size()) {
                        throw std::runtime_error("--out requiere una ruta");
                    }
                    output_path = std::filesystem::absolute(std::filesystem::path(args[index++]));
                    continue;
                }
                throw std::runtime_error("Opción desconocida para fetch: " + std::string(opt));
            }

            if (!output_path) {
                throw std::runtime_error("fetch requiere --out para indicar el archivo destino");
            }

            ephemeralnet::daemon::ControlFields fields{{"MANIFEST", manifest_uri},
                                                        {"OUT", output_path->string()}};

            const auto response = client.send("FETCH", fields);
            if (!response) {
                std::cerr << "No se pudo contactar con el daemon." << std::endl;
                return 1;
            }
            if (!response->success) {
                const auto message = response->fields.contains("MESSAGE") ? response->fields.at("MESSAGE") : "Fallo al recuperar";
                std::cerr << message << std::endl;
                return 1;
            }

            const auto output = response->fields.contains("OUTPUT") ? response->fields.at("OUTPUT") : output_path->string();
            const auto size = response->fields.contains("SIZE") ? response->fields.at("SIZE") : "0";
            std::cout << "Archivo recuperado en " << output << " (" << size << " bytes)" << std::endl;
            return 0;
        }

        std::cerr << "Comando desconocido: " << command << std::endl;
        print_usage();
        return 1;

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
