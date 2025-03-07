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

#include <windows.h>
#if defined(_WIN32)
#include <windows.h>
#endif

#if !defined(_WIN32)
int main() {
    std::cout << "CLI control flow test omitido (solo disponible en Windows)." << std::endl;
    return 0;
}
#else

struct CommandResult {
    int exit_code;
    std::string output;
};

CommandResult run_cli(const std::string& executable, const std::string& arguments) {
    const std::string command = "cmd /C \"\"" + executable + "\" " + arguments + " 2>&1\"";
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("No se pudo abrir un pipe hacia la CLI");
    }

    std::string output;
    std::array<char, 256> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        output.append(buffer.data());
    }

    const int status = _pclose(pipe);
    return CommandResult{status, output};
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
        const bool up = status.exit_code == 0 && expect_contains(status.output, "Daemon activo");
        if (expect_up == up) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    return false;
}

int main() {
    const char* executable_env = std::getenv("EPH_CLI_EXECUTABLE");
    if (!executable_env) {
        std::cerr << "EPH_CLI_EXECUTABLE no está definido" << std::endl;
        return 1;
    }

    const std::filesystem::path executable_path(executable_env);
    const auto temp_root = std::filesystem::temp_directory_path();
    const auto test_dir = temp_root / ("eph-cli-" + std::to_string(::GetTickCount64()));
    std::filesystem::create_directories(test_dir);

    const auto cleanup = [&]() {
        std::error_code ec;
        std::filesystem::remove_all(test_dir, ec);
    };

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> port_dist(40000, 50000);
    const int control_port = port_dist(gen);

    const std::string base_options = std::string("--storage-dir ") + quote(test_dir) +
                                     " --control-host 127.0.0.1 --control-port " + std::to_string(control_port);

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
        if (start_res.exit_code != 0 || !expect_contains(start_res.output, "Daemon iniciado")) {
            std::cerr << "Fallo al iniciar daemon\n" << start_res.output << "Comando: " << start_command << std::endl;
            cleanup();
            return 1;
        }
        daemon_started = true;

        if (!wait_for_status(executable_path.string(), base_options, std::chrono::seconds(10), true)) {
            std::cerr << "El daemon no respondió en el tiempo esperado" << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        const auto list_initial = run_cli(executable_path.string(), base_options + " list");
        if (list_initial.exit_code != 0 || !expect_contains(list_initial.output, "Chunks locales: 0")) {
            std::cerr << "Listado inicial inesperado\n" << list_initial.output << std::endl;
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
        if (store_res.exit_code != 0 || !expect_contains(store_res.output, "Archivo almacenado")) {
            std::cerr << "Fallo al almacenar\n" << store_res.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        const std::string manifest_prefix = "Manifiesto: ";
        const auto manifest_pos = store_res.output.find(manifest_prefix);
        if (manifest_pos == std::string::npos) {
            std::cerr << "No se encontró el manifiesto en la salida\n" << store_res.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }
        const auto manifest_end = store_res.output.find('\n', manifest_pos);
        const std::string manifest = store_res.output.substr(
            manifest_pos + manifest_prefix.size(),
            manifest_end == std::string::npos ? std::string::npos : manifest_end - manifest_pos - manifest_prefix.size());

        const auto list_after_store = run_cli(executable_path.string(), base_options + " list");
        if (list_after_store.exit_code != 0 || !expect_contains(list_after_store.output, "Chunks locales: 1")) {
            std::cerr << "Listado tras almacenar inesperado\n" << list_after_store.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        const auto output_file = test_dir / "recovery.bin";
        const auto fetch_res = run_cli(executable_path.string(),
                                       base_options + " fetch " + quote(manifest) + " --out " + quote(output_file));
        if (fetch_res.exit_code != 0 || !expect_contains(fetch_res.output, "Archivo recuperado")) {
            std::cerr << "Fallo al recuperar\n" << fetch_res.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        std::ifstream recovered(output_file, std::ios::binary);
        std::string recovered_data(
            (std::istreambuf_iterator<char>(recovered)),
            std::istreambuf_iterator<char>());
    if (recovered_data != payload) {
            std::cerr << "Contenido recuperado diferente" << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }

        const auto stop_res = run_cli(executable_path.string(), base_options + " stop");
        if (stop_res.exit_code != 0 || !expect_contains(stop_res.output, "Daemon detenido")) {
            std::cerr << "Fallo al detener daemon\n" << stop_res.output << std::endl;
            ensure_stop();
            cleanup();
            return 1;
        }
        daemon_started = false;

        if (!wait_for_status(executable_path.string(), base_options, std::chrono::seconds(5), false)) {
            std::cerr << "El daemon no se detuvo correctamente" << std::endl;
            cleanup();
            return 1;
        }

        cleanup();
        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "Excepción durante la prueba de flujo CLI: " << ex.what() << std::endl;
        ensure_stop();
        cleanup();
        return 1;
    }
}

#endif
