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
        throw std::runtime_error("No se pudo abrir un pipe hacia la CLI");
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
        std::cerr << "EPH_CLI_EXECUTABLE no está definido" << std::endl;
        return 1;
    }

    const std::string executable = std::filesystem::path(executable_env).string();

    try {
        const auto help = run_cli(executable, "--help");
        if (help.exit_code != 0 || !expect_contains(help.output, "Uso: eph")) {
            std::cerr << "Fallo en --help. Código=" << help.exit_code << "\n" << help.output << std::endl;
            return 1;
        }

        const auto status = run_cli(executable, "status");
        if (status.exit_code == 0 || !expect_contains(status.output, "No se pudo contactar con el daemon")) {
            std::cerr << "Fallo en status sin daemon. Código=" << status.exit_code << "\n" << status.output << std::endl;
            return 1;
        }

        const auto store = run_cli(executable, "store");
        if (store.exit_code == 0 || !expect_contains(store.output, "store requiere la ruta de un archivo")) {
            std::cerr << "Fallo en store sin argumentos. Código=" << store.exit_code << "\n" << store.output << std::endl;
            return 1;
        }

        const auto fetch = run_cli(executable, "fetch eph://deadbeef");
        if (fetch.exit_code == 0 || !expect_contains(fetch.output, "fetch requiere --out")) {
            std::cerr << "Fallo en fetch sin --out. Código=" << fetch.exit_code << "\n" << fetch.output << std::endl;
            return 1;
        }

    } catch (const std::exception& ex) {
        std::cerr << "Excepción durante las pruebas de la CLI: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
