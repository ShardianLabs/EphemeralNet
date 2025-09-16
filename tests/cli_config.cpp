#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
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
    const auto output_path = std::filesystem::temp_directory_path() / "ephemeralnet_cli_output.txt";
    const std::string command =
        "cmd /c \"\"" + executable + "\" " + arguments + " > \"" + output_path.string() + "\" 2>&1\"";
    const int status = std::system(command.c_str());

    std::ifstream stream(output_path, std::ios::binary);
    std::string output((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    stream.close();
    std::filesystem::remove(output_path);

    return CommandResult{status, output};
#else
    const std::string command = "\"" + executable + "\" " + arguments + " 2>&1";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Failed to open a pipe to the CLI");
    }

    std::string output;
    std::array<char, 256> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        output.append(buffer.data());
    }

    const int status = pclose(pipe);
    int exit_code = -1;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    }

    return CommandResult{exit_code, output};
#endif
}

bool expect_contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

std::filesystem::path write_temp_file(const std::string& name, const std::string& contents) {
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream file(path, std::ios::binary);
    file << contents;
    file.close();
    return path;
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
        const auto json_path = write_temp_file("ephemeralnet_config_test.json",
                                               R"JSON({
  "profiles": {
    "default": {
      "storage": {
        "directory": ""
      }
    }
  }
})JSON");
        const auto json_result = run_cli(executable, "--config \"" + json_path.string() + "\" status");
    if (json_result.exit_code == 0 || !expect_contains(json_result.output, "--storage-dir cannot be empty")) {
      std::cerr << "Failure on JSON config validation. exit=" << json_result.exit_code << "\n"
            << json_result.output << std::endl;
      std::filesystem::remove(json_path);
      return 1;
    }
    std::filesystem::remove(json_path);

        const auto yaml_path = write_temp_file("ephemeralnet_config_test.yaml",
                                               R"YAML(profiles:
  default:
    control:
      host: 127.0.0.1
    node:
      default_ttl_seconds: 7200
  staging:
    extends: default
    storage:
      directory: ./storage/staging
environments:
  ci:
    profile: staging
    node:
      default_ttl_seconds: 0
)YAML");

        const auto env_result = run_cli(executable,
                                        "--config \"" + yaml_path.string() + "\" --env ci status");
        if (env_result.exit_code == 0 || !expect_contains(env_result.output, "node.default_ttl_seconds must be positive")) {
            std::cerr << "Failure on environment override validation. exit=" << env_result.exit_code << "\n"
                      << env_result.output << std::endl;
            std::filesystem::remove(yaml_path);
            return 1;
        }

        const auto missing_env_result = run_cli(executable,
                                                "--config \"" + yaml_path.string() + "\" --env prod status");
        if (missing_env_result.exit_code == 0 || !expect_contains(missing_env_result.output, "Environment not found")) {
            std::cerr << "Failure on missing environment detection. exit=" << missing_env_result.exit_code << "\n"
                      << missing_env_result.output << std::endl;
            std::filesystem::remove(yaml_path);
            return 1;
        }

        std::filesystem::remove(yaml_path);

        const auto advertise_missing_host = run_cli(executable,
                              "--advertise-control :4000 status");
        if (advertise_missing_host.exit_code == 0 ||
          !expect_contains(advertise_missing_host.output, "E_INVALID_ADVERTISE_CONTROL")) {
          std::cerr << "Failure on advertise-control host validation. exit="
                << advertise_missing_host.exit_code << "\n"
                << advertise_missing_host.output << std::endl;
          return 1;
        }

        const auto advertise_ipv6 = run_cli(executable,
                          "--advertise-control 2001:db8::1:4000 status");
        if (advertise_ipv6.exit_code == 0 ||
          !expect_contains(advertise_ipv6.output, "IPv6 advertise endpoints must be wrapped")) {
          std::cerr << "Failure on advertise-control IPv6 validation. exit="
                << advertise_ipv6.exit_code << "\n"
                << advertise_ipv6.output << std::endl;
          return 1;
        }

        const auto bootstrap_conflict = run_cli(executable,
            "fetch eph://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --bootstrap-only --no-bootstrap --out ./cli_fetch_conflict.bin");
        if (bootstrap_conflict.exit_code == 0 ||
            !expect_contains(bootstrap_conflict.output, "--no-bootstrap cannot be combined")) {
            std::cerr << "Failure on bootstrap/no-bootstrap conflict detection. exit="
                      << bootstrap_conflict.exit_code << "\n"
                      << bootstrap_conflict.output << std::endl;
            return 1;
        }

    } catch (const std::exception& ex) {
        std::cerr << "Exception during CLI config tests: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
