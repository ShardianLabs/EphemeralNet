# Contributing to EphemeralNet

Thanks for your interest in improving EphemeralNet! We rely on community contributions to keep the daemon, CLI, and upcoming `libephemeralnet` integration healthy. This document outlines the practical steps for proposing changes.

## Code of Conduct

Participation in this project is governed by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Please read it before interacting in GitHub issues, pull requests, or discussions.

## Getting Started

1. **Fork** https://github.com/ShardianLabs/EphemeralNet and create a feature branch from `master`.
2. Make sure you have the required toolchain:
   - CMake ≥ 3.20
   - A C++20 compiler (MSVC 19.3x, GCC 11+, or Clang 13+)
   - Ninja (default generator in CI) or another supported build backend
   - Platform dependencies (see below)
3. Configure and build:

   ```powershell
   cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
   cmake --build build --parallel
   ```

4. Run the full test suite:

   ```powershell
   ctest --test-dir build --output-on-failure
   ```

5. Make sure `clang-format` or your editor preserves the existing style conventions (LLVM brace style, 4-space indents in C++, 2 spaces in YAML). Avoid introducing trailing whitespace.

### Platform-specific dependencies

- **Windows (MSVC)**: install Ninja via Chocolatey (`choco install ninja`) and build inside a Developer Command Prompt or `ilammy/msvc-dev-cmd` environment.
- **Linux**: `sudo apt-get install ninja-build cmake g++ pkg-config libcurl4-openssl-dev`.
- **macOS**: `brew install ninja cmake curl`.

These commands mirror the configuration used in `.github/workflows/ci.yml`.

## Writing Documentation

Update documentation whenever behavior changes. User-facing docs live under `docs/`, while the main `README.md` summarizes installation, usage, and architecture. If you add new CLI flags, protocol flows, or API surface, document them in the appropriate guide and mention the changes in the pull request description.

## Testing Expectations

Every code change must be covered by deterministic tests when possible. Add or update `tests/*.cpp` entries and ensure they are wired into CMake. For larger features, include integration tests (e.g., multi-node harness) or fuzz tests when applicable.

If the change requires new data fixtures or test assets, keep them small and document their origin.

## Pull Request Checklist

Before opening a PR, verify that:

- `cmake --build build --parallel` succeeds for your target platform(s)
- `ctest --test-dir build --output-on-failure` passes locally
- Documentation and changelog entries (if any) are updated
- Code adheres to the [Code of Conduct](CODE_OF_CONDUCT.md)

## Reporting Bugs or Feature Requests

Please use GitHub issues:

- **Bug report**: include repro steps, expected vs. actual behavior, environment, and logs (see the issue template for the required fields).
- **Feature request**: describe the motivation, proposed design, and any rollout considerations.

Security-related reports should follow the [Security Policy](SECURITY.md).

## License

By contributing, you agree that your work will be licensed under the MIT License that governs this repository.
