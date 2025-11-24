#include "ephemeralnet/core/UpdateCheck.hpp"

#include <algorithm>
#include <charconv>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <winhttp.h>
#else
#include <curl/curl.h>
#endif

namespace {

bool read_file_url(std::string_view url, std::string& output, std::string& error) {
    std::string path(url.substr(std::string_view{"file://"}.size()));
#ifdef _WIN32
    for (auto& ch : path) {
        if (ch == '/') {
            ch = '\\';
        }
    }
    if (path.size() >= 3 && path[0] == '\\' && path[2] == ':') {
        path.erase(path.begin());
    }
#endif
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        error = "Unable to read file URL: " + path;
        return false;
    }
    output.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    return true;
}

#ifdef _WIN32

std::wstring utf8_to_wide(std::string_view text) {
    if (text.empty()) {
        return std::wstring();
    }
    const int required = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (required <= 0) {
        throw std::runtime_error("Failed to convert URL to UTF-16");
    }
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), required);
    return result;
}

std::string windows_error_message(const char* context) {
    const DWORD code = GetLastError();
    LPWSTR buffer = nullptr;
    const DWORD size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                      nullptr,
                                      code,
                                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                      reinterpret_cast<LPWSTR>(&buffer),
                                      0,
                                      nullptr);
    std::string message = context;
    message.append(" (WinHTTP error ");
    message.append(std::to_string(code));
    message.append(")");
    if (size && buffer) {
        std::wstring_view wide(buffer, size);
        std::string narrow;
        narrow.reserve(wide.size());
        for (wchar_t ch : wide) {
            if (ch == L'\r' || ch == L'\n') {
                continue;
            }
            if (ch <= 0x7F) {
                narrow.push_back(static_cast<char>(ch));
            }
        }
        if (!narrow.empty()) {
            message.append(": ");
            message.append(narrow);
        }
    }
    if (buffer) {
        LocalFree(buffer);
    }
    return message;
}

bool download_http_winhttp(std::string_view url, std::string& output, std::string& error) {
    const std::wstring wide_url = utf8_to_wide(url);
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wide_url.c_str(), static_cast<DWORD>(wide_url.size()), 0, &components)) {
        error = windows_error_message("Unable to parse update URL");
        return false;
    }

    std::wstring host(components.lpszHostName, components.dwHostNameLength);
    std::wstring path;
    if (components.dwUrlPathLength > 0 && components.lpszUrlPath) {
        path.assign(components.lpszUrlPath, components.dwUrlPathLength);
    }
    if (components.dwExtraInfoLength > 0 && components.lpszExtraInfo) {
        path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }
    if (path.empty()) {
        path = L"/";
    }

    const INTERNET_SCHEME scheme = static_cast<INTERNET_SCHEME>(components.nScheme);
    const bool use_tls = scheme == INTERNET_SCHEME_HTTPS;

    HINTERNET session = WinHttpOpen(L"EphemeralNetUpdateCheck/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        error = windows_error_message("WinHttpOpen failed");
        return false;
    }
    WinHttpSetTimeouts(session, 5000, 5000, 10'000, 10'000);

    HINTERNET connect = WinHttpConnect(session, host.c_str(), components.nPort, 0);
    if (!connect) {
        error = windows_error_message("WinHttpConnect failed");
        WinHttpCloseHandle(session);
        return false;
    }

    const DWORD flags = use_tls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        error = windows_error_message("WinHttpOpenRequest failed");
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        error = windows_error_message("WinHttpSendRequest failed");
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }
    if (!WinHttpReceiveResponse(request, nullptr)) {
        error = windows_error_message("WinHttpReceiveResponse failed");
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        error = windows_error_message("WinHttpQueryHeaders failed");
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }
    if (status >= 400) {
        error = "HTTP status " + std::to_string(status);
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    output.clear();
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(request, &available)) {
        if (available == 0) {
            break;
        }
        std::string buffer;
        buffer.resize(available);
        DWORD downloaded = 0;
        if (!WinHttpReadData(request, buffer.data(), available, &downloaded)) {
            error = windows_error_message("WinHttpReadData failed");
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return false;
        }
        output.append(buffer.data(), downloaded);
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return true;
}

#else  // !_WIN32

size_t curl_write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* buffer = static_cast<std::string*>(userdata);
    buffer->append(ptr, size * nmemb);
    return size * nmemb;
}

bool download_http_curl(std::string_view url, std::string& output, std::string& error) {
    static bool curl_ready = [] {
        return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
    }();
    if (!curl_ready) {
        error = "Unable to initialize libcurl";
        return false;
    }
    CURL* curl = curl_easy_init();
    if (!curl) {
        error = "Unable to allocate curl handle";
        return false;
    }
    const std::string url_copy(url);
    output.clear();
    curl_easy_setopt(curl, CURLOPT_URL, url_copy.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "EphemeralNetUpdateCheck/1.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output);
    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        error = curl_easy_strerror(rc);
        curl_easy_cleanup(curl);
        return false;
    }
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    if (status >= 400) {
        error = "HTTP status " + std::to_string(status);
        return false;
    }
    return true;
}

#endif  // _WIN32
enum class JsonType { Null, Boolean, Number, String, Object, Array };

struct JsonValue {
    JsonType type{JsonType::Null};
    bool bool_value{false};
    double number_value{0.0};
    std::string string_value;
    std::vector<JsonValue> array_value;
    std::vector<std::pair<std::string, JsonValue>> object_value;

    bool is_object() const { return type == JsonType::Object; }
    bool is_string() const { return type == JsonType::String; }

    const JsonValue* find(std::string_view key) const {
        if (!is_object()) {
            return nullptr;
        }
        for (const auto& [k, value] : object_value) {
            if (k == key) {
                return &value;
            }
        }
        return nullptr;
    }
};

class JsonParser {
public:
    explicit JsonParser(std::string_view input) : input_(input) {}

    JsonValue parse() {
        skip_whitespace();
        JsonValue value = parse_value();
        skip_whitespace();
        if (!eof()) {
            throw std::runtime_error("Unexpected trailing data after JSON document");
        }
        return value;
    }

private:
    JsonValue parse_value() {
        if (eof()) {
            throw std::runtime_error("Unexpected end of JSON input");
        }
        const char ch = peek();
        if (ch == '"') {
            JsonValue value;
            value.type = JsonType::String;
            value.string_value = parse_string();
            return value;
        }
        if (ch == '{') {
            return parse_object();
        }
        if (ch == '[') {
            return parse_array();
        }
        if (ch == 't' || ch == 'f') {
            return parse_boolean();
        }
        if (ch == 'n') {
            return parse_null();
        }
        if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch)) != 0) {
            return parse_number();
        }
        throw std::runtime_error("Invalid JSON token start");
    }

    JsonValue parse_object() {
        JsonValue value;
        value.type = JsonType::Object;
        expect('{');
        skip_whitespace();
        if (match('}')) {
            return value;
        }
        while (true) {
            skip_whitespace();
            if (peek() != '"') {
                throw std::runtime_error("Expected string key in object");
            }
            std::string key = parse_string();
            skip_whitespace();
            expect(':');
            skip_whitespace();
            JsonValue child = parse_value();
            value.object_value.emplace_back(std::move(key), std::move(child));
            skip_whitespace();
            if (match('}')) {
                break;
            }
            expect(',');
            skip_whitespace();
        }
        return value;
    }

    JsonValue parse_array() {
        JsonValue value;
        value.type = JsonType::Array;
        expect('[');
        skip_whitespace();
        if (match(']')) {
            return value;
        }
        while (true) {
            skip_whitespace();
            value.array_value.push_back(parse_value());
            skip_whitespace();
            if (match(']')) {
                break;
            }
            expect(',');
            skip_whitespace();
        }
        return value;
    }

    JsonValue parse_boolean() {
        JsonValue value;
        value.type = JsonType::Boolean;
        if (match_literal("true")) {
            value.bool_value = true;
            return value;
        }
        if (match_literal("false")) {
            value.bool_value = false;
            return value;
        }
        throw std::runtime_error("Invalid boolean literal");
    }

    JsonValue parse_null() {
        if (!match_literal("null")) {
            throw std::runtime_error("Invalid null literal");
        }
        JsonValue value;
        value.type = JsonType::Null;
        return value;
    }

    JsonValue parse_number() {
        const std::size_t start = pos_;
        if (match('-')) {
            // already advanced
        }
        if (match('0')) {
            // single zero allowed
        } else if (std::isdigit(static_cast<unsigned char>(peek())) != 0) {
            while (!eof() && std::isdigit(static_cast<unsigned char>(peek())) != 0) {
                ++pos_;
            }
        } else {
            throw std::runtime_error("Invalid number literal");
        }
        if (match('.')) {
            if (eof() || std::isdigit(static_cast<unsigned char>(peek())) == 0) {
                throw std::runtime_error("Invalid fractional number");
            }
            while (!eof() && std::isdigit(static_cast<unsigned char>(peek())) != 0) {
                ++pos_;
            }
        }
        if (!eof() && (peek() == 'e' || peek() == 'E')) {
            ++pos_;
            if (!eof() && (peek() == '+' || peek() == '-')) {
                ++pos_;
            }
            if (eof() || std::isdigit(static_cast<unsigned char>(peek())) == 0) {
                throw std::runtime_error("Invalid exponent in number");
            }
            while (!eof() && std::isdigit(static_cast<unsigned char>(peek())) != 0) {
                ++pos_;
            }
        }
        const std::string_view slice = input_.substr(start, pos_ - start);
        const std::string buffer(slice);
        char* end = nullptr;
        errno = 0;
        const double parsed = std::strtod(buffer.c_str(), &end);
        if (errno == ERANGE || end != buffer.c_str() + buffer.size()) {
            throw std::runtime_error("Unable to parse number literal");
        }
        JsonValue value;
        value.type = JsonType::Number;
        value.number_value = parsed;
        return value;
    }

    std::string parse_string() {
        expect('"');
        std::string output;
        while (true) {
            if (eof()) {
                throw std::runtime_error("Unterminated string literal");
            }
            const char ch = get();
            if (ch == '"') {
                break;
            }
            if (ch == '\\') {
                if (eof()) {
                    throw std::runtime_error("Unterminated escape sequence");
                }
                const char esc = get();
                switch (esc) {
                    case '"':
                    case '\\':
                    case '/':
                        output.push_back(esc);
                        break;
                    case 'b':
                        output.push_back('\b');
                        break;
                    case 'f':
                        output.push_back('\f');
                        break;
                    case 'n':
                        output.push_back('\n');
                        break;
                    case 'r':
                        output.push_back('\r');
                        break;
                    case 't':
                        output.push_back('\t');
                        break;
                    case 'u':
                        output.append(parse_unicode_escape());
                        break;
                    default:
                        throw std::runtime_error("Invalid escape sequence in string");
                }
            } else {
                output.push_back(ch);
            }
        }
        return output;
    }

    std::string parse_unicode_escape() {
        if (pos_ + 4 > input_.size()) {
            throw std::runtime_error("Truncated unicode escape");
        }
        const std::string_view slice = input_.substr(pos_, 4);
        pos_ += 4;
        unsigned int codepoint = 0;
        for (char ch : slice) {
            codepoint <<= 4;
            if (ch >= '0' && ch <= '9') {
                codepoint |= static_cast<unsigned int>(ch - '0');
            } else if (ch >= 'a' && ch <= 'f') {
                codepoint |= static_cast<unsigned int>(10 + ch - 'a');
            } else if (ch >= 'A' && ch <= 'F') {
                codepoint |= static_cast<unsigned int>(10 + ch - 'A');
            } else {
                throw std::runtime_error("Invalid unicode escape");
            }
        }
        std::string utf8;
        append_utf8(codepoint, utf8);
        return utf8;
    }

    static void append_utf8(unsigned int codepoint, std::string& out) {
        if (codepoint <= 0x7F) {
            out.push_back(static_cast<char>(codepoint));
        } else if (codepoint <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | ((codepoint >> 6) & 0x1F)));
            out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        } else if (codepoint <= 0xFFFF) {
            out.push_back(static_cast<char>(0xE0 | ((codepoint >> 12) & 0x0F)));
            out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | ((codepoint >> 18) & 0x07)));
            out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        }
    }

    void expect(char expected) {
        if (eof() || input_[pos_] != expected) {
            throw std::runtime_error("Unexpected character in JSON input");
        }
        ++pos_;
    }

    bool match(char expected) {
        if (!eof() && input_[pos_] == expected) {
            ++pos_;
            return true;
        }
        return false;
    }

    bool match_literal(std::string_view literal) {
        if (input_.substr(pos_, literal.size()) == literal) {
            pos_ += literal.size();
            return true;
        }
        return false;
    }

    void skip_whitespace() {
        while (!eof()) {
            const char ch = input_[pos_];
            if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
                ++pos_;
                continue;
            }
            break;
        }
    }

    bool eof() const {
        return pos_ >= input_.size();
    }

    char peek() const {
        return input_[pos_];
    }

    char get() {
        return input_[pos_++];
    }

    std::string_view input_;
    std::size_t pos_{0};
};

const JsonValue* expect_string_field(const JsonValue& object, std::string_view key, std::string& error) {
    const auto* value = object.find(key);
    if (!value || !value->is_string()) {
        error = std::string("Missing or invalid string field: ") + std::string(key);
        return nullptr;
    }
    return value;
}

}  // namespace

namespace ephemeralnet::update {

const DownloadInfo* Metadata::find_download(std::string_view platform) const {
    for (const auto& download : downloads) {
        if (download.platform == platform) {
            return &download;
        }
    }
    return nullptr;
}

bool parse_update_metadata(std::string_view json, Metadata& output, std::string& error_message) {
    try {
        JsonParser parser(json);
        const JsonValue root = parser.parse();
        if (!root.is_object()) {
            error_message = "Version metadata must be a JSON object";
            return false;
        }

        const auto* version = expect_string_field(root, "version", error_message);
        if (!version) {
            return false;
        }
        const auto* tag = expect_string_field(root, "tag", error_message);
        if (!tag) {
            return false;
        }
        const auto* commit = expect_string_field(root, "commit", error_message);
        if (!commit) {
            return false;
        }
        const auto* channel = expect_string_field(root, "channel", error_message);
        if (!channel) {
            return false;
        }
        const auto* generated_at = expect_string_field(root, "generated_at", error_message);
        if (!generated_at) {
            return false;
        }

        output.version = version->string_value;
        output.tag = tag->string_value;
        output.commit = commit->string_value;
        output.channel = channel->string_value;
        output.generated_at = generated_at->string_value;

        if (const auto* notes = root.find("notes_url"); notes && notes->is_string()) {
            output.notes_url = notes->string_value;
        } else {
            output.notes_url.reset();
        }

        output.downloads.clear();
        const auto* downloads = root.find("downloads");
        if (!downloads || !downloads->is_object()) {
            error_message = "Downloads block missing or invalid";
            return false;
        }
        for (const auto& [platform, value] : downloads->object_value) {
            if (!value.is_object()) {
                continue;
            }
            DownloadInfo info{};
            info.platform = platform;

            const auto* url = expect_string_field(value, "url", error_message);
            if (!url) {
                return false;
            }
            info.url = url->string_value;

            const auto* arch = value.find("arch");
            if (arch && arch->is_string()) {
                info.arch = arch->string_value;
            } else {
                info.arch.clear();
            }

            const auto* format = value.find("format");
            if (format && format->is_string()) {
                info.format = format->string_value;
            } else {
                info.format.clear();
            }

            const auto* sha = value.find("sha256");
            if (sha && sha->is_string()) {
                info.sha256 = sha->string_value;
            } else {
                info.sha256.reset();
            }

            output.downloads.push_back(std::move(info));
        }
        if (output.downloads.empty()) {
            error_message = "No valid downloads found in metadata";
            return false;
        }
        return true;
    } catch (const std::exception& ex) {
        error_message = ex.what();
        return false;
    }
}

namespace {

std::string_view trim(std::string_view text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    return text;
}

}  // namespace

std::optional<SemVer> parse_semver(std::string_view text) {
    text = trim(text);
    if (text.empty()) {
        return std::nullopt;
    }
    if (text.front() == 'v' || text.front() == 'V') {
        text.remove_prefix(1);
    }
    SemVer result{};
    int parts_parsed = 0;
    while (!text.empty() && parts_parsed < 3) {
        std::size_t dot = text.find('.');
        const std::string_view token = text.substr(0, dot);
        if (token.empty()) {
            return std::nullopt;
        }
        int value = 0;
        const auto fc = std::from_chars(token.data(), token.data() + token.size(), value);
        if (fc.ec != std::errc{}) {
            return std::nullopt;
        }
        switch (parts_parsed) {
            case 0:
                result.major = value;
                break;
            case 1:
                result.minor = value;
                break;
            case 2:
                result.patch = value;
                break;
        }
        ++parts_parsed;
        if (dot == std::string_view::npos) {
            text = std::string_view{};
        } else {
            text.remove_prefix(dot + 1);
        }
    }
    return result;
}

int compare_semver(const SemVer& lhs, const SemVer& rhs) {
    if (lhs.major != rhs.major) {
        return (lhs.major < rhs.major) ? -1 : 1;
    }
    if (lhs.minor != rhs.minor) {
        return (lhs.minor < rhs.minor) ? -1 : 1;
    }
    if (lhs.patch != rhs.patch) {
        return (lhs.patch < rhs.patch) ? -1 : 1;
    }
    return 0;
}

bool download_to_string(std::string_view url, std::string& output, std::string& error_message) {
    if (url.rfind("file://", 0) == 0) {
        return read_file_url(url, output, error_message);
    }
#ifdef _WIN32
    return download_http_winhttp(url, output, error_message);
#else
    return download_http_curl(url, output, error_message);
#endif
}

}  // namespace ephemeralnet::update
