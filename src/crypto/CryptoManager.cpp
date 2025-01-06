#include "ephemeralnet/crypto/CryptoManager.hpp"

#include <algorithm>

namespace ephemeralnet::crypto {

namespace {
[[nodiscard]] std::uint32_t derive_counter(const ChunkId& chunk_id) noexcept {
    return static_cast<std::uint32_t>(chunk_id[0]) |
           (static_cast<std::uint32_t>(chunk_id[1]) << 8) |
           (static_cast<std::uint32_t>(chunk_id[2]) << 16) |
           (static_cast<std::uint32_t>(chunk_id[3]) << 24);
}
}

CryptoManager::CryptoManager()
    : CryptoManager(Key{}) {}

CryptoManager::CryptoManager(Key key)
    : key_(key),
      prng_(std::random_device{}()) {
    if (std::all_of(key_.bytes.begin(), key_.bytes.end(), [](auto value) { return value == 0U; })) {
        fill_random(key_.bytes);
    }
}

CipherText CryptoManager::encrypt(const ChunkId& chunk_id, const ChunkData& plaintext) {
    CipherText output{};
    output.data.resize(plaintext.size());
    fill_random(output.nonce.bytes);

    const auto counter = derive_counter(chunk_id);
    const std::span<const std::uint8_t> input{plaintext};
    ChaCha20::apply(key_, output.nonce, input, output.data, counter);
    return output;
}

std::optional<ChunkData> CryptoManager::decrypt(const ChunkId& chunk_id,
                                                std::span<const std::uint8_t> ciphertext,
                                                const Nonce& nonce) const {
    ChunkData plaintext;
    plaintext.resize(ciphertext.size());

    const auto counter = derive_counter(chunk_id);
    ChaCha20::apply(key_, nonce, ciphertext, plaintext, counter);
    return plaintext;
}

void CryptoManager::fill_random(std::span<std::uint8_t> buffer) const {
    std::uniform_int_distribution<std::uint32_t> dist(0, 0xFF);
    for (auto& byte : buffer) {
        byte = static_cast<std::uint8_t>(dist(prng_));
    }
}

}  // namespace ephemeralnet::crypto
