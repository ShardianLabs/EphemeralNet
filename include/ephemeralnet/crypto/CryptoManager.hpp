#pragma once

#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/crypto/ChaCha20.hpp"

#include <optional>
#include <random>
#include <span>

namespace ephemeralnet::crypto {

struct CipherText {
    ChunkData data;
    Nonce nonce;
    bool encrypted{true};
};

class CryptoManager {
public:
    CryptoManager();
    explicit CryptoManager(Key key);

    CipherText encrypt(const ChunkId& chunk_id, const ChunkData& plaintext);
    std::optional<ChunkData> decrypt(const ChunkId& chunk_id,
                                     std::span<const std::uint8_t> ciphertext,
                                     const Nonce& nonce) const;

    static Key generate_key();
    static void random_bytes(std::span<std::uint8_t> buffer);
    static CipherText encrypt_with_key(const Key& key,
                                       const ChunkId& chunk_id,
                                       const ChunkData& plaintext);
    static std::optional<ChunkData> decrypt_with_key(const Key& key,
                                                     const ChunkId& chunk_id,
                                                     std::span<const std::uint8_t> ciphertext,
                                                     const Nonce& nonce);

    const Key& key() const noexcept { return key_; }

private:
    Key key_{};
    mutable std::mt19937_64 prng_;

    void fill_random(std::span<std::uint8_t> buffer) const;
};

}  // namespace ephemeralnet::crypto
