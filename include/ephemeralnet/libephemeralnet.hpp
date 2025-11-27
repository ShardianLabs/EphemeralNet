#pragma once

#include "ephemeralnet/Export.hpp"
#include "ephemeralnet/Config.hpp"
#include "ephemeralnet/Types.hpp"
#include "ephemeralnet/protocol/Manifest.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace ephemeralnet::lib {

class EPHEMERALNET_API Node {
public:
    Node(PeerId id, Config config = {});
    ~Node();

    Node(Node&&) noexcept;
    Node& operator=(Node&&) noexcept;
    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    void announce_chunk(const ChunkId& chunk_id, std::chrono::seconds ttl);
    protocol::Manifest store_chunk(const ChunkId& chunk_id,
                                   ChunkData data,
                                   std::chrono::seconds ttl,
                                   std::optional<std::string> original_name = std::nullopt);
    bool ingest_manifest(const std::string& manifest_uri);
    std::optional<ChunkData> receive_chunk(const std::string& manifest_uri, ChunkData ciphertext);
    bool request_chunk(const PeerId& peer_id,
                       const std::string& host,
                       std::uint16_t port,
                       const std::string& manifest_uri);
    std::optional<ChunkData> fetch_chunk(const ChunkId& chunk_id);

    void start_transport(std::uint16_t port = 0);
    void stop_transport();
    std::uint16_t transport_port() const;
    void tick();

    const PeerId& id() const noexcept;
    Config& config() noexcept;
    const Config& config() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace ephemeralnet::lib
