#include "ephemeralnet/libephemeralnet.hpp"

#include "ephemeralnet/core/Node.hpp"

#include <utility>

namespace ephemeralnet::lib {

class Node::Impl {
public:
    Impl(PeerId id, Config config)
        : node_(std::move(id), std::move(config)) {}

    ::ephemeralnet::Node node_;
};

Node::Node(PeerId id, Config config)
    : impl_(std::make_unique<Impl>(std::move(id), std::move(config))) {}

Node::~Node() = default;
Node::Node(Node&&) noexcept = default;
Node& Node::operator=(Node&&) noexcept = default;

void Node::announce_chunk(const ChunkId& chunk_id, std::chrono::seconds ttl) {
    impl_->node_.announce_chunk(chunk_id, ttl);
}

protocol::Manifest Node::store_chunk(const ChunkId& chunk_id,
                                     ChunkData data,
                                     std::chrono::seconds ttl,
                                     std::optional<std::string> original_name) {
    return impl_->node_.store_chunk(chunk_id, std::move(data), ttl, std::move(original_name));
}

bool Node::ingest_manifest(const std::string& manifest_uri) {
    return impl_->node_.ingest_manifest(manifest_uri);
}

std::optional<ChunkData> Node::receive_chunk(const std::string& manifest_uri, ChunkData ciphertext) {
    return impl_->node_.receive_chunk(manifest_uri, std::move(ciphertext));
}

bool Node::request_chunk(const PeerId& peer_id,
                         const std::string& host,
                         std::uint16_t port,
                         const std::string& manifest_uri) {
    return impl_->node_.request_chunk(peer_id, host, port, manifest_uri);
}

std::optional<ChunkData> Node::fetch_chunk(const ChunkId& chunk_id) {
    return impl_->node_.fetch_chunk(chunk_id);
}

void Node::start_transport(std::uint16_t port) {
    impl_->node_.start_transport(port);
}

void Node::stop_transport() {
    impl_->node_.stop_transport();
}

std::uint16_t Node::transport_port() const {
    return impl_->node_.transport_port();
}

void Node::tick() {
    impl_->node_.tick();
}

const PeerId& Node::id() const noexcept {
    return impl_->node_.id();
}

Config& Node::config() noexcept {
    return impl_->node_.config();
}

const Config& Node::config() const noexcept {
    return impl_->node_.config();
}

}  // namespace ephemeralnet::lib
