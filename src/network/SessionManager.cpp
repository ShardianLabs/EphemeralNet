#include "ephemeralnet/network/SessionManager.hpp"

#include <iostream>
#include <utility>

namespace ephemeralnet {

void SessionManager::register_on_connect(SessionHandler handler) {
    on_connect_ = std::move(handler);
}

void SessionManager::register_on_disconnect(SessionHandler handler) {
    on_disconnect_ = std::move(handler);
}

void SessionManager::simulate_connect(const SessionContext& context) {
    if (on_connect_) {
        on_connect_(context);
    } else {
    std::cout << "[SessionManager] Peer connected: " << peer_id_to_string(context.peer_id) << "\n";
    }
}

void SessionManager::simulate_disconnect(const SessionContext& context) {
    if (on_disconnect_) {
        on_disconnect_(context);
    } else {
    std::cout << "[SessionManager] Peer disconnected: " << peer_id_to_string(context.peer_id) << "\n";
    }
}

}  
