#pragma once

#include "ephemeralnet/Types.hpp"

#include <functional>
#include <string>
#include <unordered_map>

namespace ephemeralnet {

struct SessionContext {
    PeerId peer_id{};
    std::string endpoint;
};

class SessionManager {
public:
    using SessionHandler = std::function<void(const SessionContext&)>;

    void register_on_connect(SessionHandler handler);
    void register_on_disconnect(SessionHandler handler);

    void simulate_connect(const SessionContext& context);
    void simulate_disconnect(const SessionContext& context);

private:
    SessionHandler on_connect_{};
    SessionHandler on_disconnect_{};
};

}  
