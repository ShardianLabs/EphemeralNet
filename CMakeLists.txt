cmake_minimum_required(VERSION 3.20)

project(EphemeralNet VERSION 0.1.0 LANGUAGES CXX)

option(EPHEMERALNET_BUILD_TESTS "Build EphemeralNet unit tests" ON)
option(EPHEMERALNET_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(cmake/CompilerWarnings.cmake)

add_library(ephemeralnet_core
    src/core/Node.cpp
    src/core/ChunkStore.cpp
    src/core/Types.cpp
    src/dht/KademliaTable.cpp
    src/network/SessionManager.cpp
    src/network/KeyManager.cpp
    src/network/KeyExchange.cpp
    src/network/ReputationManager.cpp
    src/crypto/ChaCha20.cpp
    src/crypto/CryptoManager.cpp
    src/crypto/Sha256.cpp
    src/crypto/HmacSha256.cpp
    src/crypto/Shamir.cpp
    src/network/NatTraversal.cpp
    src/core/SwarmCoordinator.cpp
    src/protocol/Manifest.cpp
    src/protocol/Message.cpp
)

add_library(ephemeralnet::core ALIAS ephemeralnet_core)

if(EPHEMERALNET_WARNINGS_AS_ERRORS)
    ephemeralnet_enable_warnings(ephemeralnet_core TREAT_AS_ERRORS)
else()
    ephemeralnet_enable_warnings(ephemeralnet_core)
endif()

set_target_properties(ephemeralnet_core PROPERTIES
    OUTPUT_NAME ephemeralnet_core
)

target_include_directories(ephemeralnet_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

find_package(Threads REQUIRED)

target_link_libraries(ephemeralnet_core
    PUBLIC
        Threads::Threads
)

if(WIN32)
    target_link_libraries(ephemeralnet_core
        PUBLIC
            ws2_32
    )
endif()

add_executable(ephemeralnet
    src/main.cpp
    src/daemon/ControlClient.cpp
    src/daemon/ControlServer.cpp
    src/daemon/StructuredLogger.cpp
)

set_target_properties(ephemeralnet PROPERTIES
    OUTPUT_NAME eph
)

if(EPHEMERALNET_WARNINGS_AS_ERRORS)
    ephemeralnet_enable_warnings(ephemeralnet TREAT_AS_ERRORS)
else()
    ephemeralnet_enable_warnings(ephemeralnet)
endif()

target_link_libraries(ephemeralnet
    PRIVATE
        ephemeralnet::core
)

target_include_directories(ephemeralnet
    PRIVATE
        include
)

target_compile_definitions(ephemeralnet
    PRIVATE
        EPHEMERALNET_VERSION="${PROJECT_VERSION}"
)

if(EPHEMERALNET_BUILD_TESTS)
    enable_testing()

    add_executable(ephemeralnet_smoke
        tests/smoke.cpp
    )

    target_link_libraries(ephemeralnet_smoke
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_smoke TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_smoke)
    endif()

    add_test(NAME EphemeralNet.Smoke COMMAND ephemeralnet_smoke)

    add_executable(ephemeralnet_protocol_tests
        tests/protocol_message.cpp
    )

    target_link_libraries(ephemeralnet_protocol_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_protocol_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_protocol_tests)
    endif()

    add_test(NAME EphemeralNet.ProtocolMessages COMMAND ephemeralnet_protocol_tests)

    add_executable(ephemeralnet_protocol_fuzz_tests
        tests/protocol_fuzz.cpp
    )

    target_link_libraries(ephemeralnet_protocol_fuzz_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_protocol_fuzz_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_protocol_fuzz_tests)
    endif()

    add_test(NAME EphemeralNet.ProtocolFuzz COMMAND ephemeralnet_protocol_fuzz_tests)

    add_executable(ephemeralnet_protocol_auth_tests
        tests/protocol_auth.cpp
    )

    target_link_libraries(ephemeralnet_protocol_auth_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_protocol_auth_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_protocol_auth_tests)
    endif()

    add_test(NAME EphemeralNet.ProtocolAuth COMMAND ephemeralnet_protocol_auth_tests)

    add_executable(ephemeralnet_dht_tests
        tests/dht_buckets.cpp
    )

    target_link_libraries(ephemeralnet_dht_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_dht_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_dht_tests)
    endif()

    add_test(NAME EphemeralNet.DhtBuckets COMMAND ephemeralnet_dht_tests)

    add_executable(ephemeralnet_key_schedule_tests
        tests/key_schedule.cpp
    )

    target_link_libraries(ephemeralnet_key_schedule_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_key_schedule_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_key_schedule_tests)
    endif()

    add_test(NAME EphemeralNet.KeySchedule COMMAND ephemeralnet_key_schedule_tests)

    add_executable(ephemeralnet_crypto_hardening_tests
        tests/crypto_hardening.cpp
    )

    target_link_libraries(ephemeralnet_crypto_hardening_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_crypto_hardening_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_crypto_hardening_tests)
    endif()

    add_test(NAME EphemeralNet.CryptoHardening COMMAND ephemeralnet_crypto_hardening_tests)

    add_executable(ephemeralnet_handshake_tests
        tests/handshake.cpp
    )

    target_link_libraries(ephemeralnet_handshake_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_handshake_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_handshake_tests)
    endif()

    add_test(NAME EphemeralNet.Handshake COMMAND ephemeralnet_handshake_tests)

    add_executable(ephemeralnet_ttl_audit_tests
        tests/ttl_audit.cpp
    )

    target_link_libraries(ephemeralnet_ttl_audit_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_ttl_audit_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_ttl_audit_tests)
    endif()

    add_test(NAME EphemeralNet.TtlAudit COMMAND ephemeralnet_ttl_audit_tests)

    add_executable(ephemeralnet_secure_transport_tests
        tests/secure_transport.cpp
    )

    target_link_libraries(ephemeralnet_secure_transport_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_secure_transport_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_secure_transport_tests)
    endif()

    add_test(NAME EphemeralNet.SecureTransport COMMAND ephemeralnet_secure_transport_tests)

    add_executable(ephemeralnet_shamir_tests
        tests/shamir.cpp
    )

    target_link_libraries(ephemeralnet_shamir_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_shamir_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_shamir_tests)
    endif()

    add_test(NAME EphemeralNet.Shamir COMMAND ephemeralnet_shamir_tests)

    add_executable(ephemeralnet_cli_config_tests
        tests/cli_config.cpp
    )

    target_link_libraries(ephemeralnet_cli_config_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_cli_config_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_cli_config_tests)
    endif()

    add_test(NAME EphemeralNet.CLIConfig COMMAND ephemeralnet_cli_config_tests)

    add_executable(ephemeralnet_manifest_tests
        tests/manifest.cpp
    )

    target_link_libraries(ephemeralnet_manifest_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_manifest_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_manifest_tests)
    endif()

    add_test(NAME EphemeralNet.Manifest COMMAND ephemeralnet_manifest_tests)

    add_executable(ephemeralnet_manifest_fuzz_tests
        tests/manifest_fuzz.cpp
    )

    target_link_libraries(ephemeralnet_manifest_fuzz_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_manifest_fuzz_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_manifest_fuzz_tests)
    endif()

    add_test(NAME EphemeralNet.ManifestFuzz COMMAND ephemeralnet_manifest_fuzz_tests)

    add_executable(ephemeralnet_manifest_flow_tests
        tests/manifest_flow.cpp
    )

    target_link_libraries(ephemeralnet_manifest_flow_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_manifest_flow_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_manifest_flow_tests)
    endif()

    add_test(NAME EphemeralNet.ManifestFlow COMMAND ephemeralnet_manifest_flow_tests)

    add_executable(ephemeralnet_secure_exchange_tests
        tests/secure_exchange.cpp
    )

    target_link_libraries(ephemeralnet_secure_exchange_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_secure_exchange_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_secure_exchange_tests)
    endif()

    add_test(NAME EphemeralNet.SecureExchange COMMAND ephemeralnet_secure_exchange_tests)

    add_executable(ephemeralnet_manifest_announce_tests
        tests/announce_distribution.cpp
    )

    target_link_libraries(ephemeralnet_manifest_announce_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_manifest_announce_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_manifest_announce_tests)
    endif()

    add_test(NAME EphemeralNet.ManifestAnnounce COMMAND ephemeralnet_manifest_announce_tests)

    add_executable(ephemeralnet_fetch_retry_tests
        tests/fetch_retry.cpp
    )

    target_link_libraries(ephemeralnet_fetch_retry_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_fetch_retry_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_fetch_retry_tests)
    endif()

    add_test(NAME EphemeralNet.FetchRetry COMMAND ephemeralnet_fetch_retry_tests)

    add_executable(ephemeralnet_fetch_priority_tests
        tests/fetch_priority.cpp
    )

    target_link_libraries(ephemeralnet_fetch_priority_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_fetch_priority_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_fetch_priority_tests)
    endif()

    add_test(NAME EphemeralNet.FetchPriority COMMAND ephemeralnet_fetch_priority_tests)

    add_executable(ephemeralnet_upload_choking_tests
        tests/upload_choking.cpp
    )

    target_link_libraries(ephemeralnet_upload_choking_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_upload_choking_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_upload_choking_tests)
    endif()

    add_test(NAME EphemeralNet.UploadChoking COMMAND ephemeralnet_upload_choking_tests)

    add_executable(ephemeralnet_upload_choking_scheduler_tests
        tests/upload_choking_scheduler.cpp
    )

    target_link_libraries(ephemeralnet_upload_choking_scheduler_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_upload_choking_scheduler_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_upload_choking_scheduler_tests)
    endif()

    add_test(NAME EphemeralNet.UploadChokingScheduler COMMAND ephemeralnet_upload_choking_scheduler_tests)

    add_executable(ephemeralnet_bootstrap_tests
        tests/bootstrap.cpp
    )

    target_link_libraries(ephemeralnet_bootstrap_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_bootstrap_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_bootstrap_tests)
    endif()

    add_test(NAME EphemeralNet.Bootstrap COMMAND ephemeralnet_bootstrap_tests)

    add_executable(ephemeralnet_nat_traversal_tests
        tests/nat_traversal.cpp
    )

    target_link_libraries(ephemeralnet_nat_traversal_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_nat_traversal_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_nat_traversal_tests)
    endif()

    add_test(NAME EphemeralNet.NatTraversal COMMAND ephemeralnet_nat_traversal_tests)

    add_executable(ephemeralnet_nat_node_tests
        tests/nat_node.cpp
    )

    target_link_libraries(ephemeralnet_nat_node_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_nat_node_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_nat_node_tests)
    endif()

    add_test(NAME EphemeralNet.NatNode COMMAND ephemeralnet_nat_node_tests)

    add_executable(ephemeralnet_swarm_distribution_tests
        tests/swarm_distribution.cpp
    )

    target_link_libraries(ephemeralnet_swarm_distribution_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_swarm_distribution_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_swarm_distribution_tests)
    endif()

    add_test(NAME EphemeralNet.SwarmDistribution COMMAND ephemeralnet_swarm_distribution_tests)

    add_executable(ephemeralnet_swarm_fairness_tests
        tests/swarm_fairness.cpp
    )

    target_link_libraries(ephemeralnet_swarm_fairness_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_swarm_fairness_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_swarm_fairness_tests)
    endif()

    add_test(NAME EphemeralNet.SwarmFairness COMMAND ephemeralnet_swarm_fairness_tests)

    add_executable(ephemeralnet_swarm_node_tests
        tests/swarm_node.cpp
    )

    target_link_libraries(ephemeralnet_swarm_node_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_swarm_node_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_swarm_node_tests)
    endif()

    add_test(NAME EphemeralNet.SwarmNode COMMAND ephemeralnet_swarm_node_tests)

    add_executable(ephemeralnet_swarm_roles_tests
        tests/swarm_roles.cpp
    )

    target_link_libraries(ephemeralnet_swarm_roles_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_swarm_roles_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_swarm_roles_tests)
    endif()

    add_test(NAME EphemeralNet.SwarmRoles COMMAND ephemeralnet_swarm_roles_tests)

    add_executable(ephemeralnet_persistent_storage_tests
        tests/persistent_storage.cpp
    )

    target_link_libraries(ephemeralnet_persistent_storage_tests
        PRIVATE
            ephemeralnet::core
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_persistent_storage_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_persistent_storage_tests)
    endif()

    add_test(NAME EphemeralNet.PersistentStorage COMMAND ephemeralnet_persistent_storage_tests)

    add_test(NAME EphemeralNet.CLIUsage COMMAND $<TARGET_FILE:ephemeralnet> --help)
    set_tests_properties(EphemeralNet.CLIUsage PROPERTIES
        PASS_REGULAR_EXPRESSION "Usage: eph"
    )

    add_test(NAME EphemeralNet.CLIHelpAlias COMMAND $<TARGET_FILE:ephemeralnet> help)
    set_tests_properties(EphemeralNet.CLIHelpAlias PROPERTIES
        PASS_REGULAR_EXPRESSION "Usage: eph"
    )

    add_executable(ephemeralnet_cli_tests
        tests/cli_error_cases.cpp
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_cli_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_cli_tests)
    endif()

    add_test(NAME EphemeralNet.CLIBehaviour COMMAND ephemeralnet_cli_tests)
    set_tests_properties(EphemeralNet.CLIBehaviour PROPERTIES
        ENVIRONMENT "EPH_CLI_EXECUTABLE=$<TARGET_FILE:ephemeralnet>"
    )

    add_executable(ephemeralnet_cli_flow_tests
        tests/cli_control_flow.cpp
    )

    if(EPHEMERALNET_WARNINGS_AS_ERRORS)
        ephemeralnet_enable_warnings(ephemeralnet_cli_flow_tests TREAT_AS_ERRORS)
    else()
        ephemeralnet_enable_warnings(ephemeralnet_cli_flow_tests)
    endif()

    add_test(NAME EphemeralNet.CLIControlFlow COMMAND ephemeralnet_cli_flow_tests)
    set_tests_properties(EphemeralNet.CLIControlFlow PROPERTIES
        ENVIRONMENT "EPH_CLI_EXECUTABLE=$<TARGET_FILE:ephemeralnet>"
    )

    set_tests_properties(EphemeralNet.CLIConfig PROPERTIES
        ENVIRONMENT "EPH_CLI_EXECUTABLE=$<TARGET_FILE:ephemeralnet>"
    )
endif()
