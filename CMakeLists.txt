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
    src/crypto/ChaCha20.cpp
    src/crypto/CryptoManager.cpp
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

add_executable(ephemeralnet
    src/main.cpp
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
endif()
