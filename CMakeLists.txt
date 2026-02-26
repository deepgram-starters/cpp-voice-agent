cmake_minimum_required(VERSION 3.20)
project(cpp-voice-agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Dependencies via vcpkg ----
find_package(Crow CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# ---- Build target ----
add_executable(cpp-voice-agent src/main.cpp)

target_link_libraries(cpp-voice-agent
    PRIVATE
        Crow::Crow
        Boost::system
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
)
