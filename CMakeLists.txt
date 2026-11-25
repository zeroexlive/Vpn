cmake_minimum_required(VERSION 3.14)
project(feilian-client C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# CUI — MIT, https://github.com/yappologistic/CUI.git
# Pinned to the release the cloned copy in ~/workspace/CUI documents (1.5.0).
include(FetchContent)
FetchContent_Declare(cui
  GIT_REPOSITORY https://github.com/yappologistic/CUI.git
  GIT_TAG v1.5.0)
FetchContent_MakeAvailable(cui)

find_package(OpenSSL REQUIRED)

add_executable(feilian-client
  src/main.c
  src/feilian.c)

target_include_directories(feilian-client PRIVATE src)
target_link_libraries(feilian-client PRIVATE cui::cui OpenSSL::SSL OpenSSL::Crypto)
cui_app_target(feilian-client)

# Linux X11 is the CUI default backend; nothing extra to link here,
# CUI brings -lX11 -ldl -lm -lpthread itself.
