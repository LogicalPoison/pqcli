cmake_minimum_required(VERSION 3.16)
project(pqcli VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(PQCLI_USE_SYSTEM_LIBOQS "Prefer a system-installed liboqs over the submodule" OFF)
option(PQCLI_BUILD_LIBOQS "Build liboqs from third_party/liboqs (submodule)" ON)

# ---------------------------------------------------------------------------
# Monocypher (vendored) — XChaCha20-Poly1305, BLAKE2b, crypto_wipe
# ---------------------------------------------------------------------------
set(MONOCYPHER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher)
if(NOT EXISTS "${MONOCYPHER_DIR}/monocypher.c")
  message(FATAL_ERROR "Monocypher not found at ${MONOCYPHER_DIR}")
endif()
add_library(monocypher STATIC ${MONOCYPHER_DIR}/monocypher.c)
target_include_directories(monocypher PUBLIC ${MONOCYPHER_DIR})
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(monocypher PRIVATE -O2)
endif()

# ---------------------------------------------------------------------------
# liboqs: submodule under third_party/liboqs, or system package
# ---------------------------------------------------------------------------
set(LIBOQS_FOUND FALSE)

if(PQCLI_USE_SYSTEM_LIBOQS)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBOQS QUIET liboqs)
    if(LIBOQS_FOUND)
      message(STATUS "Using system liboqs (pkg-config): ${LIBOQS_VERSION}")
    endif()
  endif()
  if(NOT LIBOQS_FOUND)
    find_path(LIBOQS_INCLUDE_DIR NAMES oqs/oqs.h
      PATHS /usr/local/include /usr/include $ENV{LIBOQS_ROOT}/include)
    find_library(LIBOQS_LIBRARY NAMES oqs liboqs
      PATHS /usr/local/lib /usr/lib $ENV{LIBOQS_ROOT}/lib)
    if(LIBOQS_INCLUDE_DIR AND LIBOQS_LIBRARY)
      set(LIBOQS_FOUND TRUE)
      set(LIBOQS_INCLUDE_DIRS ${LIBOQS_INCLUDE_DIR})
      set(LIBOQS_LIBRARIES ${LIBOQS_LIBRARY})
      message(STATUS "Using system liboqs: ${LIBOQS_LIBRARY}")
    endif()
  endif()
endif()

set(LIBOQS_SUBMODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/liboqs")
if(NOT LIBOQS_FOUND AND PQCLI_BUILD_LIBOQS)
  if(EXISTS "${LIBOQS_SUBMODULE_DIR}/CMakeLists.txt")
    message(STATUS "Building liboqs from submodule: ${LIBOQS_SUBMODULE_DIR}")
    set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
    set(OQS_DIST_BUILD ON CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    # Prefer liboqs internal AES/SHA so we do not need OpenSSL at all
    set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
    add_subdirectory(${LIBOQS_SUBMODULE_DIR} ${CMAKE_BINARY_DIR}/third_party/liboqs EXCLUDE_FROM_ALL)
    set(LIBOQS_FOUND TRUE)
    set(LIBOQS_FROM_SUBMODULE TRUE)
  else()
    message(WARNING
      "third_party/liboqs not found.\n"
      "  git submodule update --init --recursive")
  endif()
endif()

if(NOT LIBOQS_FOUND)
  message(FATAL_ERROR
    "liboqs not available.\n"
    "  git submodule update --init --recursive\n"
    "or install from https://github.com/open-quantum-safe/liboqs")
endif()

# ---------------------------------------------------------------------------
# pqcli executable
# ---------------------------------------------------------------------------
set(PQCLI_SOURCES
  src/main.c
  src/utils.c
  src/crypto.c
  src/keyring.c
  src/commands.c
  src/features.c
)

add_executable(pqcli ${PQCLI_SOURCES})

target_include_directories(pqcli PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${MONOCYPHER_DIR}
)

target_link_libraries(pqcli PRIVATE monocypher)

if(LIBOQS_FROM_SUBMODULE)
  target_link_libraries(pqcli PRIVATE oqs)
  target_include_directories(pqcli PRIVATE
    ${CMAKE_BINARY_DIR}/third_party/liboqs/include
    ${LIBOQS_SUBMODULE_DIR}/src
  )
else()
  target_include_directories(pqcli PRIVATE ${LIBOQS_INCLUDE_DIRS})
  target_link_libraries(pqcli PRIVATE ${LIBOQS_LIBRARIES})
endif()

if(WIN32)
  target_compile_definitions(pqcli PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(pqcli PRIVATE bcrypt)
elseif(UNIX AND NOT APPLE)
  target_link_libraries(pqcli PRIVATE m)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(pqcli PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter)
endif()

install(TARGETS pqcli RUNTIME DESTINATION bin)

message(STATUS "=== pqcli configuration ===")
message(STATUS "  Version:      ${PROJECT_VERSION}")
message(STATUS "  Symmetric:    Monocypher (XChaCha20-Poly1305 + BLAKE2b)")
message(STATUS "  C standard:   ${CMAKE_C_STANDARD}")
if(LIBOQS_FROM_SUBMODULE)
  message(STATUS "  liboqs:       submodule (third_party/liboqs)")
else()
  message(STATUS "  liboqs:       ${LIBOQS_LIBRARIES}")
endif()
message(STATUS "============================")
