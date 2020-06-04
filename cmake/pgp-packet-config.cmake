include("${CMAKE_CURRENT_LIST_DIR}/pgp-packet-targets.cmake")

# set module path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_LIST_DIR}/Modules/)

# find boost and sodium
find_package(Boost              REQUIRED)
find_package(sodium     1.0.16  REQUIRED)

# first try to find CryptoPP built using CMake
find_package(cryptopp CONFIG QUIET)

# if this didn't work, use our built-in search tool
if (NOT TARGET cryptopp-static)
    find_package(CryptoPP REQUIRED)
endif()
