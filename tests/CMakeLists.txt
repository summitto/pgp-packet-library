add_subdirectory(googletest)

set(test-sources "")
foreach(source ${pgp-packet-sources})
    list(APPEND test-sources "../${source}")
endforeach(source)

list(APPEND test-sources
    main.cpp
    unit_tests/array_signature_subpacket.cpp
    unit_tests/curve_oid.cpp
    unit_tests/decoder.cpp
    unit_tests/device_random_engine.cpp
    unit_tests/dsa_public_key.cpp
    unit_tests/dsa_secret_key.cpp
    unit_tests/dsa_signature.cpp
    unit_tests/ecdh_public_key.cpp
    unit_tests/ecdh_secret_key.cpp
    unit_tests/ecdsa_public_key.cpp
    unit_tests/ecdsa_secret_key.cpp
    unit_tests/eddsa_public_key.cpp
    unit_tests/eddsa_secret_key.cpp
    unit_tests/eddsa_signature.cpp
    unit_tests/elgamal_public_key.cpp
    unit_tests/elgamal_secret_key.cpp
    unit_tests/expected_number.cpp
    unit_tests/fixed_number.cpp
    unit_tests/gcrypt_encoder.cpp
    unit_tests/key_flags_subpacket.cpp
    unit_tests/multiprecision_integer.cpp
    unit_tests/numeric_signature_subpacket.cpp
    unit_tests/packet.cpp
    unit_tests/public_key.cpp
    unit_tests/range_encoder.cpp
    unit_tests/rsa_public_key.cpp
    unit_tests/rsa_secret_key.cpp
    unit_tests/rsa_signature.cpp
    unit_tests/secret_key.cpp
    unit_tests/signature.cpp
    unit_tests/signature_subpacket_set.cpp
    unit_tests/unknown_signature.cpp
    unit_tests/unknown_signature_subpacket.cpp
    unit_tests/user_id.cpp
    unit_tests/variable_number.cpp)

list(APPEND test-sources
    device_random_engine.cpp
    key_template.cpp)

add_executable(tests ${test-sources})
set_property(TARGET tests PROPERTY CXX_STANDARD 17)

target_compile_options(tests PRIVATE
    -Wall -Wextra -Wdeprecated -Wdocumentation -Wno-sign-compare
    -g -O0 -fprofile-instr-generate -fcoverage-mapping -fsanitize=address)
# target_compile_options(tests PRIVATE "-g" "-O0" "-fprofile-instr-generate" "-fcoverage-mapping" "-Weverything" "-Wno-c++98-compat" "-Wno-c++98-compat-pedantic" "-Wno-padded" "-Wno-shadow-uncaptured-local" "-Wno-global-constructors")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-instr-generate -fcoverage-mapping -fsanitize=address")

target_include_directories(tests PUBLIC ${LIBGCRYPT_INCLUDE_DIRS})
target_link_libraries(tests ${LIBGCRYPT_LIBRARIES})

target_include_directories(tests PUBLIC ${Boost_INCLUDE_DIRS})

target_include_directories(tests PUBLIC ${SODIUM_INCLUDE_DIRS})
target_link_libraries(tests ${SODIUM_LIBRARIES})

target_include_directories(tests PUBLIC ${CRYPTOPP_INCLUDE_DIRS})
target_link_libraries(tests ${CRYPTOPP_LIBRARIES})

target_include_directories(tests PUBLIC ${PROJECT_SOURCE_DIR}/GSL/include)
target_include_directories(tests PUBLIC ${PROJECT_SOURCE_DIR}/variant/include)

target_link_libraries(tests gtest_main)

add_custom_target(test
    COMMAND tests
    DEPENDS tests)

add_custom_target(profdata
    COMMAND llvm-profdata merge -o ${CMAKE_CURRENT_BINARY_DIR}/default.profdata ${CMAKE_CURRENT_BINARY_DIR}/default.profraw
    DEPENDS test)

add_custom_target(coverage
    COMMAND llvm-cov report ${CMAKE_CURRENT_BINARY_DIR}/tests -instr-profile=${CMAKE_CURRENT_BINARY_DIR}/default.profdata -ignore-filename-regex='/\(GSL|variant|tests\)/'
    DEPENDS profdata)

add_custom_target(coverage-html
    COMMAND llvm-cov show ${CMAKE_CURRENT_BINARY_DIR}/tests -instr-profile=${CMAKE_CURRENT_BINARY_DIR}/default.profdata -format=html -output-dir=${PROJECT_BINARY_DIR}/coverage -ignore-filename-regex='/\(GSL|variant|tests\)/'
    DEPENDS profdata)
