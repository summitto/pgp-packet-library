#include <gtest/gtest.h>
#include <sodium/core.h>


int main(int argc, char **argv) {
    // ensure libsodium is initialized
    if (sodium_init() == -1) {
        // cannot run tests without libsodium
        throw std::runtime_error{ "Failed to initialize libsodium" };
    }

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
