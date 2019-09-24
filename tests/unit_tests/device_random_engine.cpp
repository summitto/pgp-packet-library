#include <gtest/gtest.h>
#include <cstddef>
#include <array>
#include "device_random_engine.h"


TEST(device_random_engine, is_random)
{
    using result_type = tests::device_random_engine::result_type;
    tests::device_random_engine e1, e2;

    constexpr const size_t size = 64;
    std::array<result_type, size> data1, data2;
    for (size_t i = 0; i < size; i++) data1[i] = e1();
    for (size_t i = 0; i < size; i++) data2[i] = e2();

    for (size_t i = 0; i < size; i++) {
        ASSERT_LE(e1.min(), data1[i]);
        ASSERT_LE(data1[i], e1.max());
    }

    // Yes, I know, two separate draws of 64 bytes _MIGHT_ be the same with an
    // ideal random number generator. In practice, though, no. And testing this
    // _does_ protect against initialising the random engine with the same seed
    // every time.
    ASSERT_NE(data1, data2);
}
