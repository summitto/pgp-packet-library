#include <random>
#include <limits>
#include <gtest/gtest.h>
#include "decoder.h"
#include "fixed_number.h"
#include "range_encoder.h"
#include "../device_random_engine.h"


namespace {
    thread_local tests::device_random_engine random_engine;

    template <typename T>
    void test_faithful_encoding_value(pgp::fixed_number<T> number) {
        // encode into data
        std::vector<uint8_t> data(2 + sizeof(T));
        pgp::range_encoder encoder{data};
        number.encode(encoder);

        // decode from data and check for equality
        pgp::decoder decoder{data};
        pgp::fixed_number<T> result{decoder};
        ASSERT_EQ(number, result);
    }

    template <typename T>
    void test_faithful_encoding()
    {
        std::uniform_int_distribution<T> distr(0, std::numeric_limits<T>::max());
        for (int i = 0; i < 1000; i++) {
            pgp::fixed_number<T> num{distr(random_engine)};

            test_faithful_encoding_value(num);
        }

        test_faithful_encoding_value(pgp::fixed_number<T>{0});
        test_faithful_encoding_value(pgp::fixed_number<T>{1});
        test_faithful_encoding_value(pgp::fixed_number<T>{std::numeric_limits<T>::max()});
        test_faithful_encoding_value(pgp::fixed_number<T>{std::numeric_limits<T>::max() - 1});
    }
}

TEST(fixed_number, faithful_encoding)
{
    test_faithful_encoding<uint8_t>();
    test_faithful_encoding<uint16_t>();
    test_faithful_encoding<uint32_t>();
    test_faithful_encoding<uint64_t>();
}
