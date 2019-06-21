#include <limits>
#include <array>
#include <stdexcept>
#include <gtest/gtest.h>
#include "range_encoder.h"
#include "../device_random_engine.h"


namespace {
    thread_local tests::device_random_engine random_engine;
}

TEST(range_encoder, push_integer)
{
    std::uniform_int_distribution<int> type_distr(0, 3);
    std::uniform_int_distribution<uint64_t> distr(0, std::numeric_limits<uint64_t>::max());

    std::array<uint8_t, 42> data, dataControl;
    pgp::range_encoder encoder{data};

    ASSERT_EQ(encoder.size(), 0);

    size_t cursor = 0;

    // In C++20 this would be a template lambda, of course
    auto push_integer = [&](auto dummy) {
        size_t size = sizeof(decltype(dummy));
        if (cursor + size <= data.size()) {
            decltype(dummy) value = static_cast<decltype(dummy)>(distr(random_engine));

            // Encode in big endian
            for (size_t i = 0; i < size; i++) {
                dataControl[cursor + i] = gsl::narrow_cast<uint8_t>(value >> (8 * (size - 1 - i)));
            }

            encoder.push(value);
            cursor += size;

            ASSERT_EQ(encoder.size(), cursor);
        }
    };

    while (cursor < data.size()) {
        switch (type_distr(random_engine)) {
            case 0: push_integer(static_cast<uint8_t >(0)); break;
            case 1: push_integer(static_cast<uint16_t>(0)); break;
            case 2: push_integer(static_cast<uint32_t>(0)); break;
            case 3: push_integer(static_cast<uint64_t>(0)); break;
        }
    }

    ASSERT_EQ(data, dataControl);
}

TEST(range_encoder, push_while_masked)
{
    std::array<uint8_t, 8> data;
    pgp::range_encoder encoder{data};

    encoder.insert_bits(2, 0b11);
    // The first byte fits even after the queued bits, so the push should succeed
    encoder.push<uint16_t>(0x1234);
    ASSERT_EQ(data[0], 0b11010010);

    encoder.insert_bits(4, 0b1111);
    // Too many queued bits for number to fit
    ASSERT_THROW(encoder.push<uint8_t>(0x12), std::range_error);
    ASSERT_THROW(encoder.push<uint16_t>(0x1234), std::range_error);
}

TEST(range_encoder, push_iterators)
{
    std::array<uint8_t, 4> input{10, 20, 30, 50};
    std::array<uint8_t, 5> data{0, 0, 0, 0, 0};

    pgp::range_encoder encoder{data};
    encoder.push(input.begin(), input.begin());
    ASSERT_EQ(encoder.size(), 0);

    encoder.push(input.begin(), input.begin() + 3);
    ASSERT_EQ(encoder.size(), 3);
    ASSERT_EQ(pgp::span(input.data(), input.data() + 3), pgp::span(data.data(), data.data() + 3));
    ASSERT_EQ(data[3], 0);

    encoder.push(input.begin() + 3, input.begin() + 4);
    ASSERT_EQ(pgp::span<const uint8_t>(input), pgp::span<const uint8_t>(data.data(), data.data() + 4));

    ASSERT_THROW(encoder.push(input.begin(), input.begin() + 2), std::out_of_range);

    ASSERT_EQ(encoder.size(), 4);

    encoder.push<uint8_t>(1);
    ASSERT_THROW(encoder.push(input.begin(), input.begin() + 1), std::out_of_range);
    ASSERT_THROW(encoder.push(input.begin(), input.begin() + 2), std::out_of_range);
}

TEST(range_encoder, insert_blob)
{
    std::array<uint8_t, 4> input{10, 20, 30, 50};
    std::array<uint8_t, 5> data{0, 0, 0, 0, 0};

    pgp::range_encoder encoder{data};
    encoder.insert_blob(pgp::span<const uint8_t>());
    ASSERT_EQ(encoder.size(), 0);

    encoder.insert_blob(pgp::span<const uint8_t>(input.data(), input.data() + 3));
    ASSERT_EQ(encoder.size(), 3);
    ASSERT_EQ(pgp::span(input.data(), input.data() + 3), pgp::span(data.data(), data.data() + 3));
    ASSERT_EQ(data[3], 0);

    encoder.insert_blob(pgp::span<const uint8_t>(input.data() + 3, input.data() + 4));
    ASSERT_EQ(pgp::span<const uint8_t>(input), pgp::span<const uint8_t>(data.data(), data.data() + 4));

    ASSERT_THROW(encoder.insert_blob(pgp::span<const uint8_t>(input.data(), input.data() + 2)), std::out_of_range);

    encoder.push<uint8_t>(1);
    ASSERT_THROW(encoder.insert_blob(pgp::span<const uint8_t>(input.data(), input.data() + 1)), std::out_of_range);
    ASSERT_THROW(encoder.insert_blob(pgp::span<const uint8_t>(input.data(), input.data() + 2)), std::out_of_range);
}

TEST(range_encoder, insert_blob_bits)
{
    std::array<uint8_t, 2> input{10, 20};
    std::array<uint8_t, 5> data{0, 0, 0, 0, 0};

    pgp::range_encoder encoder{data};
    encoder.insert_bits(2, 0b11);
    // The first byte fits even after the queued bits, so the push should succeed
    encoder.insert_blob(pgp::span<const uint8_t>(input));

    encoder.insert_bits(6, 0);
    // Too many bits queued
    ASSERT_THROW(encoder.insert_blob(pgp::span<const uint8_t>(input)), std::range_error);
}

TEST(range_encoder, out_of_range)
{
    std::array<uint8_t, 5> data;
    pgp::range_encoder encoder{data};
    ASSERT_THROW(encoder.push(static_cast<uint64_t>(42)), std::out_of_range);
}

TEST(range_encoder, insert_bits)
{
    std::array<uint8_t, 2> data;
    pgp::range_encoder encoder{data};

    // Too many bits given
    ASSERT_THROW(encoder.insert_bits(7, 0b10101010), std::range_error);

    encoder.insert_bits(3, 0b101);
    encoder.insert_bits(3, 0b010);

    // Cannot cross byte boundaries
    ASSERT_THROW(encoder.insert_bits(3, 0b010), std::out_of_range);

    encoder.insert_bits(2, 0b10);
    ASSERT_EQ(data[0], 0b10101010);

    encoder.push<uint8_t>(1);

    // Out of buffer space
    ASSERT_THROW(encoder.insert_bits(1, 0b1), std::out_of_range);
}

TEST(range_encoder, insert_bits_byte_bounds)
{
    std::array<uint8_t, 1> data;
    pgp::range_encoder encoder{data};
    encoder.insert_bits(7, 0b101010);
    ASSERT_THROW(encoder.insert_bits(2, 0b00), std::out_of_range);
    encoder.insert_bits(1, 0b0);
}

TEST(range_encoder, flush)
{
    uint8_t initial_value = 0b10000001;
    std::array<uint8_t, 4> data{initial_value, initial_value, initial_value, initial_value};
    pgp::range_encoder encoder{data};

    encoder.insert_bits(3, 0b111);
    encoder.flush();
    ASSERT_EQ(data[0], 0b11100000);

    encoder.insert_bits(7, 0b1011011);
    encoder.insert_bits(1, 0b1);
    ASSERT_EQ(encoder.size(), 2);
    ASSERT_EQ(data[1], 0b10110111);

    // no-op flush
    encoder.flush();
    ASSERT_EQ(encoder.size(), 2);
    ASSERT_EQ(data[2], initial_value);

    encoder.push<uint16_t>(42);
    ASSERT_EQ(data[2], 0);
    ASSERT_EQ(data[3], 42);
}
