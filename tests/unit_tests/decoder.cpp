#include <stdexcept>
#include <array>
#include <boost/endian/conversion.hpp>
#include <gtest/gtest.h>
#include "../../decoder.h"


TEST(decoder, extract_bits)
{
    // DeBruijn sequence B(2, 7): every sequence of 7 bits occurs
    const auto big = boost::endian::native_to_big<uint8_t>;
    const std::array<uint8_t, 16> data{
        big(0b10000000), big(0b01100000), big(0b00101000), big(0b00011100),
        big(0b10001001), big(0b11000110), big(0b11100010), big(0b11001001),
        big(0b01010100), big(0b00111010), big(0b10011011), big(0b11001011),
        big(0b01010111), big(0b11101011), big(0b11101101), big(0b11111110)
    };

    size_t bit_index = 0;

    const auto get_next_bit = [&data, &bit_index]() -> bool {
        // Assuming we're on a little endian machine, we need to perform big-to-little conversion.
        int index_in_byte = 7 - bit_index % 8;

        uint8_t byte = boost::endian::big_to_native(data.at(bit_index / 8));
        bool res = byte & (1 << index_in_byte);
        bit_index++;
        return res;
    };

    pgp::decoder decoder{data};
    ASSERT_FALSE(decoder.empty());
    ASSERT_EQ(decoder.size(), data.size());

    for (size_t i = 0; i < 8 * data.size(); i++) {
        ASSERT_EQ(decoder.extract_bits(1), get_next_bit());
        ASSERT_EQ(decoder.empty(), i + 1 == 8 * data.size());
        ASSERT_EQ(decoder.size(), data.size() - (i + 1) / 8);
    }

    ASSERT_THROW(decoder.extract_bits(1), std::out_of_range);
}

TEST(decoder, extract_number)
{
    const auto big = boost::endian::native_to_big<uint8_t>;
    const std::array<uint8_t, 9> data{
        big(0x12), big(0x34), big(0x56), big(0x78),
        big(0x9a), big(0xbc), big(0xde), big(0xf0),
        big(0x42)
    };

    pgp::decoder decoder{data};
    ASSERT_EQ(decoder.extract_bits(3), 0b000);
    ASSERT_EQ(decoder.peek_number<uint8_t>(), 0x12);

    ASSERT_EQ(decoder.extract_bits(2), 0b10);

    ASSERT_EQ(decoder.peek_number<uint8_t>(), 0x02);
    ASSERT_EQ(decoder.peek_number<uint16_t>(), 0x0234);
    ASSERT_EQ(decoder.peek_number<uint32_t>(), 0x02345678);
    ASSERT_EQ(decoder.peek_number<uint64_t>(), 0x023456789abcdef0);

    ASSERT_EQ(decoder.extract_number<uint8_t>(), 0x02);

    ASSERT_EQ(decoder.peek_number<uint8_t>(), 0x34);
    ASSERT_EQ(decoder.peek_number<uint16_t>(), 0x3456);
    ASSERT_EQ(decoder.peek_number<uint32_t>(), 0x3456789a);
    ASSERT_EQ(decoder.peek_number<uint64_t>(), 0x3456789abcdef042);

    decoder.extract_number<uint8_t>();
    ASSERT_THROW(decoder.peek_number<uint64_t>(), std::out_of_range);
}

TEST(decoder, extract_blob)
{
    const auto big = boost::endian::native_to_big<uint8_t>;
    const std::array<uint8_t, 4> data{
        big(0x12), big(0x34), big(0x56), big(0x78)
    };

    {
        pgp::decoder decoder{data};
        ASSERT_EQ(decoder.extract_blob<uint8_t>(2), gsl::span(data.data(), 2));
    }

    pgp::decoder decoder{data};
    decoder.extract_number<uint8_t>();
    ASSERT_EQ(decoder.extract_blob<uint8_t>(2), gsl::span(data.data() + 1, 2));
}

TEST(decoder, splice)
{
    const auto big = boost::endian::native_to_big<uint8_t>;
    const std::array<uint8_t, 4> data{
        big(0x12), big(0x34), big(0x56), big(0x78)
    };

    pgp::decoder decoder{data};
    ASSERT_THROW(decoder.splice(5), std::out_of_range);

    pgp::decoder subdec{decoder.splice(3)};
    ASSERT_EQ(subdec.extract_number<uint16_t>(), 0x1234);
    ASSERT_EQ(subdec.extract_number<uint8_t>(), 0x56);
    ASSERT_TRUE(subdec.empty());

    ASSERT_EQ(decoder.extract_number<uint8_t>(), 0x78);
    ASSERT_TRUE(decoder.empty());
}
