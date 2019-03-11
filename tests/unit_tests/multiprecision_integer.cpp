#include <algorithm>
#include <gtest/gtest.h>
#include "../../multiprecision_integer.h"
#include "../../range_encoder.h"
#include "../../decoder.h"
#include "../../fixed_number.h"


TEST(multiprecision_integer, default_empty)
{
    pgp::multiprecision_integer mi;
    ASSERT_EQ(mi.size(), 2);  // to account for the bits field
    ASSERT_EQ(mi.data().size(), 0);
}

TEST(multiprecision_integer, decode)
{
    const auto big = boost::endian::native_to_big<uint8_t>;
    const std::array<uint8_t, 5> data{
        big(0), big(21),
        big(0x1f), big(0x13), big(0x37)
    };

    pgp::decoder decoder{data};
    pgp::multiprecision_integer mi1{decoder};

    pgp::multiprecision_integer mi2{gsl::span(data.data() + 2, 3)};
    ASSERT_EQ(mi1, mi2);
}

TEST(multiprecision_integer, equality)
{
    pgp::multiprecision_integer mi1{gsl::span<const uint8_t>{{1, 2, 3}}};
    pgp::multiprecision_integer mi2{gsl::span<const uint8_t>{{4, 5, 6}}};
    pgp::multiprecision_integer mi3{gsl::span<const uint8_t>{{1, 2}}};
    pgp::multiprecision_integer mi4{gsl::span<const uint8_t>{{1, 2, 3, 4}}};

    ASSERT_EQ(mi1, mi1);
    ASSERT_NE(mi1, mi2);
    ASSERT_NE(mi1, mi3);
    ASSERT_NE(mi1, mi4);
}

TEST(multiprecision_integer, computed_bits)
{
    std::array<uint8_t, 3> data;

    data[1] = 12;
    data[2] = 34;

    for (int zeros = 0; zeros <= 7; zeros++) {
        data[0] = 0xff >> zeros;

        pgp::multiprecision_integer mi{data};

        std::vector<uint8_t> dest(8);
        pgp::range_encoder encoder{dest};
        mi.encode(encoder);

        pgp::decoder decoder{dest};
        ASSERT_EQ(pgp::uint16(decoder), 8 - zeros + 16);
    }
}

TEST(multiprecision_integer, zero_stripping)
{
    std::array<uint8_t, 6> data;

    std::fill(data.begin(), data.end(), 0xff);

    for (size_t i = 0; i <= data.size(); i++) {
        if (i > 0) data[i - 1] = 0;

        pgp::multiprecision_integer mi(data);

        std::vector<uint8_t> dest(8);
        pgp::range_encoder encoder{dest};
        mi.encode(encoder);

        pgp::decoder decoder{dest};
        ASSERT_EQ(pgp::uint16{decoder}, 8 * (data.size() - i));
    }
}
