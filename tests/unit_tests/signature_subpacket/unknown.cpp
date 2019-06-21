#include <array>
#include <vector>
#include <gtest/gtest.h>
#include "signature_subpacket/unknown.h"
#include "range_encoder.h"
#include "decoder.h"


TEST(signature_subpacket_unknown, properties)
{
    auto type_1 = pgp::signature_subpacket_type::features;

    std::array<uint8_t, 10> data{1, 5, 3, 3, 7, 5, 3, 4, 3, 4};

    // Check that decoding and initializing with data is the same thing
    pgp::decoder decoder{data};
    pgp::signature_subpacket::unknown p1{type_1, decoder};
    pgp::signature_subpacket::unknown p2{type_1, data};

    ASSERT_EQ(p1.data(), p2.data());
    ASSERT_EQ(p1, p1);

    // Two extra bytes: one for the variable_number, one for the type tag
    ASSERT_EQ(p1.size(), 2 + data.size());
    ASSERT_EQ(p1.type(), type_1);

    // Check that encoding does something useful
    std::vector<uint8_t> encoded(20);
    pgp::range_encoder encoder{encoded};
    p1.encode(encoder);
    encoded.resize(encoder.size());

    ASSERT_EQ(encoded.size(), 2 + data.size());
    // The size tag is a variable_number, but for these small inputs it's just
    // 1 byte; note that the size reports the byte for the type as well
    ASSERT_EQ(encoded[0], 1 + data.size());
    ASSERT_EQ(encoded[1], static_cast<uint8_t>(type_1));
    ASSERT_EQ(
        (pgp::span<const uint8_t>{data.data(), util::narrow_cast<ptrdiff_t>(data.size())}),
        (pgp::span<const uint8_t>{encoded.data() + 2, util::narrow_cast<ptrdiff_t>(encoded.size() - 2)})
    );
}

TEST(signature_subpacket_unknown, equality)
{
    auto type_1 = pgp::signature_subpacket_type::features;

    pgp::signature_subpacket::unknown p1{type_1, std::array<uint8_t, 3>{10, 11, 12}};
    pgp::signature_subpacket::unknown p2{type_1, std::array<uint8_t, 3>{11, 11, 12}};
    pgp::signature_subpacket::unknown p3{type_1, std::array<uint8_t, 5>{10, 11, 12, 13, 14}};
    ASSERT_EQ(p1, p1);
    ASSERT_NE(p1, p2);
    ASSERT_NE(p1, p3);
}
