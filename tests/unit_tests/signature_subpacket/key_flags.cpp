#include <array>
#include <gtest/gtest.h>
#include "signature_subpacket/key_flags.h"
#include "range_encoder.h"


TEST(signature_subpacket_key_flags, variadic_constructor)
{
    uint8_t a = 0x1, b = 0x4, c = 0x80;
    pgp::signature_subpacket::key_flags packet(a, b, c);
    ASSERT_TRUE(packet.is_set(0x1));
    ASSERT_TRUE(packet.is_set(0x4));
    ASSERT_TRUE(packet.is_set(0x80));
}

TEST(signature_subpacket_key_flags, type)
{
    ASSERT_EQ(pgp::signature_subpacket::key_flags::type(), pgp::signature_subpacket_type::key_flags);
}

TEST(signature_subpacket_key_flags, faithful_encoding)
{
    for (int i = 0; i < 256; i++) {
        pgp::signature_subpacket::key_flags packet{static_cast<uint8_t>(i)};

        // For flags fields of at most 191 bytes, the packet length will be 3;
        // this is true for the forseeable future.
        ASSERT_EQ(packet.size(), 3);

        // Encode it to 'data'
        std::array<uint8_t, 3> data;
        pgp::range_encoder encoder{data};
        packet.encode(encoder);

        ASSERT_EQ(encoder.size(), packet.size());

        // Decode it from 'data'; extract the packet type and length outside the class
        pgp::decoder decoder{data};

        pgp::uint8 decoded_length{decoder};
        ASSERT_EQ(decoded_length, 2);  // type + flags

        pgp::signature_subpacket_type decoded_type{decoder.extract_number<uint8_t>()};
        ASSERT_EQ(decoded_type, pgp::signature_subpacket::key_flags::type());

        pgp::signature_subpacket::key_flags result{decoder};

        ASSERT_EQ(packet, result);
    }
}

TEST(signature_subpacket_key_flags, equality)
{
    pgp::signature_subpacket::key_flags p1{0x42};
    pgp::signature_subpacket::key_flags p2{0x43};

    ASSERT_EQ(p1, p1);
    ASSERT_NE(p1, p2);
}
