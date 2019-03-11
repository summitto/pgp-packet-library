#include <array>
#include <gtest/gtest.h>
#include "../../array_signature_subpacket.h"
#include "../../range_encoder.h"
#include "../../decoder.h"


TEST(array_signature_subpacket, issuer_constructors)
{
    std::array<uint8_t, 8> data{1, 2, 4, 8, 9, 13, 10, 42};

    pgp::decoder decoder{data};
    pgp::issuer_subpacket p1{decoder};

    pgp::issuer_subpacket p2{data};

    ASSERT_EQ(p1.data(), p2.data());
}

TEST(array_signature_subpacket, issuer_encode_decode)
{
    std::array<uint8_t, 8> data{1, 2, 65, 2, 6, 9, 9, 8};
    pgp::issuer_subpacket p1{data};

    // First encode the data
    std::array<uint8_t, 16> enc;
    pgp::range_encoder encoder{enc};
    p1.encode(encoder);

    ASSERT_EQ(encoder.size(), p1.size());

    // Then try to decode it again
    pgp::decoder decoder{enc};
    pgp::variable_number dec_size{decoder};
    // one extra for the type tag
    ASSERT_EQ(dec_size, 1 + data.size());

    pgp::signature_subpacket_type type{decoder.extract_number<uint8_t>()};
    ASSERT_EQ(type, pgp::issuer_subpacket::type());

    pgp::issuer_subpacket p2{decoder};
    ASSERT_EQ(p1.data(), p2.data());
}

TEST(array_signature_subpacket, issuer_type)
{
    ASSERT_EQ(pgp::issuer_subpacket::type(), pgp::signature_subpacket_type::issuer);
}
