#include <array>
#include <gtest/gtest.h>
#include "../../../signature_subpacket/issuer_fingerprint.h"
#include "../../../range_encoder.h"
#include "../../../decoder.h"


TEST(signature_subpacket_issuer_fingerprint, constructors)
{
    std::array<uint8_t, 21> data{
        4,
        65, 8, 7, 2, 6, 8, 5, 8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 45, 64, 97
    };

    std::array<uint8_t, 20> bare_data;
    std::copy(std::next(std::begin(data), 1), std::end(data), std::begin(bare_data));

    pgp::decoder decoder{data};
    pgp::signature_subpacket::issuer_fingerprint p1{decoder};

    pgp::signature_subpacket::issuer_fingerprint p2{bare_data};

    ASSERT_EQ(p1.data(), p2.data());
}

TEST(signature_subpacket_issuer_fingerprint, encode_decode)
{
    std::array<uint8_t, 20> bare_data{
        23, 85, 65, 89, 12, 2, 10, 63, 7, 4, 1, 5, 8, 9, 6, 3, 2, 31, 64, 79
    };
    pgp::signature_subpacket::issuer_fingerprint p1{bare_data};

    // First encode the data
    std::array<uint8_t, 25> enc;
    pgp::range_encoder encoder{enc};
    p1.encode(encoder);

    ASSERT_EQ(encoder.size(), p1.size());

    // Then try to decode it again
    pgp::decoder decoder{enc};
    pgp::variable_number dec_size{decoder};
    // one extra for the type tag, one extra for the key version
    ASSERT_EQ(dec_size, 1 + 1 + bare_data.size());

    pgp::signature_subpacket_type type{decoder.extract_number<uint8_t>()};
    ASSERT_EQ(type, pgp::signature_subpacket_type::issuer_fingerprint);

    pgp::signature_subpacket::issuer_fingerprint p2{decoder};
    ASSERT_EQ(p1.data(), p2.data());
    ASSERT_EQ(p1, p2);

    // check whether operator!= works
    std::array<uint8_t, 20> other_data;
    std::fill(std::begin(other_data), std::end(other_data), 1);
    pgp::signature_subpacket::issuer_fingerprint p3{other_data};
    ASSERT_NE(p1, p3);
}

TEST(signature_subpacket_issuer_fingerprint, type)
{
    ASSERT_EQ(pgp::signature_subpacket::issuer_fingerprint::type(), pgp::signature_subpacket_type::issuer_fingerprint);
}
