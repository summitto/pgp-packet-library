#include <stdexcept>
#include <array>
#include <vector>
#include <gtest/gtest.h>
#include "signature_subpacket_set.h"
#include "range_encoder.h"
#include "decoder.h"


namespace {
    pgp::signature_subpacket::issuer make_issuer_subpacket()
    {
        std::array<uint8_t, 8> data;
        for (size_t i = 0; i < 8; i++) data[i] = static_cast<uint8_t>(i * i + 3);
        return pgp::signature_subpacket::issuer{data};
    }

    pgp::signature_subpacket::primary_user_id make_PUID_subpacket()
    {
        return pgp::signature_subpacket::primary_user_id{42};
    }

    pgp::signature_subpacket::key_flags make_key_flags_subpacket()
    {
        return pgp::signature_subpacket::key_flags{0x2, 0x40};
    }
}

TEST(signature_subpacket_set, constructor)
{
    {
        pgp::signature_subpacket_set sss;
        // 2 for the size prefix
        ASSERT_EQ(sss.size(), 2);
    }

    {
        pgp::signature_subpacket::issuer          p1 = make_issuer_subpacket();
        pgp::signature_subpacket::primary_user_id p2 = make_PUID_subpacket();
        pgp::signature_subpacket::key_flags       p3 = make_key_flags_subpacket();
        pgp::signature_subpacket_set sss({p1, p2, p3});

        // 2 for the size prefix
        ASSERT_EQ(sss.size(), 2 + p1.size() + p2.size() + p3.size());

        ASSERT_EQ(mpark::get<pgp::signature_subpacket::issuer>(sss[0]), p1);
        ASSERT_EQ(mpark::get<pgp::signature_subpacket::primary_user_id>(sss[1]), p2);
        ASSERT_EQ(mpark::get<pgp::signature_subpacket::key_flags>(sss[2]), p3);

        // Test the equality operators
        pgp::signature_subpacket_set sss2({p2, p1, p3});
        ASSERT_NE(sss, sss2);
    }
}

TEST(signature_subpacket_set, iterators)
{
    pgp::signature_subpacket::issuer          p1 = make_issuer_subpacket();
    pgp::signature_subpacket::primary_user_id p2 = make_PUID_subpacket();
    pgp::signature_subpacket::key_flags       p3 = make_key_flags_subpacket();
    pgp::signature_subpacket_set sss({p1, p2, p3});

    ASSERT_EQ(mpark::get<pgp::signature_subpacket::issuer>(*sss.begin()), p1);
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::issuer>(*sss.cbegin()), p1);
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::key_flags>(*sss.rbegin()), p3);
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::key_flags>(*sss.crbegin()), p3);

    ASSERT_EQ(sss.begin() + 3, sss.end());
    ASSERT_EQ(sss.cbegin() + 3, sss.cend());
    ASSERT_EQ(sss.rbegin() + 3, sss.rend());
    ASSERT_EQ(sss.crbegin() + 3, sss.crend());
}

TEST(signature_subpacket_set, encode_decode)
{
    pgp::signature_subpacket::issuer          p1 = make_issuer_subpacket();
    pgp::signature_subpacket::primary_user_id p2 = make_PUID_subpacket();
    pgp::signature_subpacket::key_flags       p3 = make_key_flags_subpacket();
    pgp::signature_subpacket_set sss({p1, p2, p3});

    std::vector<uint8_t> data(64);
    pgp::range_encoder encoder{data};
    sss.encode(encoder);

    ASSERT_EQ(encoder.size(), sss.size());

    data.resize(sss.size());

    pgp::decoder decoder{data};
    pgp::signature_subpacket_set sss2{decoder};

    ASSERT_EQ(std::distance(sss2.begin(), sss2.end()), 3);
    ASSERT_EQ(sss2.size(), sss.size());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::issuer>(sss[0]).data(), p1.data());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::primary_user_id>(sss[1]).data(), p2.data());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::key_flags>(sss[2]) == p3, true);
}

TEST(signature_subpacket_set, decode_all)
{
    pgp::signature_subpacket::unknown                   p1{pgp::signature_subpacket_type::revocation_reason, {}};
    pgp::signature_subpacket::issuer                    p2{{1, 2, 3, 4, 5, 6, 7, 8}};
    pgp::signature_subpacket::signature_creation_time   p3{0x12345678};
    pgp::signature_subpacket::signature_expiration_time p4{0x12345678};
    pgp::signature_subpacket::exportable_certification  p5{0xf9};
    pgp::signature_subpacket::primary_user_id           p6{0xf9};
    pgp::signature_subpacket::key_expiration_time       p7{0x59165325};
    pgp::signature_subpacket::key_flags                 p8{0x12, 0x34};
    
    pgp::signature_subpacket_set sss{{p1, p2, p3, p4, p5, p6, p7, p8}};

    std::vector<uint8_t> data(sss.size());
    pgp::range_encoder encoder{data};
    sss.encode(encoder);

    pgp::decoder decoder{data};
    pgp::signature_subpacket_set sss2{decoder};

    ASSERT_EQ(mpark::get<pgp::signature_subpacket::unknown>(sss2[0]).type(), p1.type());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::issuer>(sss2[1]).type(), p2.type());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::signature_creation_time>(sss2[2]).type(), p3.type());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::signature_expiration_time>(sss2[3]).type(), p4.type());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::exportable_certification>(sss2[4]).type(), p5.type());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::primary_user_id>(sss2[5]).type(), p6.type());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::key_expiration_time>(sss2[6]).type(), p7.type());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::key_flags>(sss2[7]).type(), p8.type());
}

TEST(signature_subpacket_set, data)
{
    pgp::signature_subpacket::issuer          p1 = make_issuer_subpacket();
    pgp::signature_subpacket::primary_user_id p2 = make_PUID_subpacket();
    pgp::signature_subpacket::key_flags       p3 = make_key_flags_subpacket();
    pgp::signature_subpacket_set sss({p1, p2, p3});

    // Note the extra .data() calls on sss
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::issuer>(sss.data()[0]).data(), p1.data());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::primary_user_id>(sss.data()[1]).data(), p2.data());
    ASSERT_EQ(mpark::get<pgp::signature_subpacket::key_flags>(sss.data()[2]) == p3, true);
}
