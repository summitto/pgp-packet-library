#include <stdexcept>
#include <array>
#include <vector>
#include <gtest/gtest.h>
#include "../../signature_subpacket_set.h"
#include "../../range_encoder.h"
#include "../../decoder.h"


namespace {
    pgp::issuer_subpacket make_issuer_subpacket()
    {
        std::array<uint8_t, 8> data;
        for (size_t i = 0; i < 8; i++) data[i] = static_cast<uint8_t>(i * i + 3);
        return pgp::issuer_subpacket(data);
    }

    pgp::primary_user_id_subpacket make_PUID_subpacket()
    {
        return pgp::primary_user_id_subpacket(42);
    }

    pgp::key_flags_subpacket make_key_flags_subpacket()
    {
        return pgp::key_flags_subpacket(0x2, 0x40);
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
        pgp::issuer_subpacket p1 = make_issuer_subpacket();
        pgp::primary_user_id_subpacket p2 = make_PUID_subpacket();
        pgp::key_flags_subpacket p3 = make_key_flags_subpacket();
        pgp::signature_subpacket_set sss({p1, p2, p3});

        // 2 for the size prefix
        ASSERT_EQ(sss.size(), 2 + p1.size() + p2.size() + p3.size());

        ASSERT_EQ(mpark::get<pgp::issuer_subpacket>(sss[0]).data(), p1.data());
        ASSERT_EQ(mpark::get<pgp::primary_user_id_subpacket>(sss[1]).data(), p2.data());
        ASSERT_EQ(mpark::get<pgp::key_flags_subpacket>(sss[2]) == p3, true);
    }
}

TEST(signature_subpacket_set, iterators)
{
    pgp::issuer_subpacket p1 = make_issuer_subpacket();
    pgp::primary_user_id_subpacket p2 = make_PUID_subpacket();
    pgp::key_flags_subpacket p3 = make_key_flags_subpacket();
    pgp::signature_subpacket_set sss({p1, p2, p3});

    ASSERT_EQ(mpark::get<pgp::issuer_subpacket>(*sss.begin()).data(), p1.data());
    ASSERT_EQ(mpark::get<pgp::issuer_subpacket>(*sss.cbegin()).data(), p1.data());
    ASSERT_EQ(mpark::get<pgp::key_flags_subpacket>(*sss.rbegin()) == p3, true);
    ASSERT_EQ(mpark::get<pgp::key_flags_subpacket>(*sss.crbegin()) == p3, true);

    ASSERT_EQ(sss.begin() + 3, sss.end());
    ASSERT_EQ(sss.cbegin() + 3, sss.cend());
    ASSERT_EQ(sss.rbegin() + 3, sss.rend());
    ASSERT_EQ(sss.crbegin() + 3, sss.crend());
}

TEST(signature_subpacket_set, encode_decode)
{
    pgp::issuer_subpacket p1 = make_issuer_subpacket();
    pgp::primary_user_id_subpacket p2 = make_PUID_subpacket();
    pgp::key_flags_subpacket p3 = make_key_flags_subpacket();
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
    ASSERT_EQ(mpark::get<pgp::issuer_subpacket>(sss[0]).data(), p1.data());
    ASSERT_EQ(mpark::get<pgp::primary_user_id_subpacket>(sss[1]).data(), p2.data());
    ASSERT_EQ(mpark::get<pgp::key_flags_subpacket>(sss[2]) == p3, true);
}

TEST(signature_subpacket_set, decode_all)
{
    pgp::unknown_signature_subpacket p1 = pgp::unknown_signature_subpacket(pgp::signature_subpacket_type::fingerprint, {});
    pgp::issuer_subpacket p2 = pgp::issuer_subpacket({1, 2, 3, 4, 5, 6, 7, 8});
    pgp::signature_creation_time_subpacket p3 = pgp::signature_creation_time_subpacket(0x12345678);
    pgp::signature_expiration_time_subpacket p4 = pgp::signature_expiration_time_subpacket(0x12345678);
    pgp::exportable_certification_subpacket p5 = pgp::exportable_certification_subpacket(0xf9);
    pgp::primary_user_id_subpacket p6 = pgp::primary_user_id_subpacket(0xf9);
    pgp::key_expiration_time_subpacket p7 = pgp::key_expiration_time_subpacket(0x59165325);
    pgp::key_flags_subpacket p8 = pgp::key_flags_subpacket(0x12, 0x34);
    
    pgp::signature_subpacket_set sss({p1, p2, p3, p4, p5, p6, p7, p8});

    std::vector<uint8_t> data(sss.size());
    pgp::range_encoder encoder{data};
    sss.encode(encoder);

    pgp::decoder decoder{data};
    pgp::signature_subpacket_set sss2{decoder};

    ASSERT_EQ(mpark::get<pgp::unknown_signature_subpacket>(sss2[0]).type(), p1.type());
    ASSERT_EQ(mpark::get<pgp::issuer_subpacket>(sss2[1]).type(), p2.type());
    ASSERT_EQ(mpark::get<pgp::signature_creation_time_subpacket>(sss2[2]).type(), p3.type());
    ASSERT_EQ(mpark::get<pgp::signature_expiration_time_subpacket>(sss2[3]).type(), p4.type());
    ASSERT_EQ(mpark::get<pgp::exportable_certification_subpacket>(sss2[4]).type(), p5.type());
    ASSERT_EQ(mpark::get<pgp::primary_user_id_subpacket>(sss2[5]).type(), p6.type());
    ASSERT_EQ(mpark::get<pgp::key_expiration_time_subpacket>(sss2[6]).type(), p7.type());
    ASSERT_EQ(mpark::get<pgp::key_flags_subpacket>(sss2[7]).type(), p8.type());
}

TEST(signature_subpacket_set, data)
{
    pgp::issuer_subpacket p1 = make_issuer_subpacket();
    pgp::primary_user_id_subpacket p2 = make_PUID_subpacket();
    pgp::key_flags_subpacket p3 = make_key_flags_subpacket();
    pgp::signature_subpacket_set sss({p1, p2, p3});

    // Note the extra .data() calls on sss
    ASSERT_EQ(mpark::get<pgp::issuer_subpacket>(sss.data()[0]).data(), p1.data());
    ASSERT_EQ(mpark::get<pgp::primary_user_id_subpacket>(sss.data()[1]).data(), p2.data());
    ASSERT_EQ(mpark::get<pgp::key_flags_subpacket>(sss.data()[2]) == p3, true);
}
