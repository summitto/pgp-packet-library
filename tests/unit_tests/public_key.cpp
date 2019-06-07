#include <gtest/gtest.h>
#include "../key_template.h"
#include "public_key.h"
#include "range_encoder.h"
#include "decoder.h"


TEST(public_key, constructor)
{
    auto n = tests::generate::mpi();
    auto e = tests::generate::mpi();

    pgp::public_key k{
        1234,
        pgp::key_algorithm::rsa_encrypt_or_sign,
        mpark::in_place_type_t<pgp::public_key::rsa_key_t>(),
        n, e
    };

    ASSERT_EQ(k.tag(), pgp::packet_tag::public_key);
    ASSERT_EQ(k.creation_time(), 1234);
    ASSERT_EQ(k.algorithm(), pgp::key_algorithm::rsa_encrypt_or_sign);
    auto &keyval = mpark::get<pgp::public_key::rsa_key_t>(k.key());
    ASSERT_EQ(keyval.n().data(), n.data());
    ASSERT_EQ(keyval.e().data(), e.data());
}

TEST(public_key, encode_decode)
{
    auto p = tests::generate::mpi();
    auto q = tests::generate::mpi();
    auto g = tests::generate::mpi();
    auto y = tests::generate::mpi();

    pgp::public_key k{
        5678,
        pgp::key_algorithm::dsa,
        mpark::in_place_type_t<pgp::public_key::dsa_key_t>(),
        p, q, g, y
    };

    std::vector<uint8_t> data(2048);
    pgp::range_encoder encoder{data};
    k.encode(encoder);

    ASSERT_EQ(encoder.size(), k.size());
    data.resize(encoder.size());

    pgp::decoder decoder{data};
    pgp::public_key k2{decoder};

    ASSERT_EQ(k, k2);
}

TEST(public_key, equality)
{
    auto n = tests::generate::mpi();
    auto e = tests::generate::mpi();

    pgp::public_key k{
        1234,
        pgp::key_algorithm::rsa_encrypt_or_sign,
        mpark::in_place_type_t<pgp::public_key::rsa_key_t>(),
        n, e
    };

    pgp::public_key k2{
        4321,
        pgp::key_algorithm::rsa_encrypt_or_sign,
        mpark::in_place_type_t<pgp::public_key::rsa_key_t>(),
        n, e
    };

    pgp::public_key k3{
        1234,
        pgp::key_algorithm::rsa_sign_only,
        mpark::in_place_type_t<pgp::public_key::rsa_key_t>(),
        n, e
    };

    pgp::multiprecision_integer n2;
    do n2 = tests::generate::mpi();
    while (n2 == n);

    pgp::public_key k4{
        1234,
        pgp::key_algorithm::rsa_encrypt_or_sign,
        mpark::in_place_type_t<pgp::public_key::rsa_key_t>(),
        n2, e
    };

    ASSERT_EQ(k, k);
    ASSERT_NE(k, k2);
    ASSERT_NE(k, k3);
    ASSERT_NE(k, k4);
}

TEST(public_key, fingerprint)
{
    std::array<uint8_t, 8> qdata{1, 2, 4, 8, 3, 143, 32, 92};

    pgp::curve_oid               oid      {pgp::curve_oid::ed25519()};
    pgp::multiprecision_integer  Q        {qdata};
    pgp::hash_algorithm          hashalgo {pgp::hash_algorithm::sha1};
    pgp::symmetric_key_algorithm keyalgo  {pgp::symmetric_key_algorithm::aes256};

    pgp::public_key k{
        1554103728,
        pgp::key_algorithm::ecdh,
        mpark::in_place_type_t<pgp::public_key::ecdh_key_t>(),
        oid, Q, hashalgo, keyalgo
    };

    std::array<uint8_t, 8> expected = {0x3e, 0xb9, 0x45, 0xeb, 0x87, 0x7e, 0xbe, 0x0d};
    ASSERT_EQ(k.key_id(), expected);
}
