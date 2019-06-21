#include <gtest/gtest.h>
#include "../key_template.h"
#include "secret_key.h"
#include "range_encoder.h"
#include "decoder.h"


TEST(secret_key, constructor)
{
    auto n = tests::generate::mpi();
    auto e = tests::generate::mpi();
    auto d = tests::generate::mpi();
    auto p = tests::generate::mpi();
    auto q = tests::generate::mpi();
    auto u = tests::generate::mpi();

    pgp::secret_key k{
        1234,
        pgp::key_algorithm::rsa_encrypt_or_sign,
        pgp::in_place_type_t<pgp::secret_key::rsa_key_t>(),
        std::make_tuple(n, e), std::make_tuple(d, p, q, u)
    };

    ASSERT_EQ(k.tag(), pgp::packet_tag::secret_key);
    ASSERT_EQ(k.creation_time(), 1234);
    ASSERT_EQ(k.algorithm(), pgp::key_algorithm::rsa_encrypt_or_sign);
    auto &keyval = pgp::get<pgp::secret_key::rsa_key_t>(k.key());
    ASSERT_EQ(keyval.n().data(), n.data());
    ASSERT_EQ(keyval.e().data(), e.data());
    ASSERT_EQ(keyval.d().data(), d.data());
    ASSERT_EQ(keyval.p().data(), p.data());
    ASSERT_EQ(keyval.q().data(), q.data());
    ASSERT_EQ(keyval.u().data(), u.data());
}

TEST(secret_key, encode_decode)
{
    auto p = tests::generate::mpi();
    auto q = tests::generate::mpi();
    auto g = tests::generate::mpi();
    auto y = tests::generate::mpi();
    auto x = tests::generate::mpi();

    pgp::secret_key k{
        5678,
        pgp::key_algorithm::dsa,
        pgp::in_place_type_t<pgp::secret_key::dsa_key_t>(),
        std::make_tuple(p, q, g, y), std::make_tuple(x)
    };

    std::vector<uint8_t> data(4096);
    pgp::range_encoder encoder{data};
    k.encode(encoder);

    ASSERT_EQ(encoder.size(), k.size());
    data.resize(encoder.size());

    pgp::decoder decoder{data};
    pgp::secret_key k2{decoder};

    ASSERT_EQ(k, k2);
}

TEST(secret_key, equality)
{
    auto n = tests::generate::mpi();
    auto e = tests::generate::mpi();
    auto d = tests::generate::mpi();
    auto p = tests::generate::mpi();
    auto q = tests::generate::mpi();
    auto u = tests::generate::mpi();

    pgp::secret_key k{
        1234,
        pgp::key_algorithm::rsa_encrypt_or_sign,
        pgp::in_place_type_t<pgp::secret_key::rsa_key_t>(),
        std::make_tuple(n, e), std::make_tuple(d, p, q, u)
    };

    pgp::secret_key k2{
        4321,
        pgp::key_algorithm::rsa_encrypt_or_sign,
        pgp::in_place_type_t<pgp::secret_key::rsa_key_t>(),
        std::make_tuple(n, e), std::make_tuple(d, p, q, u)
    };

    pgp::secret_key k3{
        1234,
        pgp::key_algorithm::rsa_sign_only,
        pgp::in_place_type_t<pgp::secret_key::rsa_key_t>(),
        std::make_tuple(n, e), std::make_tuple(d, p, q, u)
    };

    pgp::multiprecision_integer n2;
    do n2 = tests::generate::mpi();
    while (n2 == n);

    pgp::secret_key k4{
        1234,
        pgp::key_algorithm::rsa_encrypt_or_sign,
        pgp::in_place_type_t<pgp::secret_key::rsa_key_t>(),
        std::make_tuple(n2, e), std::make_tuple(d, p, q, u)
    };

    ASSERT_EQ(k, k);
    ASSERT_NE(k, k2);
    ASSERT_NE(k, k3);
    ASSERT_NE(k, k4);
}

TEST(secret_key, fingerprint)
{
    std::array<uint8_t, 8> qdata{1, 2, 4, 8, 3, 143, 32, 92};
    std::array<uint8_t, 8> kdata{65, 8, 5, 131, 8, 5, 31, 8};

    pgp::curve_oid               oid      {pgp::curve_oid::ed25519()};
    pgp::multiprecision_integer  Q        {qdata};
    pgp::hash_algorithm          hashalgo {pgp::hash_algorithm::sha1};
    pgp::symmetric_key_algorithm keyalgo  {pgp::symmetric_key_algorithm::aes256};
    pgp::multiprecision_integer  kparam   {kdata};

    pgp::secret_key k{
        1554103729,
        pgp::key_algorithm::ecdh,
        pgp::in_place_type_t<pgp::secret_key::ecdh_key_t>(),
        std::make_tuple(oid, Q, hashalgo, keyalgo), std::make_tuple(kparam)
    };

    std::array<uint8_t, 8> expected = {0x1b, 0x98, 0x5c, 0x78, 0x29, 0xa5, 0xcc, 0x81};
    ASSERT_EQ(k.key_id(), expected);
}
