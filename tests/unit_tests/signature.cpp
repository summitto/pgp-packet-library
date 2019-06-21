#include <gtest/gtest.h>
#include <cryptopp/rsa.h>
#include "signature.h"
#include "../device_random_engine.h"


namespace {
    thread_local tests::device_random_engine random_engine;

    template <typename Key = pgp::secret_key>
    Key secret_key_1()
    {
        auto curve = pgp::curve_oid::ed25519();
        auto Q = pgp::multiprecision_integer{std::array<uint8_t, 8>{97, 34, 135, 227, 159, 215, 93, 229}};
        auto k = pgp::multiprecision_integer{std::array<uint8_t, 8>{228, 159, 246, 23, 20, 155, 206, 156}};

        return Key{
            12345678,
            pgp::key_algorithm::eddsa,
            mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>(),
            std::make_tuple(curve, Q), std::make_tuple(k)
        };
    }

    template <typename Key = pgp::secret_key>
    Key secret_key_2()
    {
        auto curve = pgp::curve_oid::curve_25519();
        auto Q = pgp::multiprecision_integer{std::array<uint8_t, 8>{205, 117, 106, 55, 92, 162, 221, 6}};
        auto k = pgp::multiprecision_integer{std::array<uint8_t, 8>{225, 138, 163, 90, 177, 224, 61, 100}};

        return Key{
            987654321,
            pgp::key_algorithm::eddsa,
            mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>(),
            std::make_tuple(curve, Q), std::make_tuple(k)
        };
    }

    template <typename Key = pgp::secret_key>
    Key secret_key_3()
    {
        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::RSA::PrivateKey private_key;
        private_key.GenerateRandomWithKeySize(prng, 2048);

        pgp::multiprecision_integer n = private_key.GetModulus();
        pgp::multiprecision_integer e = private_key.GetPublicExponent();

        pgp::multiprecision_integer d = private_key.GetPrivateExponent();
        pgp::multiprecision_integer p = private_key.GetPrime1();
        pgp::multiprecision_integer q = private_key.GetPrime2();
        pgp::multiprecision_integer u = private_key.GetMultiplicativeInverseOfPrime2ModPrime1();

        return Key{
            987654321,
            pgp::key_algorithm::rsa_encrypt_or_sign,
            mpark::in_place_type_t<pgp::secret_key::rsa_key_t>(),
            std::make_tuple(n, e), std::make_tuple(d, p, q, u)
        };
    }

    pgp::signature_subpacket_set generate_subpacket_set()
    {
        size_t num_packets = std::uniform_int_distribution<size_t>(0, 4)(random_engine);

        std::vector<pgp::signature_subpacket_set::subpacket_variant> packets;
        packets.reserve(num_packets);

        for (size_t i = 0; i < num_packets; i++) {
            switch (std::uniform_int_distribution(0, 6)(random_engine)) {
                case 0: packets.emplace_back(pgp::signature_subpacket::issuer{{1, 2, 3, 4}}); break;
                case 1: packets.emplace_back(pgp::signature_subpacket::signature_creation_time{1234}); break;
                case 2: packets.emplace_back(pgp::signature_subpacket::signature_expiration_time{8451632}); break;
                case 3: packets.emplace_back(pgp::signature_subpacket::exportable_certification{0xff}); break;
                case 4: packets.emplace_back(pgp::signature_subpacket::primary_user_id{0x12}); break;
                case 5: packets.emplace_back(pgp::signature_subpacket::key_expiration_time{99999}); break;
                case 6: packets.emplace_back(pgp::signature_subpacket::key_flags{0x37}); break;
            }
        }

        return pgp::signature_subpacket_set{packets};
    }

    enum class signature_hash_type {
        user_id,
        subkey_binding,
    };

    // Usefulness of this hashing reimplementation is questionable; it's
    // almost just copying the actual implementation. It does serve as a
    // regression test, though.
    template <signature_hash_type Type, typename... Args>
    pgp::uint16 signature_hash_reimplementation(
            const pgp::signature &sig,
            const pgp::signature_subpacket_set &hashedsubs,
            std::tuple<Args...> extra_args)
    {
        pgp::sha256_encoder hash_encoder;

        if constexpr (Type == signature_hash_type::user_id) {
            const auto &key = std::get<0>(extra_args);
            const auto &userid = std::get<1>(extra_args);

            key.hash(hash_encoder);
            hash_encoder.push<uint8_t>(0xb4);
            hash_encoder.push<uint32_t>(gsl::narrow_cast<uint32_t>(userid.size()));
            userid.encode(hash_encoder);
        } else if constexpr (Type == signature_hash_type::subkey_binding) {
            const auto &ownerkey = std::get<0>(extra_args);
            const auto &subkey = std::get<1>(extra_args);

            ownerkey.hash(hash_encoder);
            subkey.hash(hash_encoder);
        }

        hash_encoder.push(sig.version());
        hash_encoder.push(sig.type());
        hash_encoder.push(sig.public_key_algorithm());
        hash_encoder.push(sig.hashing_algorithm());
        hashedsubs.encode(hash_encoder);

        hash_encoder.push(sig.version());
        hash_encoder.push<uint8_t>(0xff);
        hash_encoder.push<uint32_t>(
            gsl::narrow_cast<uint32_t>(
                sizeof(sig.version()) +
                sizeof(sig.type()) +
                sizeof(sig.public_key_algorithm()) +
                sizeof(sig.hashing_algorithm()) +
                hashedsubs.size()
            )
        );

        auto digest = hash_encoder.digest();
        pgp::decoder decoder{digest};
        return pgp::uint16{decoder};
    }
}

TEST(signature, constructor_encode_decode)
{
    pgp::signature_type sigtype{pgp::signature_type::standalone};
    pgp::key_algorithm keyalgo{pgp::key_algorithm::rsa_sign_only};
    pgp::hash_algorithm hashalgo{pgp::hash_algorithm::sha256};
    pgp::signature_subpacket_set hashedsubs{{
        pgp::signature_subpacket::signature_creation_time{1234},
        pgp::signature_subpacket::signature_expiration_time{5678}
    }};
    pgp::signature_subpacket_set unhashedsubs{{
        pgp::signature_subpacket::issuer{{9, 8, 7, 6, 5, 4, 3, 2}}
    }};
    pgp::uint16 hash_prefix{0x1337};

    pgp::multiprecision_integer rsasig_arg{std::array<uint8_t, 8>{52, 3, 235, 53, 52, 35, 32, 35}};
    pgp::rsa_signature rsasig{rsasig_arg};

    pgp::signature sig{
        sigtype,
        keyalgo,
        hashalgo,
        hashedsubs,
        unhashedsubs,
        hash_prefix,
        mpark::in_place_type_t<pgp::rsa_signature>(),
        rsasig_arg
    };

    ASSERT_EQ(pgp::signature::tag(), pgp::packet_tag::signature);
    ASSERT_EQ(sig.version(), 4);
    ASSERT_EQ(sig.type(), sigtype);
    ASSERT_EQ(sig.public_key_algorithm(), keyalgo);
    ASSERT_EQ(sig.hashing_algorithm(), hashalgo);
    ASSERT_TRUE(sig.hashed_subpackets() == hashedsubs);
    ASSERT_TRUE(sig.unhashed_subpackets() == unhashedsubs);
    ASSERT_EQ(sig.hash_prefix(), hash_prefix);
    ASSERT_EQ(mpark::get<pgp::rsa_signature>(sig.data()).s().data(), rsasig.s().data());

    std::vector<uint8_t> data(2048);
    pgp::range_encoder encoder{data};
    sig.encode(encoder);

    ASSERT_EQ(encoder.size(), sig.size());
    data.resize(encoder.size());

    pgp::decoder decoder{data};
    pgp::signature sig2{decoder};

    ASSERT_EQ(sig, sig2);

    pgp::signature sig_modified{
        sigtype,
        keyalgo,
        hashalgo,
        {},
        {},
        hash_prefix,
        mpark::in_place_type_t<pgp::rsa_signature>(),
        rsasig_arg
    };
    ASSERT_NE(sig, sig_modified);
}

TEST(signature, constructor_user_id)
{
    using namespace std::literals;

    pgp::secret_key key{secret_key_1()};

    pgp::user_id userid{"some_username"s};
    auto hashedsubs = generate_subpacket_set();
    auto unhashedsubs = generate_subpacket_set();

    pgp::signature sig{
        key,
        userid,
        hashedsubs,
        unhashedsubs
    };

    ASSERT_EQ(sig.type(), pgp::signature_type::positive_user_id_and_public_key_certification);
    ASSERT_EQ(sig.public_key_algorithm(), key.algorithm());
    ASSERT_EQ(sig.hashing_algorithm(), pgp::hash_algorithm::sha256);
    ASSERT_TRUE(sig.hashed_subpackets() == hashedsubs);
    ASSERT_TRUE(sig.unhashed_subpackets() == unhashedsubs);

    pgp::uint16 hash_prefix{
        signature_hash_reimplementation<signature_hash_type::user_id>(
            sig,
            hashedsubs,
            std::make_tuple(key, userid)
        )
    };

    ASSERT_EQ(hash_prefix, sig.hash_prefix());
}

namespace {
    void constructor_subkey_test(pgp::secret_key &&ownerkey, pgp::secret_subkey &&subkey)
    {
        using namespace std::literals;

        auto hashedsubs = generate_subpacket_set();
        auto unhashedsubs = generate_subpacket_set();

        pgp::signature sig{
            ownerkey,
            subkey,
            hashedsubs,
            unhashedsubs
        };

        ASSERT_EQ(sig.type(), pgp::signature_type::subkey_binding);
        ASSERT_EQ(sig.public_key_algorithm(), ownerkey.algorithm());
        ASSERT_EQ(sig.hashing_algorithm(), pgp::hash_algorithm::sha256);
        ASSERT_TRUE(sig.hashed_subpackets() == hashedsubs);
        ASSERT_TRUE(sig.unhashed_subpackets() == unhashedsubs);

        pgp::uint16 hash_prefix{
            signature_hash_reimplementation<signature_hash_type::subkey_binding>(
                sig,
                hashedsubs,
                std::make_tuple(ownerkey, subkey)
            )
        };

        ASSERT_EQ(hash_prefix, sig.hash_prefix());
    }
}

TEST(signature, constructor_subkey)
{
    // Test all combinations
    constructor_subkey_test(secret_key_1(), secret_key_2<pgp::secret_subkey>());
    constructor_subkey_test(secret_key_1(), secret_key_3<pgp::secret_subkey>());
    constructor_subkey_test(secret_key_2(), secret_key_1<pgp::secret_subkey>());
    constructor_subkey_test(secret_key_2(), secret_key_3<pgp::secret_subkey>());
    constructor_subkey_test(secret_key_3(), secret_key_1<pgp::secret_subkey>());
    constructor_subkey_test(secret_key_3(), secret_key_2<pgp::secret_subkey>());
}
