#include <gtest/gtest.h>
#include "../../signature.h"
#include "../device_random_engine.h"


namespace {
    thread_local tests::device_random_engine random_engine;

    template <typename Key = pgp::secret_key>
    Key secret_key_1()
    {
        auto curve = pgp::curve_oid::ed25519();
        auto Q = pgp::multiprecision_integer{gsl::span<const uint8_t>({97, 34, 135, 227, 159, 215, 93, 229})};
        auto k = pgp::multiprecision_integer{gsl::span<const uint8_t>({228, 159, 246, 23, 20, 155, 206, 156})};

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
        auto Q = pgp::multiprecision_integer{gsl::span<const uint8_t>({205, 117, 106, 55, 92, 162, 221, 6})};
        auto k = pgp::multiprecision_integer{gsl::span<const uint8_t>({225, 138, 163, 90, 177, 224, 61, 100})};

        return Key{
            987654321,
            pgp::key_algorithm::eddsa,
            mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>(),
            std::make_tuple(curve, Q), std::make_tuple(k)
        };
    }

    pgp::signature_subpacket_set generate_subpacket_set()
    {
        size_t num_packets = std::uniform_int_distribution<size_t>(0, 4)(random_engine);

        std::vector<pgp::signature_subpacket_set::subpacket_variant> packets;
        packets.reserve(num_packets);

        for (size_t i = 0; i < num_packets; i++) {
            switch (std::uniform_int_distribution(0, 6)(random_engine)) {
                case 0: packets.emplace_back(pgp::issuer_subpacket{{1, 2, 3, 4}}); break;
                case 1: packets.emplace_back(pgp::signature_creation_time_subpacket{1234}); break;
                case 2: packets.emplace_back(pgp::signature_expiration_time_subpacket{8451632}); break;
                case 3: packets.emplace_back(pgp::exportable_certification_subpacket{0xff}); break;
                case 4: packets.emplace_back(pgp::primary_user_id_subpacket{0x12}); break;
                case 5: packets.emplace_back(pgp::key_expiration_time_subpacket{99999}); break;
                case 6: packets.emplace_back(pgp::key_flags_subpacket{0x37}); break;
            }
        }

        return pgp::signature_subpacket_set{packets};
    }
}

TEST(signature, constructor_encode_decode)
{
    pgp::signature_type sigtype{pgp::signature_type::standalone};
    pgp::key_algorithm keyalgo{pgp::key_algorithm::rsa_sign_only};
    pgp::hash_algorithm hashalgo{pgp::hash_algorithm::sha256};
    pgp::signature_subpacket_set hashedsubs{{
        pgp::signature_creation_time_subpacket{1234},
        pgp::signature_expiration_time_subpacket{5678}
    }};
    pgp::signature_subpacket_set unhashedsubs{{
        pgp::issuer_subpacket{{9, 8, 7, 6, 5, 4, 3, 2}}
    }};
    pgp::uint16 hash_prefix{0x1337};

    pgp::multiprecision_integer rsasig_arg{gsl::span<const uint8_t>({52, 3, 235, 53, 52, 35, 32, 35})};
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

    // Usefulness of this hashing check is questionable; it's almost just
    // copying the implementation. It does serve as a regression test, though.
    pgp::gcrypt_encoder<pgp::gcrypt_sha256_encoding> hash_encoder;
    key.hash(hash_encoder);
    hash_encoder.push<uint8_t>(0xb4);
    hash_encoder.push<uint32_t>(gsl::narrow_cast<uint32_t>(userid.size()));
    userid.encode(hash_encoder);

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
    pgp::uint16 hash_prefix{decoder};

    // This is what it was all for
    ASSERT_EQ(hash_prefix, sig.hash_prefix());
}

TEST(signature, constructor_subkey)
{
    using namespace std::literals;

    pgp::secret_key ownerkey{secret_key_1()};
    pgp::secret_subkey subkey{secret_key_2<pgp::secret_subkey>()};

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

    // Usefulness of this hashing check is questionable; it's almost just
    // copying the implementation. It does serve as a regression test, though.
    pgp::gcrypt_encoder<pgp::gcrypt_sha256_encoding> hash_encoder;
    ownerkey.hash(hash_encoder);
    subkey.hash(hash_encoder);

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
    pgp::uint16 hash_prefix{decoder};

    // This is what it was all for
    ASSERT_EQ(hash_prefix, sig.hash_prefix());
}
