#include <gtest/gtest.h>
#include "signature_subpacket/embedded.h"
#include <sodium/randombytes.h>
#include "range_encoder.h"
#include "signature.h"
#include "generate.h"
#include "decoder.h"


namespace {
    pgp::signature make_unknown_signature(uint16_t hash_prefix) {
        return pgp::signature{
            pgp::signature_type::standalone,
            pgp::key_algorithm::dsa,
            pgp::hash_algorithm::sha1,
            pgp::signature_subpacket_set{},
            pgp::signature_subpacket_set{},
            hash_prefix,
            pgp::in_place_type_t<pgp::unknown_signature>{}
        };
    }

    pgp::signature make_eddsa_signature() {
        pgp::secret_key sk = std::get<0>(tests::generate::eddsa::key());

        std::array<uint8_t, 32> message;
        randombytes_buf(message.data(), message.size());

        pgp::eddsa_signature::encoder_t sig_encoder{sk};
        sig_encoder.insert_blob(pgp::span<const uint8_t>{message});
        auto eddsa_sig = util::make_from_tuple<pgp::eddsa_signature>(sig_encoder.finalize());

        return pgp::signature{
            pgp::signature_type::standalone,
            pgp::key_algorithm::eddsa,
            pgp::hash_algorithm::sha256,
            pgp::signature_subpacket_set{},
            pgp::signature_subpacket_set{},
            0x1234,
            pgp::in_place_type_t<pgp::eddsa_signature>{},
            eddsa_sig
        };
    }
}


TEST(signature_subpacket_embedded, equality)
{
    pgp::signature s1{make_unknown_signature(0x1234)};
    pgp::signature s2{make_unknown_signature(0x4321)};

    pgp::signature_subpacket::embedded_signature p1{s1};
    pgp::signature_subpacket::embedded_signature p2{s2};

    ASSERT_EQ(p1, p1);
    ASSERT_NE(p1, p2);
}

TEST(signature_subpacket_embedded, copy)
{
    pgp::signature s1{make_unknown_signature(0x1234)};
    pgp::signature s2{make_unknown_signature(0x4321)};

    pgp::signature_subpacket::embedded_signature p1{s1};
    pgp::signature_subpacket::embedded_signature p2{s2};

    auto p1copy{p1};

    ASSERT_EQ(p1, p1copy);
    ASSERT_NE(p1copy, p2);

    p2 = p1copy;
    ASSERT_EQ(p1copy, p2);
    ASSERT_EQ(p2.contained(), s1);
}

TEST(signature_subpacket_embedded, move)
{
    pgp::signature s1{make_unknown_signature(0x1111)};

    pgp::signature_subpacket::embedded_signature p1{s1};

    auto p1copy{p1};

    auto p1move{std::move(p1)};
    ASSERT_THROW(p1.contained(), std::runtime_error);
    ASSERT_EQ(p1move, p1copy);
    ASSERT_EQ(p1move.contained(), s1);

    pgp::signature_subpacket::embedded_signature p2{make_unknown_signature(0xffff)};
    p2 = p1move;

    ASSERT_EQ(p1move, p2);
    ASSERT_EQ(p2.contained(), s1);
}

TEST(signature_subpacket_embedded, encode_decode)
{
    // we need an actual signature here, because we need a size()
    pgp::signature s1{make_eddsa_signature()};

    pgp::signature_subpacket::embedded_signature p1{s1};

    std::vector<uint8_t> data(1024);
    pgp::range_encoder encoder{data};

    p1.encode(encoder);
    ASSERT_EQ(p1.size(), encoder.size());

    data.resize(encoder.size());

    pgp::decoder decoder{data};

    pgp::variable_number dec_size{decoder};
    ASSERT_EQ(dec_size + dec_size.size(), p1.size());

    pgp::signature_subpacket_type type{decoder.extract_number<uint8_t>()};
    ASSERT_EQ(type, pgp::signature_subpacket_type::embedded_signature);

    pgp::signature_subpacket::embedded_signature p2{decoder};

    ASSERT_EQ(p2, p1);
    ASSERT_EQ(p1.contained(), s1);
}

TEST(signature_subpacket_embedded, decode_throw)
{
    pgp::signature s1{make_eddsa_signature()};
    pgp::signature_subpacket::embedded_signature p1{s1};

    std::vector<uint8_t> data(p1.size() + 1);
    pgp::range_encoder encoder{data};

    p1.encode(encoder);
    ASSERT_EQ(encoder.size(), data.size() - 1);

    pgp::decoder decoder{data};
    pgp::variable_number dec_size{decoder};  // Ignore the size
    decoder.extract_number<uint8_t>();  // Ignore the type

    // Decode with long input throws error because parser is not exhausted
    ASSERT_THROW(pgp::signature_subpacket::embedded_signature{decoder}, std::runtime_error);
}
