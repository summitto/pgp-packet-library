#include <array>
#include <gtest/gtest.h>
#include "user_id.h"
#include "decoder.h"
#include "range_encoder.h"


TEST(user_id, tag)
{
    using namespace std::literals;
    ASSERT_EQ(pgp::user_id(""s).tag(), pgp::packet_tag::user_id);
    ASSERT_EQ(pgp::user_id(pgp::span("abc")).tag(), pgp::packet_tag::user_id);
}

TEST(user_id, encode_decode)
{
    using namespace std::literals;
    pgp::user_id id1{"yellow submarine"s};
    ASSERT_EQ(id1.size(), 16);

    ASSERT_EQ(id1.id(), "yellow submarine");

    std::array<uint8_t, 16> data;
    pgp::range_encoder encoder{data};
    id1.encode(encoder);
    ASSERT_EQ(encoder.size(), 16);

    ASSERT_EQ(data[0], 'y');

    ASSERT_EQ(
        pgp::span<const uint8_t>(data),
        pgp::span<const uint8_t>((const uint8_t*)"yellow submarine", 16));

    pgp::decoder decoder{data};
    pgp::user_id id2{decoder};
    ASSERT_EQ(decoder.size(), 0);
    ASSERT_EQ(id2.id(), id1.id());

    ASSERT_EQ(id2, id1);

    pgp::user_id id3{"something else"s};
    ASSERT_NE(id1, id3);
}
