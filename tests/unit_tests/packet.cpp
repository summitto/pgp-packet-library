#include <gtest/gtest.h>
#include "packet.h"
#include "range_encoder.h"
#include "decoder.h"
#include "../device_random_engine.h"


namespace {
    thread_local tests::device_random_engine random_engine;
}

TEST(packet, constructor)
{
    using namespace std::literals;

    pgp::packet packet(mpark::in_place_type_t<pgp::user_id>(), "another username"s);

    ASSERT_EQ(packet.tag(), pgp::packet_tag::user_id);
    ASSERT_EQ(mpark::get<pgp::user_id>(packet.body()).id(), "another username");
}

TEST(packet, encode_decode)
{
    std::uniform_int_distribution<size_t> distr(0, 1048576);

    auto test_for_size = [](size_t size) {
        std::string iddata(size, 'a');
        pgp::packet packet{mpark::in_place_type_t<pgp::user_id>(), iddata};

        std::vector<uint8_t> data(packet.size());
        pgp::range_encoder encoder{data};
        packet.encode(encoder);

        ASSERT_EQ(encoder.size(), data.size());

        pgp::decoder decoder{data};
        pgp::packet packet2{decoder};

        ASSERT_EQ(packet.tag(), packet2.tag());
        ASSERT_EQ(packet, packet2);
    };

    for (int i = 0; i < 100; i++) {
        test_for_size(distr(random_engine));
    }

    // Some boundary values
    test_for_size(0);  // zero is always a boundary value
    test_for_size(1);
    test_for_size(255);  // case boundary in (en,de)coding
    test_for_size(256);
    test_for_size(65535);  // case boundary in (en,de)coding
    test_for_size(65536);
    test_for_size(1048576);  // 2**20, some high value
    test_for_size(1048577);  // 2**20 + 1, some high value that isn't a power of 2
}

TEST(packet, decode_fail)
{
    std::array<uint8_t, 3> data{1, 2, 3};
    pgp::decoder decoder{data};
    ASSERT_THROW(pgp::packet{decoder}, std::runtime_error);
}

TEST(packet, equality)
{
    using namespace std::literals;

    pgp::packet p1{mpark::in_place_type_t<pgp::user_id>(), "abc"s};
    pgp::packet p2{mpark::in_place_type_t<pgp::user_id>(), "def"s};
    pgp::packet p3{mpark::in_place_type_t<pgp::unknown_packet>()};

    ASSERT_EQ(p1, p1);
    ASSERT_NE(p1, p2);
    ASSERT_NE(p1, p3);
}
