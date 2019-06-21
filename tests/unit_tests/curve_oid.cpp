#include <stdexcept>
#include <array>
#include <vector>
#include <gtest/gtest.h>
#include "curve_oid.h"
#include "decoder.h"


TEST(curve_oid, size_preset_curves)
{
    auto ed_oid = pgp::curve_oid::ed25519();
    auto ed_data = ed_oid.data();

    size_t num_bytes = ed_data.size();

    ASSERT_EQ(ed_oid.size(), num_bytes + 1);

    std::vector<uint8_t> data(num_bytes + 1);
    data[0] = gsl::narrow_cast<uint8_t>(num_bytes);
    for (size_t i = 0; i < num_bytes; i++) {
        data[i + 1] = ed_data[i];
    }

    pgp::decoder decoder{data};
    pgp::curve_oid oid{decoder};
    ASSERT_EQ(oid, ed_oid);
    ASSERT_EQ(oid.data(), ed_data);
}

TEST(curve_oid, preset_curves)
{
    std::array<uint8_t, 9> ed25519{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01 };
    std::array<uint8_t, 10> curve_25519{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };

    ASSERT_EQ(pgp::curve_oid::ed25519().data(), pgp::span<const uint8_t>(ed25519));
    ASSERT_EQ(pgp::curve_oid::curve_25519().data(), pgp::span<const uint8_t>(curve_25519));
}

TEST(curve_oid, equality)
{
    ASSERT_NE(pgp::curve_oid::ed25519(), pgp::curve_oid::curve_25519());
}

TEST(curve_oid, other_data)
{
    std::array<uint8_t, 5> data{4, 1, 2, 3, 4};
    pgp::decoder decoder{data};
    pgp::curve_oid oid{decoder};

    ASSERT_EQ(pgp::span<const uint8_t>(data.data() + 1, data.data() + 5), oid.data());

    pgp::curve_oid oid2{data};
    ASSERT_EQ(pgp::span<const uint8_t>(data), oid2.data());
}
