#include <vector>
#include <gtest/gtest.h>
#include "../../numeric_signature_subpacket.h"
#include "../../range_encoder.h"
#include "../../decoder.h"
#include "../device_random_engine.h"


namespace {
    thread_local tests::device_random_engine random_engine;

    template <typename T, typename Int>
    class TestFunctions {
    private:
        std::uniform_int_distribution<Int> distr;
        
    public:
        TestFunctions():
            distr{0, std::numeric_limits<Int>::max()}
        {}

        void test_constructors()
        {
            Int value{distr(random_engine)};

            std::vector<uint8_t> data(sizeof(Int));
            pgp::range_encoder int_encoder{data};
            int_encoder.push(value);

            data.resize(int_encoder.size());

            pgp::decoder decoder{data};
            T p1{decoder};

            T p2{value};

            ASSERT_EQ(p1.data(), p2.data());
        }

        void test_encode_decode()
        {
            Int value{distr(random_engine)};

            T p1{value};

            // First encode the data
            std::vector<uint8_t> enc(16);
            pgp::range_encoder encoder{enc};
            p1.encode(encoder);

            enc.resize(encoder.size());

            ASSERT_EQ(encoder.size(), p1.size());

            // Then try to decode it again
            pgp::decoder decoder{enc};
            pgp::variable_number dec_size{decoder};
            // one extra for the type tag
            ASSERT_EQ(dec_size, 1 + sizeof(Int));

            pgp::signature_subpacket_type type{decoder.extract_number<uint8_t>()};
            ASSERT_EQ(type, T::type());

            T p2{decoder};
            ASSERT_EQ(p1.data(), p2.data());
        }
    };
}

TEST(numeric_signature_subpacket, constructors)
{
    TestFunctions<pgp::key_expiration_time_subpacket, uint32_t>().test_constructors();
    TestFunctions<pgp::revocable_subpacket, uint8_t>().test_constructors();
}

TEST(numeric_signature_subpacket, encode_decode)
{
    TestFunctions<pgp::key_expiration_time_subpacket, uint32_t>().test_encode_decode();
    TestFunctions<pgp::revocable_subpacket, uint8_t>().test_encode_decode();
}

TEST(numeric_signature_subpacket, decode_throw)
{
    pgp::key_expiration_time_subpacket p1{42};

    std::vector<uint8_t> data(16);
    pgp::range_encoder encoder{data};
    p1.encode(encoder);

    data.resize(encoder.size());

    pgp::decoder decoder{data};
    pgp::variable_number dec_size{decoder};  // Ignore the size
    decoder.extract_number<uint8_t>();  // Ignore the type

    // Decode with shorter type throws error because parser is not exhausted
    ASSERT_THROW((pgp::revocable_subpacket(decoder)), std::runtime_error);
}
