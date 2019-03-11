#include <vector>
#include <cstdint>
#include <gtest/gtest.h>
#include "../../gcrypt_encoder.h"
#include "../device_random_engine.h"


namespace {
    thread_local tests::device_random_engine random_engine;

    void random_vector(std::vector<uint8_t> &dest)
    {
        std::uniform_int_distribution<uint8_t> distr(0, 255);
        for (uint8_t &elem : dest) {
            elem = distr(random_engine);
        }
    }

    std::vector<uint8_t> random_vector(size_t size)
    {
        std::vector<uint8_t> v(size);
        random_vector(v);
        return v;
    }

    template <typename T>
    void deterministic_type()
    {
        std::uniform_int_distribution<size_t> length_distr(0, 10000);

        for (int i = 0; i < 10; i++) {
            std::vector<uint8_t> v{random_vector(length_distr(random_engine))};

            pgp::gcrypt_encoder<T> enc1;
            enc1.insert_blob(gsl::span<const uint8_t>(v));
            auto res1 = enc1.digest();

            pgp::gcrypt_encoder<T> enc2;
            enc2.insert_blob(gsl::span<const uint8_t>(v));
            auto res2 = enc2.digest();

            ASSERT_EQ(res1, res2);
        }
    }

    template <typename T>
    void push_equivalent()
    {
        std::vector<uint8_t> v(1234);
        std::uniform_int_distribution<int> push_distr(0, 2);

        pgp::gcrypt_encoder<T> enc1;
        enc1.push(v.begin(), v.end());
        auto res1 = enc1.digest();

        for (int i = 0; i < 100; i++) {
            pgp::gcrypt_encoder<T> enc;

            size_t cursor = 0;
            while (cursor < v.size()) {
                switch (push_distr(random_engine)) {
                    case 0:
                        enc.push(v[cursor]);
                        cursor++;
                        break;

                    case 1: {
                        std::uniform_int_distribution<size_t> sub_distr(0, v.size() - cursor);
                        size_t len = sub_distr(random_engine);
                        enc.push(v.begin() + cursor, v.begin() + cursor + len);
                        cursor += len;
                        break;
                    }

                    case 2: {
                        std::uniform_int_distribution<size_t> sub_distr(0, v.size() - cursor);
                        size_t len = sub_distr(random_engine);
                        enc.insert_blob(gsl::span<const uint8_t>(v.data() + cursor, v.data() + cursor + len));
                        cursor += len;
                        break;
                    }
                }
            }

            auto res2 = enc.digest();
            ASSERT_EQ(res1, res2);
        }
    }
}

TEST(gcrypt_encoder, deterministic)
{
    deterministic_type<pgp::gcrypt_sha1_encoding>();
    deterministic_type<pgp::gcrypt_sha256_encoding>();
}

TEST(gcrypt_encoder, push_equivalent)
{
    push_equivalent<pgp::gcrypt_sha1_encoding>();
    push_equivalent<pgp::gcrypt_sha256_encoding>();
}

TEST(gcrypt_encoder, push_enum)
{
    enum class enum_t {
        ITEM1,
        ITEM2,
        ITEM3,
    };

    pgp::gcrypt_encoder<pgp::gcrypt_sha1_encoding> enc1;
    enc1.push(enum_t::ITEM1);
    enc1.push(enum_t::ITEM2);
    enc1.push(enum_t::ITEM3);
    auto res1 = enc1.digest();

    using underlying = std::underlying_type_t<enum_t>;

    pgp::gcrypt_encoder<pgp::gcrypt_sha1_encoding> enc2;
    enc2.push(static_cast<underlying>(enum_t::ITEM1));
    enc2.push(static_cast<underlying>(enum_t::ITEM2));
    enc2.push(static_cast<underlying>(enum_t::ITEM3));
    auto res2 = enc2.digest();

    ASSERT_EQ(res1, res2);
}

TEST(gcrypt_encoder, different)
{
    auto v1 = random_vector(123);
    auto v2 = random_vector(123);

    ASSERT_NE(v1, v2);

    pgp::gcrypt_encoder<pgp::gcrypt_sha1_encoding> enc1;
    enc1.push(v1.begin(), v1.end());
    auto res1 = enc1.digest();

    pgp::gcrypt_encoder<pgp::gcrypt_sha1_encoding> enc2;
    enc2.push(v2.begin(), v2.end());
    auto res2 = enc2.digest();

    ASSERT_NE(res1, res2);
}
