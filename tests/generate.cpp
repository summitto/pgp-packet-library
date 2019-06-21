#include <sodium/randombytes.h>
#include "generate.h"


namespace tests::generate {
    namespace detail {
        thread_local device_random_engine random_engine;
    }

    pgp::multiprecision_integer mpi()
    {
        std::uniform_int_distribution<int> length_distr(1, 600);
        std::uniform_int_distribution<uint8_t> distr(0, 25);

        // select a random length
        int length = length_distr(detail::random_engine);

        // get random data with that length
        std::vector<uint8_t> data(length);
        for (uint8_t &elem : data) {
            elem = distr(detail::random_engine);
        }

        // put it in an MPI
        return pgp::multiprecision_integer{data};
    }

    pgp::curve_oid oid()
    {
        return random_choice<pgp::curve_oid>({
            pgp::curve_oid::ed25519(),
            pgp::curve_oid::curve_25519(),
        });
    }

    pgp::hash_algorithm hashalgo()
    {
        return random_choice<pgp::hash_algorithm>({
            pgp::hash_algorithm::md5,
            pgp::hash_algorithm::sha1,
            pgp::hash_algorithm::ripemd160,
            pgp::hash_algorithm::sha256,
            pgp::hash_algorithm::sha384,
            pgp::hash_algorithm::sha512,
            pgp::hash_algorithm::sha224,
        });
    }

    pgp::symmetric_key_algorithm keyalgo()
    {
        return random_choice<pgp::symmetric_key_algorithm>({
            pgp::symmetric_key_algorithm::plaintext,
            pgp::symmetric_key_algorithm::idea,
            pgp::symmetric_key_algorithm::triple_des,
            pgp::symmetric_key_algorithm::cast5,
            pgp::symmetric_key_algorithm::blowfish,
            pgp::symmetric_key_algorithm::aes128,
            pgp::symmetric_key_algorithm::aes192,
            pgp::symmetric_key_algorithm::aes256,
            pgp::symmetric_key_algorithm::twofish256,
            pgp::symmetric_key_algorithm::camellia128,
            pgp::symmetric_key_algorithm::camellia192,
            pgp::symmetric_key_algorithm::camellia256,
        });
    }

    namespace eddsa {
        std::tuple<
            pgp::secret_key,
            std::array<uint8_t, public_key_size>,
            std::array<uint8_t, secret_key_size>
        > key()
        {
            constexpr const std::array<uint8_t, 1> public_key_tag{0x40};
            constexpr const size_t public_key_size = public_key_tag.size() + crypto_sign_PUBLICKEYBYTES;
            constexpr const size_t secret_key_size = crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES;

            // containers for the libsodium-generated key data
            std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pubkey_sodium;
            std::array<uint8_t, crypto_sign_SECRETKEYBYTES> seckey_sodium;

            // generate the key pair
            randombytes_buf(pubkey_sodium.data(), pubkey_sodium.size());
            randombytes_buf(seckey_sodium.data(), seckey_sodium.size());
            crypto_sign_keypair(pubkey_sodium.data(), seckey_sodium.data());

            // convert to our format
            std::array<uint8_t, public_key_size> pubkey;
            std::array<uint8_t, secret_key_size> seckey;
            auto it = std::copy(public_key_tag.begin(), public_key_tag.end(), pubkey.begin());
            std::copy(pubkey_sodium.begin(), pubkey_sodium.end(), it);
            std::copy_n(seckey_sodium.begin(), seckey.size(), seckey.begin());

            // construct the secret_key object
            pgp::secret_key sk{
                1554106568,
                pgp::key_algorithm::eddsa,
                mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>(),
                std::make_tuple(
                    pgp::curve_oid::ed25519(),
                    pgp::multiprecision_integer(pubkey)
                ),
                std::make_tuple(pgp::multiprecision_integer(seckey))
            };

            return std::make_tuple(sk, pubkey, seckey);
        }
    }
}
