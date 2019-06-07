#pragma once

#include "symmetric_key_algorithm.h"
#include "multiprecision_integer.h"
#include "device_random_engine.h"
#include <sodium/crypto_sign.h>
#include "hash_algorithm.h"
#include "secret_key.h"
#include "curve_oid.h"
#include <vector>
#include <random>


namespace tests::generate {
    namespace detail {
        extern thread_local device_random_engine random_engine;
    }

    template <typename T>
    T random_choice(std::vector<T> options)
    {
        std::uniform_int_distribution<size_t> distr(0, options.size() - 1);
        return options[distr(detail::random_engine)];
    }

    pgp::multiprecision_integer mpi();

    pgp::curve_oid oid();

    pgp::hash_algorithm hashalgo();

    pgp::symmetric_key_algorithm keyalgo();

    namespace eddsa {
        constexpr const std::array<uint8_t, 1> public_key_tag{0x40};
        constexpr const size_t public_key_size = public_key_tag.size() + crypto_sign_PUBLICKEYBYTES;
        constexpr const size_t secret_key_size = crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES;

        /**
         *  Generate an EDDSA secret key.
         *
         *  @return  The secret key, as well as the public and secret key data.
         */
        std::tuple<
            pgp::secret_key,
            std::array<uint8_t, public_key_size>,
            std::array<uint8_t, secret_key_size>
        > key();
    }
}
