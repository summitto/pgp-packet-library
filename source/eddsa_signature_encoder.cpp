#include "eddsa_signature_encoder.h"
#include <sodium/crypto_sign.h>
#include <cstdint>
#include <algorithm>
#include <array>
#include "util/span.h"


namespace pgp {

    /**
     *  Make the signature
     *
     *  @return Tuple of the r and s parameters for the EDDSA signature
     */
    std::tuple<multiprecision_integer, multiprecision_integer>
    eddsa_signature_encoder::finalize() noexcept
    {
        // the buffer for the signed message and the concatenated key
        std::array<uint8_t, crypto_sign_BYTES>  signed_message{};
        std::array<uint8_t, 64>                 key_data{};

        // retrieve the key data - ignore the silly leading byte from the public key
        auto public_data = eddsa_key.Q().data().subspan<1>();
        auto secret_data = eddsa_key.k().data();

        // make sure the key fits within the provided key_data structure
        assert(public_data.size() <= 32);
        assert(secret_data.size() <= 32);

        // the iterator to work with
        auto iter = key_data.begin();

        // if leading key bytes were missing (due to them being zero) we have to
        // prefill this with zeroes to avoid libsodium being fed uninitialized data
        iter = std::fill_n(iter, 32 - secret_data.size(), 0);
        iter = std::copy(secret_data.begin(), secret_data.end(), iter);

        // the public key data might also be missing leading bytes if they were zero
        // so we should similary prefill it
        iter = std::fill_n(iter, 32 - public_data.size(), 0);
        iter = std::copy(public_data.begin(), public_data.end(), iter);

        // get the digest to sign
        auto digest_data = digest();

        // now sign the message
        crypto_sign_detached(signed_message.data(), nullptr, digest_data.data(), digest_data.size(), key_data.data());

        // split up the data and return it
        return std::make_tuple(
            multiprecision_integer{span{ signed_message.data(),      32 }},
            multiprecision_integer{span{ signed_message.data() + 32, 32 }}
        );
    }

}
