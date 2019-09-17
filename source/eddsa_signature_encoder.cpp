#include "eddsa_signature_encoder.h"
#include <sodium/crypto_sign.h>


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
        std::array<uint8_t, crypto_sign_BYTES>  signed_message;
        std::array<uint8_t, 64>                 key_data;

        // ensure that unfilled bytes of key_data are empty
        std::fill(key_data.begin(), key_data.end(), 0);

        // retrieve the key data - ignore the silly leading byte from the public key
        auto public_data = eddsa_key.Q().data().subspan<1>();
        auto secret_data = eddsa_key.k().data();

        // copy the public key and then the private key
        assert(public_data.size() <= 32);
        assert(secret_data.size() <= 32);
        auto iter = std::copy(secret_data.begin(), secret_data.end(), key_data.begin() + 32 - secret_data.size());
        std::copy(public_data.begin(), public_data.end(), iter + 32 - public_data.size());

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
