#include "rsa_signature_encoder.h"


namespace pgp {

    /**
     *  Constructor
     */
    rsa_signature_encoder::rsa_signature_encoder(secret_key key) :
        _signature_context{signer_t{}.NewSignatureAccumulator(_prng)},
        key{std::move(key)}
    {}

    /**
     *  Destructor
     */
    rsa_signature_encoder::~rsa_signature_encoder()
    {
        // close the signature context; if it was already closed, this
        // is a nullptr, on which the delete operator is a no-op
        delete _signature_context;
    }

    /**
     *  Retrieve the RSA s parameter of the final sigature
     *
     *  This method should be called *at most once*.
     *
     *  @return The signature of the data
     */
    std::tuple<pgp::multiprecision_integer> rsa_signature_encoder::finalize() noexcept
    {
        // retrieve the key implementation
        auto &rsa_key = mpark::get<basic_secret_key<rsa_public_key, rsa_secret_key>>(key.key());

        // construct a Crypto++ private key; we also have p, q, u at our
        // disposal, but Crypto++'s extended constructor needs dp and dq as
        // well, which we don't have
        CryptoPP::RSA::PrivateKey k1;
        k1.Initialize(
            static_cast<CryptoPP::Integer>(rsa_key.n()),
            static_cast<CryptoPP::Integer>(rsa_key.e()),
            static_cast<CryptoPP::Integer>(rsa_key.d())
        );

        // construct the RSA signer
        signer_t signer{k1};

        // construct the target buffer for the signature
        const size_t signature_length = signer.MaxSignatureLength();
        std::vector<uint8_t> signed_message(signature_length);

        // sign the message, and resize the buffer to the actual size
        size_t actual_length = signer.Sign(_prng, _signature_context, signed_message.data());
        signed_message.resize(actual_length);

        // the Sign() method deallocated the accumulator, so forget the reference to it
        _signature_context = nullptr;

        // return the signature parameter
        return std::make_tuple(signed_message);
    }

    /**
     *  Retrieve the hash prefix: the first two bytes of the hash
     *
     *  This method should be called *at most once*.
     *
     *  @return The two-byte prefix of the hash of the data
     */
    std::array<uint8_t, 2> rsa_signature_encoder::hash_prefix() noexcept
    {
        // the buffer to store the prefix in
        std::array<uint8_t, 2> result;

        // obtain the prefix from the hash context
        _hash_context.TruncatedFinal(result.data(), 2);

        // return the prefix
        return result;
    }

}
