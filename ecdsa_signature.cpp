#include "ecdsa_signature.h"
#include <sodium/crypto_sign.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>


namespace pgp {
	using namespace CryptoPP;
    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    ecdsa_signature::ecdsa_signature(decoder &parser) :
        _r{ parser },
        _s{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  key     The key to use for signing
     *  @param  digest  The hash that needs to be signed
     */
    ecdsa_signature::ecdsa_signature(const secret_key &key, std::array<uint8_t, 32> digest)
    {
        // retrieve the key implementation
        auto &ecdsa_key = mpark::get<basic_secret_key<ecdsa_public_key, ecdsa_secret_key>>(key.key());

        // the buffer for the signed message and the concatenated key
        std::array<uint8_t, crypto_sign_BYTES>  signed_message;
        // std::array<uint8_t, 64>                 key_data;

        // retrieve the key data - ignore the silly leading byte from the public key
        auto public_data = ecdsa_key.Q().data().subspan<1>();
        auto secret_data = ecdsa_key.k().data();

        //crypto_sign_detached(signed_message.data(), nullptr, digest.data(), digest.size(), key_data.data());

		AutoSeededRandomPool prng;
		
		ECDSA<ECP, SHA1>::PrivateKey k1;
		CryptoPP::Integer mainKeySecret_x;
		mainKeySecret_x.Decode(secret_data.data(), 32);

		k1.Initialize(ASN1::secp256r1(), mainKeySecret_x);
		// std::cout << std::dec;
		// std::cout << "Private Key: " << mainKeySecret_x << " - Secret Data Size: " <<  secret_data.size() << std::endl;
		// std::cout << "Private Key: " << std::hex << mainKeySecret_x << std::dec << " - Secret Data Size: " <<  secret_data.size() << std::endl;

		ECDSA<ECP, SHA1>::Signer signer(k1);
        // now sign the message
		signer.SignMessage( prng, digest.data(), digest.size(), signed_message.data() );
	
		ECDSA<ECP, SHA1>::PublicKey publicKey;
		k1.MakePublicKey(publicKey);
		ECDSA<ECP, SHA1>::Verifier verifier(publicKey);
				
		bool result = verifier.VerifyMessage( digest.data(), digest.size(), signed_message.data(), signed_message.size() );
		if( !result ) {
			std::cerr << "Failed to verify signature on message" << std::endl;
		} else {
			std::cout << "All good! " << std::endl;
		}
		
		std::cout << "Signed message: ";
		for(const auto& s: signed_message)
			std::cout << std::hex << (unsigned int) s;

		std::cout << "\n" << std::endl;

        // split up the data and assign it
        _r = gsl::span{ signed_message.data(),      32 };
        _s = gsl::span{ signed_message.data() + 32, 32 };
    }

    /**
     *  Constructor
     *
     *  @param  r       The EdDSA r value
     *  @param  s       The EdDSA s value
     */
    ecdsa_signature::ecdsa_signature(multiprecision_integer r, multiprecision_integer s) noexcept :
        _r{ std::move(r) },
        _s{ std::move(s) }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t ecdsa_signature::size() const noexcept
    {
        // we need space to store both values
        return _r.size() + _s.size();
    }

    /**
     *  Retrieve the EdDSA r value
     *
     *  @return The r value
     */
    const multiprecision_integer &ecdsa_signature::r() const noexcept
    {
        // return the r value
        return _r;
    }

    /**
     *  Retrieve the EdDSA s value
     *
     *  @return The s value
     */
    const multiprecision_integer &ecdsa_signature::s() const noexcept
    {
        // return the s value
        return _s;
    }

}
