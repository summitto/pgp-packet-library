#pragma once

#include <cryptopp/cryptlib.h>          // for PK_MessageAccumulator
#include <cryptopp/osrng.h>             // for AutoSeededRandomPool
#include <cryptopp/pkcspad.h>           // for PKCS1v15
#include <cryptopp/pubkey.h>            // for RSASS::Signer
#include <cryptopp/rsa.h>               // for RSASS
#include <cryptopp/sha.h>               // for SHA256
#include <cstdint>                      // for uint8_t
#include <array>                        // for array
#include <boost/endian/conversion.hpp>  // for native_to_big
#include <limits>                       // for numeric_limits
#include <memory>                       // for unique_ptr
#include <tuple>                        // for tuple
#include <type_traits>                  // for enable_if_t, is_enum, underly...
#include <utility>                      // for get
#include "basic_key.h"                  // for basic_key
#include "basic_secret_key.h"           // for basic_secret_key
#include "multiprecision_integer.h"     // for multprecision_integer
#include "packet_tag.h"                 // for packet_tag
#include "rsa_public_key.h"             // for rsa_public_key
#include "rsa_secret_key.h"             // for rsa_secret_key
#include "secret_key.h"                 // for secret_key_traits
#include "util/span.h"                  // for span


namespace pgp {

    /**
     *  Class for encoding data into an RSA signature
     */
    class rsa_signature_encoder
    {
        private:
            using signer_t = CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer;

        public:
            /**
             *  Constructor
             */
            template <packet_tag key_tag>
            rsa_signature_encoder(const basic_key<secret_key_traits<key_tag>> &key) :
                _signature_context{signer_t{}.NewSignatureAccumulator(_prng)},
                rsa_key{get<basic_secret_key<rsa_public_key, rsa_secret_key>>(key.key())}
            {}

            /**
             *  Push a number to the encoder
             *
             *  @param  value   The number to push
             *  @return self, for chaining
             */
            template <typename T>
            typename std::enable_if_t<std::numeric_limits<T>::is_integer, rsa_signature_encoder&>
            push(T value) noexcept
            {
                // convert the value to big endian
                auto result = boost::endian::native_to_big(value);

                // add it to the accumulators
                insert_blob(span<const T>{&result, 1});

                // allow chaining
                return *this;
            }

            /**
             *  Insert an enum
             *
             *  @param  value   The enum to insert
             *  @return self, for chaining
             */
            template <typename T>
            typename std::enable_if_t<std::is_enum<T>::value, rsa_signature_encoder&>
            push(T value)
            {
                // cast it to a number and insert it
                return push(static_cast<typename std::underlying_type_t<T>>(value));
            }

            /**
             *  Push a range of data
             *
             *  @param  begin   The iterator to the beginning of the data
             *  @param  end     The iterator to the end of the data
             *  @return self, for chaining
             */
            template <typename iterator_t>
            rsa_signature_encoder &push(iterator_t begin, iterator_t end)
            {
                // note: possible c++20 optimization
                // // do we have a contiguous range of memory?
                // if constexpr(std::is_same_v<std::iterator_traits<iterator_t>::iterator_category, std::contiguous_iterator_tag>) {
                //     // push the whole range at once
                //     insert_blob(span<const decltype(*begin)>{&(*begin), std::distance(begin, end)});
                // }

                // iterate over the range
                while (begin != end) {
                    // push the data
                    push(*begin);

                    // move to next element
                    ++begin;
                }

                // allow chaining
                return *this;
            }

            /**
             *  Insert a blob of data
             *
             *  @param  value   The data to insert
             *  @return self, for chaining
             */
            template <typename T>
            rsa_signature_encoder &insert_blob(span<const T> value)
            {
                // add the data to the accumulators
                _signature_context->Update(reinterpret_cast<const uint8_t*>(value.data()), value.size() * sizeof(T));
                _hash_context.Update      (reinterpret_cast<const uint8_t*>(value.data()), value.size() * sizeof(T));

                // allow chaining
                return *this;
            }

            /**
             *  Retrieve the RSA s parameter of the final sigature
             *
             *  This method should be called *at most once*.
             *
             *  @return The signature of the data
             */
            std::tuple<pgp::multiprecision_integer> finalize() noexcept;

            /**
             *  Retrieve the hash prefix: the first two bytes of the hash
             *
             *  This method should be called *at most once*.
             *
             *  @return The two-byte prefix of the hash of the data
             */
            std::array<uint8_t, 2> hash_prefix() noexcept;

        private:
            // a random number generator for the message accumulator
            CryptoPP::AutoSeededRandomPool _prng;

            // accumulator context for the signature
            std::unique_ptr<CryptoPP::PK_MessageAccumulator> _signature_context;

            // accumulator context for the bare hash
            CryptoPP::SHA256 _hash_context;

            // key with which to make the signature
            basic_secret_key<rsa_public_key, rsa_secret_key> rsa_key;
    };

}
