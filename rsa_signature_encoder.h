#pragma once

#include <iostream>
#include <boost/endian/conversion.hpp>
#include <gsl/span>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cassert>
#include "secret_key.h"


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
            rsa_signature_encoder();

            /**
             *  Destructor
             */
            ~rsa_signature_encoder();

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
                insert_blob(gsl::span<const T>{&result, 1});

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
                //     insert_blob(gsl::span<const decltype(*begin)>{&(*begin), std::distance(begin, end)});
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
            rsa_signature_encoder &insert_blob(gsl::span<const T> value)
            {
                // add the data to the accumulators
                _signature_context->Update(reinterpret_cast<const uint8_t*>(value.data()), value.size() * sizeof(T));
                _hash_context.Update      (reinterpret_cast<const uint8_t*>(value.data()), value.size() * sizeof(T));

                // allow chaining
                return *this;
            }

            /**
             *  Retrieve the final signature
             *
             *  This method should be called *at most once*.
             *
             *  @return The signature of the data
             */
            pgp::multiprecision_integer signature(const secret_key &key) noexcept;

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
            CryptoPP::PK_MessageAccumulator *_signature_context = nullptr;

            // accumulator context for the bare hash
            CryptoPP::SHA256 _hash_context;
    };

}
