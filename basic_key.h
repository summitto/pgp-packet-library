#pragma once

#include "decoder.h"
#include "packet_tag.h"
#include "unknown_key.h"
#include "fixed_number.h"
#include <crypto++/sha.h>
#include "key_algorithm.h"
#include "expected_number.h"
#include <mpark/variant.hpp>
#include "multiprecision_integer.h"


namespace pgp {

    /**
     *  Basic class for managing a key
     */
    template <typename key_traits>
    class basic_key
    {
        public:
            /**
             *  A variant with all supported key types
             */
            using key_variant = mpark::variant<
                unknown_key,
                typename key_traits::rsa_key_t,
                typename key_traits::dsa_key_t,
                typename key_traits::elgamal_key_t,
                typename key_traits::ecdh_key_t,
                typename key_traits::eddsa_key_t
            >;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             *  @throws std::out_of_range
             */
            basic_key(decoder &parser) :
                _version{ parser },
                _creation_time{ parser },
                _algorithm{ parser.extract_number<uint8_t>() }
            {
                // create the correct key based on the algorithm
                switch (_algorithm) {
                    case key_algorithm::rsa_encrypt_or_sign:
                    case key_algorithm::rsa_encrypt_only:
                    case key_algorithm::rsa_sign_only:
                        _key.template emplace<typename key_traits::rsa_key_t>(parser);
                        break;
                    case key_algorithm::elgamal_encrypt_only:
                        _key.template emplace<typename key_traits::elgamal_key_t>(parser);
                        break;
                    case key_algorithm::dsa:
                        _key.template emplace<typename key_traits::dsa_key_t>(parser);
                        break;
                    case key_algorithm::ecdh:
                        _key.template emplace<typename key_traits::ecdh_key_t>(parser);
                        break;
                    case key_algorithm::eddsa:
                        _key.template emplace<typename key_traits::eddsa_key_t>(parser);
                        break;
                }
            }

            /**
             *  Constructor
             *
             *  @param  creation_time   UNIX timestamp the key was created at
             *  @param  algorithm       The key algorithm used
             *  @param  ...,            The parameters to forward to the key constructor
             *  @throws std::runtime_error
             */
            template <class T, typename... Arguments>
            basic_key(uint32_t creation_time, key_algorithm algorithm, mpark::in_place_type_t<T>, Arguments&& ...parameters) :
                _version{},
                _creation_time{ creation_time },
                _algorithm{ algorithm },
                _key{ mpark::in_place_type_t<T>{}, std::forward<Arguments>(parameters)... }
            {}

            /**
             *  Retrieve the packet tag used for this
             *  packet type
             *  @return The packet type to use
             */
            packet_tag tag() const noexcept
            {
                // retrieve the tag from the key traits
                return key_traits::tag();
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             *  @throws std::runtime_error for unknown key types
             */
            size_t size() const
            {
                // the size of all the members
                auto result = _version.size() + _creation_time.size() + sizeof(_algorithm);

                // retrieve the key
                mpark::visit([&result](auto &key) {
                    // add the key size to the total
                    result += key.size();
                }, _key);

                // return the resulting size
                return result;
            }

            /**
             *  Retrieve the fingerprint for this key
             *
             *  @return The 8-byte fingerprint
             */
            std::array<uint8_t, 8> fingerprint() const noexcept
            {
                // the hashing context to create the fingerprint
                CryptoPP::SHA hasher;

                // the magic constant to use for key fingerprints
                static constexpr const expected_number<uint8_t, 0x99> fingerprint_magic;

                // retrieve the key
                mpark::visit([this, &hasher](auto &&key) {
                    // determine key type
                    using key_type_t    = std::decay_t<decltype(key)>;
                    using public_type_t = typename key_type_t::public_key_t;

                    // the size of the key data we hash
                    // note that we cast to the public key
                    uint16 size{
                        _version.size() +
                        _creation_time.size() +
                        sizeof(_algorithm) +
                        key.public_key_t::size()
                    };

                    // add magic constant and base fields
                    fingerprint_magic.hash(hasher);
                    size.hash(hasher);
                    _version.hash(hasher);
                    _creation_time.hash(hasher);
                    hasher.Update(reinterpret_cast<const uint8_t*>(&_algorithm), sizeof _algorithm);

                    // // also hash the key data
                    key.hash(hasher);
                }, _key);

                // the container for the digest and the result container
                std::array<uint8_t, 20> data;
                std::array<uint8_t, 8>  result;

                // finalize the hashing
                hasher.Final(data.data());

                // copy the last 8 bytes over
                std::copy(data.begin() + 12, data.end(), result.begin());

                // and return the now-filled result
                return result;
            }

            /**
             *  Get the key version
             *  @return The key version format
             */
            constexpr uint8_t version() const noexcept
            {
                // extract the value version
                return _version.value();
            }

            /**
             *  Get the creation time
             *  @return UNIX timestamp with key creation time
             */
            uint32_t creation_time() const noexcept
            {
                // return the creation time of the key
                return _creation_time;
            }

            /**
             *  Retrieve the key algorithm
             *  @return The algorithm used in the key
             */
            key_algorithm algorithm() const noexcept
            {
                // return the stored algorithm of the key
                return _algorithm;
            }

            /**
             *  Retrieve the key-specific data
             *
             *  @return The variant with the specifics
             */
            const key_variant &key() const noexcept
            {
                // return the stored key
                return _key;
            }

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const
            {
                // write out all the components of the key
                _version.encode(writer);
                _creation_time.encode(writer);
                writer.insert_enum(_algorithm);

                // retrieve the key
                mpark::visit([&writer](auto &key) {
                    // also encode the key itself
                    key.encode(writer);
                }, _key);
            }
        private:
            expected_number<uint8_t, 4>         _version;               // the expected key version format
            uint32                              _creation_time;         // the UNIX timestamp the key was created at
            key_algorithm                       _algorithm      { 0 };  // the algorithm for creating the key
            key_variant                         _key;                   // the specific key

    };

}
