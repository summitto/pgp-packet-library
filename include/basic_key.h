#pragma once

#include "packet_tag.h"
#include "unknown_key.h"
#include "fixed_number.h"
#include "hash_encoder.h"
#include "util/variant.h"
#include "key_algorithm.h"
#include "decoder_traits.h"
#include "expected_number.h"
#include "util/narrow_cast.h"
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
             *  Expose the key types
             */
            using rsa_key_t     = typename key_traits::rsa_key_t;
            using dsa_key_t     = typename key_traits::dsa_key_t;
            using elgamal_key_t = typename key_traits::elgamal_key_t;
            using ecdh_key_t    = typename key_traits::ecdh_key_t;
            using eddsa_key_t   = typename key_traits::eddsa_key_t;
            using ecdsa_key_t   = typename key_traits::ecdsa_key_t;

            /**
             *  A variant with all supported key types
             */
            using key_variant = variant<
                unknown_key,
                rsa_key_t,
                dsa_key_t,
                elgamal_key_t,
                ecdh_key_t,
                eddsa_key_t,
                ecdsa_key_t
            >;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             *  @throws std::out_of_range
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            basic_key(decoder &parser) :
                _version{ parser },
                _creation_time{ parser },
                _algorithm{ parser.template extract_number<uint8_t>() }
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
                    case key_algorithm::ecdsa:
                        _key.template emplace<typename key_traits::ecdsa_key_t>(parser);
                        break;
                }
            }

            /**
             *  Constructor
             *
             *  @param  creation_time   UNIX timestamp the key was created at
             *  @param  algorithm       The key algorithm used
             *  @param  parameters      The parameters to forward to the key constructor
             *  @throws std::runtime_error
             */
            template <class T, typename... Arguments>
            basic_key(uint32_t creation_time, key_algorithm algorithm, in_place_type_t<T>, Arguments&& ...parameters) :
                _version{},
                _creation_time{ creation_time },
                _algorithm{ algorithm },
                _key{ in_place_type_t<T>{}, std::forward<Arguments>(parameters)... }
            {}

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const basic_key<key_traits> &other) const noexcept
            {
                return creation_time() == other.creation_time() &&
                        algorithm() == other.algorithm() &&
                        key() == other.key();
            }

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator!=(const basic_key<key_traits> &other) const noexcept
            {
                return !operator==(other);
            }

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
                visit([&result](auto &key) {
                    // add the key size to the total
                    result += key.size();
                }, _key);

                // return the resulting size
                return result;
            }

            /**
             *  Hash the key into a given hash context
             *
             *  @param  writer  The hasher to write to
             */
            template <class encoder_t>
            void hash(encoder_t &writer) const noexcept
            {
                // the magic constant to use for key fingerprints
                static constexpr const expected_number<uint8_t, 0x99> fingerprint_magic;

                // retrieve the key
                visit([this, &writer](auto &&key) {
                    // determine key type
                    using key_type_t    = std::decay_t<decltype(key)>;

                    // Clang has a longstanding bug, which is possibly related
                    // to the following bug reports:
                    // - https://bugs.llvm.org/show_bug.cgi?id=24883
                    // - https://bugs.llvm.org/show_bug.cgi?id=33298
                    // where it raises spurious unused-local-typedef warnings
                    // for local typedefs in a templated function. To prevent
                    // the warning from cluttering up the builds, we ignore it
                    // on clang only below.
#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-local-typedef"
#endif
                    using public_type_t = typename key_type_t::public_key_t;
#ifdef __clang__
#pragma GCC diagnostic pop
#endif

                    // the size of the key data we hash
                    // note that we cast to the public key
                    uint16 size{
                        util::narrow_cast<uint16_t>(
                            _version.size() +
                            _creation_time.size() +
                            sizeof(_algorithm) +
                            key.public_type_t::size()
                        )
                    };

                    // add magic constant and base fields
                    fingerprint_magic.encode(writer);
                    size.encode(writer);
                    _version.encode(writer);
                    _creation_time.encode(writer);
                    writer.push(_algorithm);

                    // also hash the key data
                    key.public_type_t::encode(writer);
                }, _key);
            }

            /**
             *  Retrieve the fingerprint for this key
             *
             *  @return The 20-byte fingerprint
             */
            std::array<uint8_t, 20> fingerprint() const noexcept
            {
                // the hashing context to create the fingerprint
                sha1_encoder    encoder;

                // hash the key into the context
                hash(encoder);

                // return the resulting digest
                return encoder.digest();
            }

            /**
             *  Retrieve the key ID for this key
             *
             *  @return The 8-byte key ID
             */
            std::array<uint8_t, 8> key_id() const noexcept
            {
                // obtain the fingerprint
                std::array<uint8_t, 20> print{fingerprint()};

                // copy the last 8 bytes into the result container
                std::array<uint8_t, 8>  result;
                std::copy(print.begin() + 12, print.end(), result.begin());

                // return the result
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
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // write out all the components of the key
                _version.encode(writer);
                _creation_time.encode(writer);
                writer.push(_algorithm);

                // retrieve the key
                visit([&writer](auto &key) {
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
