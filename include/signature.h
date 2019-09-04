#pragma once

#include "signature_subpacket_set.h"
#include "unknown_signature.h"
#include "expected_number.h"
#include "eddsa_signature.h"
#include "ecdsa_signature.h"
#include "decoder_traits.h"
#include "signature_type.h"
#include "hash_algorithm.h"
#include "key_algorithm.h"
#include "dsa_signature.h"
#include "rsa_signature.h"
#include "util/variant.h"
#include "fixed_number.h"
#include "packet_tag.h"
#include "secret_key.h"
#include "public_key.h"
#include "user_id.h"


namespace pgp {

    /**
     *  Class holding a pgp signature
     */
    class signature
    {
        public:
            /**
             *  The valid signatures we can hold
             */
            using signature_variant = variant<
                unknown_signature,
                dsa_signature,
                rsa_signature,
                eddsa_signature,
                ecdsa_signature
            >;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            signature(decoder &parser) :
                _version{ parser },
                _type{ parser.template extract_number<uint8_t>() },
                _key_algorithm{ parser.template extract_number<uint8_t>() },
                _hash_algorithm{ parser.template extract_number<uint8_t>() },
                _hashed_subpackets{ parser },
                _unhashed_subpackets{ parser },
                _hash_prefix{ parser }
            {
                // what kind of signature should we construct?
                switch (_key_algorithm) {
                    case key_algorithm::rsa_encrypt_or_sign:
                    case key_algorithm::rsa_sign_only:
                        _signature.emplace<rsa_signature>(parser);
                        break;
                    case key_algorithm::dsa:
                        _signature.emplace<dsa_signature>(parser);
                        break;
                    case key_algorithm::eddsa:
                        _signature.emplace<eddsa_signature>(parser);
                        break;
                    case key_algorithm::ecdsa:
                        _signature.emplace<ecdsa_signature>(parser);
                        break;
                    default:
                        // do nothing, use the unknown_key
                        break;
                }
            }

            /**
             *  Constructor
             *
             *  @param  type                    The signature type
             *  @param  public_key_algorithm    The public key algorithm
             *  @param  hashing_algorithm       The used hashing algorithm
             *  @param  hashed_subpackets       The set of hashed subpackets
             *  @param  unhashed_subpackets     The set of unhashed subpackets
             *  @param  hash_prefix             The 16 most significant bits of the signed hash
             *  @param  parameters              The parameters for constructing the signature
             */
            template <class T, typename... Arguments>
            signature(signature_type type, key_algorithm public_key_algorithm, hash_algorithm hashing_algorithm, signature_subpacket_set hashed_subpackets, signature_subpacket_set unhashed_subpackets, uint16_t hash_prefix, in_place_type_t<T>, Arguments&& ...parameters) :
                _type{ type },
                _key_algorithm{ public_key_algorithm },
                _hash_algorithm{ hashing_algorithm },
                _hashed_subpackets{ std::move(hashed_subpackets) },
                _unhashed_subpackets{ std::move(unhashed_subpackets) },
                _hash_prefix{ hash_prefix },
                _signature{ in_place_type_t<T>{}, std::forward<Arguments>(parameters)... }
            {}

            /**
             *  Constructor
             *
             *  @param  bound_key               The key we are binding in the signature
             *  @param  user                    The user id we are binding in the signature
             *  @param  hashed_subpackets       The subpackets that will be used for generating the hash
             *  @param  unhashed_subpackets     The subpackets that will not be hashed
             */
            signature(const secret_key &bound_key, const user_id &user, signature_subpacket_set hashed_subpackets, signature_subpacket_set unhashed_subpackets);

            /**
             *  Constructor
             *
             *  @param  signer                  The key that will certify it owns/trusts another key
             *  @param  signee                  The (usually sub-)key that belongs to the owner
             *  @param  hashed_subpackets       The subpackets that will be used for generating the hash
             *  @param  unhashed_subpackets     The subpackets that will not be hashed
             */
            template <packet_tag signer_tag, typename signee_traits>
            signature(
                const basic_key<secret_key_traits<signer_tag>> &signer,
                const basic_key<signee_traits> &signee,
                signature_subpacket_set hashed_subpackets,
                signature_subpacket_set unhashed_subpackets
            ) :
                _type{ secret_key_traits<signer_tag>::is_subkey()
                            ? signature_type::primary_key_binding
                            : signature_type::subkey_binding },
                _key_algorithm{ signer.algorithm() },
                _hash_algorithm{ hash_algorithm::sha256 },
                _hashed_subpackets{ std::move(hashed_subpackets) },
                _unhashed_subpackets{ std::move(unhashed_subpackets) }
            {
                visit([&signer, &signee, this](auto &&key_instance) {
                    // obtain the appropriate types
                    using signature_t = typename std::decay_t<decltype(key_instance)>::signature_t;
                    using encoder_t = typename signature_t::encoder_t;

                    // construct the appropriate signature encoder
                    encoder_t encoder{signer};

                    // hash the keys; the main key always comes first
                    if constexpr (!secret_key_traits<signer_tag>::is_subkey()) {
                        // for a subkey binding, the main key is the signer
                        signer.hash(encoder);
                        signee.hash(encoder);
                    } else {
                        // for a primary key binding, the main key is the signee
                        signee.hash(encoder);
                        signer.hash(encoder);
                    }

                    // now hash the signature data itself
                    hash_signature(encoder);

                    // store the hash prefix
                    _hash_prefix = decoder{encoder.hash_prefix()};

                    // Extra move was deemed worth it versus the monstrosity that would
                    // be required to use std::apply here.
                    _signature.emplace<signature_t>(util::make_from_tuple<signature_t>(encoder.finalize()));
                }, signer.key());
            }

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const signature &other) const noexcept;
            bool operator!=(const signature &other) const noexcept;

            /**
             *  Retrieve the packet tag used for this
             *  packet type
             *  @return The packet type to use
             */
            static constexpr packet_tag tag() noexcept
            {
                // this is a signature packet
                return packet_tag::signature;
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             *  @throws std::runtime_error for unknown signature types
             */
            size_t size() const;

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
             *  Get the signature type
             *  @return The type of signature
             */
            signature_type type() const noexcept;

            /**
             *  Get the used key algorithm
             *
             *  @return The public key algorithm
             */
            key_algorithm public_key_algorithm() const noexcept;

            /**
             *  Get the used hashing algorithm
             *
             *  @return The hashing algorithm
             */
            hash_algorithm hashing_algorithm() const noexcept;

            /**
             *  Retrieve the hashed subpackets
             *
             *  @return The hashed subpackets
             */
            const signature_subpacket_set &hashed_subpackets() const noexcept;

            /**
             *  Retrieve the unhashed subpackets
             *
             *  @return The unhashed subpackets
             */
            const signature_subpacket_set &unhashed_subpackets() const noexcept;

            /**
             *  Retrieve the 16 most significant bits from the signed hash
             *
             *  @return Two bytes of hash data
             */
            uint16_t hash_prefix() const noexcept;

            /**
             *  Retrieve the signature data
             *
             *  @return The signature data
             */
            const signature_variant &data() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // encode all the fields of the signature
                _version.encode(writer);
                writer.push(_type);
                writer.push(_key_algorithm);
                writer.push(_hash_algorithm);
                _hashed_subpackets.encode(writer);
                _unhashed_subpackets.encode(writer);
                _hash_prefix.encode(writer);

                // retrieve the signature itself
                visit([&writer](auto &signature) {
                    // encode the signature
                    signature.encode(writer);
                }, _signature);
            }
        private:
            /**
             *  Hash the signature data
             *
             *  @param  hash_encoder    The encoder to write to
             */
            template <class encoder_t>
            void hash_signature(encoder_t &hash_encoder)
            {
                // hash our own data
                hash_encoder.push(version());
                hash_encoder.push(type());
                hash_encoder.push(public_key_algorithm());
                hash_encoder.push(hashing_algorithm());
                _hashed_subpackets.encode(hash_encoder);

                // add trailer
                hash_encoder.push(version());
                hash_encoder.template push<uint8_t>(0xFF);
                hash_encoder.push(
                    util::narrow_cast<uint32_t>(
                        sizeof(version())               +
                        sizeof(type())                  +
                        sizeof(public_key_algorithm())  +
                        sizeof(hashing_algorithm())     +
                        _hashed_subpackets.size()
                    )
                );
            }

            expected_number<uint8_t, 4>         _version;               // the expected signature version format
            signature_type                      _type;                  // the signature type used
            key_algorithm                       _key_algorithm;         // the used key algorithm
            hash_algorithm                      _hash_algorithm;        // the used hashing algorithm
            signature_subpacket_set             _hashed_subpackets;     // the set of hashed subpackets
            signature_subpacket_set             _unhashed_subpackets;   // the set of unhashed subpackets
            uint16                              _hash_prefix;           // the 16 most significant bits of the signed hash
            signature_variant                   _signature;             // the actual signature
    };

}
