#pragma once

#include "signature_subpacket_set.h"
#include "unknown_signature.h"
#include <mpark/variant.hpp>
#include "expected_number.h"
#include "eddsa_signature.h"
#include "util/to_lvalue.h"
#include "signature_type.h"
#include "hash_algorithm.h"
#include "key_algorithm.h"
#include "dsa_signature.h"
#include "rsa_signature.h"
#include "fixed_number.h"
#include "packet_tag.h"
#include "secret_key.h"
#include "public_key.h"
#include "decoder.h"
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
            using signature_variant = mpark::variant<
                unknown_signature,
                dsa_signature,
                rsa_signature,
                eddsa_signature
            >;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            signature(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  type                    The signature type
             *  @param  public_key_algorithm    The public key algorithm
             *  @param  hashing_algorithm       The used hashing algorithm
             *  @param  hashed_subpackets       The set of hashed subpackets
             *  @param  unhashed_subpackets     The set of unhashed subpackets
             *  @param  hash_prefix             The 16 most significant bits of the signed hash
             *  @param  ...,                    The parameters for constructing the signature
             */
            template <class T, typename... Arguments>
            signature(signature_type type, key_algorithm public_key_algorithm, hash_algorithm hashing_algorithm, signature_subpacket_set hashed_subpackets, signature_subpacket_set unhashed_subpackets, uint16_t hash_prefix, mpark::in_place_type_t<T>, Arguments&& ...parameters) :
                _type{ type },
                _key_algorithm{ public_key_algorithm },
                _hash_algorithm{ hashing_algorithm },
                _hashed_subpackets{ std::move(hashed_subpackets) },
                _unhashed_subpackets{ std::move(unhashed_subpackets) },
                _hash_prefix{ hash_prefix },
                _signature{ mpark::in_place_type_t<T>{}, std::forward<Arguments>(parameters)... }
            {}

            /**
             *  Constructor
             *
             *  @param  bound_key               The key we are binding in the signature
             *  @param  user                    The user id we are binding in the signature
             *  @param  hashed_subpackets       The subpackets that will be used for generating the hash
             *  @param  unhashed_subpackets     The subpackets that will not be hashed
             */
            template <class T, typename... Arguments>
            signature( mpark::in_place_type_t<T>, const secret_key &bound_key, const user_id &user, signature_subpacket_set hashed_subpackets, signature_subpacket_set unhashed_subpackets) :
                _type{ signature_type::positive_user_id_and_public_key_certification },
                _key_algorithm{ bound_key.algorithm() },
                _hash_algorithm{ hash_algorithm::sha256 },
                _hashed_subpackets{ std::move(hashed_subpackets) },
                _unhashed_subpackets{ std::move(unhashed_subpackets) }
            {
                // encoder to calculate the fingerprint
                pgp::gcrypt_encoder<pgp::gcrypt_sha256_encoding> hash_encoder;

                // hash the key
                bound_key.hash(hash_encoder);

                // hash the user id
                hash_encoder.push<uint8_t>(0xB4);
                hash_encoder.push<uint32_t>(user.size());
                user.encode(hash_encoder);

                // now hash the signature data itself
                hash_signature(hash_encoder);

                // now create a digest of the data and read the prefix
                auto digest  = hash_encoder.digest();
                _hash_prefix = util::to_lvalue(decoder{ digest });

                // what kind of signature should we construct?
                switch (_key_algorithm) {
                    case key_algorithm::rsa_encrypt_or_sign:
                    case key_algorithm::rsa_sign_only:
                        _signature.emplace<rsa_signature>(bound_key, digest);
                        break;
                    case key_algorithm::dsa:
                        _signature.emplace<dsa_signature>(bound_key, digest);
                        break;
                    case key_algorithm::eddsa:
                        _signature.emplace<eddsa_signature>(bound_key, digest);
                        break;
                    default:
                        // do nothing, use the unknown_key
                        break;
                }
            }

            /**
             *  Constructor
             *
             *  @param  owner                   The key that will certify it owns another key
             *  @param  subkey                  The subkey that belongs to the owner
             *  @param  hashed_subpackets       The subpackets that will be used for generating the hash
             *  @param  unhashed_subpackets     The subpackets that will not be hashed
             */
            template <class T, typename... Arguments>
            signature( mpark::in_place_type_t<T>, const secret_key &owner, const secret_subkey &subkey, signature_subpacket_set hashed_subpackets, signature_subpacket_set unhashed_subpackets) :
                _type{ signature_type::subkey_binding },
                _key_algorithm{ owner.algorithm() },
                _hash_algorithm{ hash_algorithm::sha256 },
                _hashed_subpackets{ std::move(hashed_subpackets) },
                _unhashed_subpackets{ std::move(unhashed_subpackets) }
            {
                // encoder to calculate the fingerprint
                pgp::gcrypt_encoder<pgp::gcrypt_sha256_encoding> hash_encoder;

                // hash the keys
                owner.hash(hash_encoder);
                subkey.hash(hash_encoder);

                // now hash the signature data itself
                hash_signature(hash_encoder);

                // now create a digest of the data and read the prefix
                auto digest  = hash_encoder.digest();
                _hash_prefix = util::to_lvalue(decoder{ digest });

                // what kind of signature should we construct?
                switch (_key_algorithm) {
                    case key_algorithm::rsa_encrypt_or_sign:
                    case key_algorithm::rsa_sign_only:
                        _signature.emplace<rsa_signature>(owner, digest);
                        break;
                    case key_algorithm::dsa:
                        _signature.emplace<dsa_signature>(owner, digest);
                        break;
                    case key_algorithm::eddsa:
                        _signature.emplace<eddsa_signature>(owner, digest);
                        break;
                    default:
                        // do nothing, use the unknown_key
                        break;
                }
            }

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
                mpark::visit([&writer](auto &signature) {
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
                hash_encoder.template push<uint32_t>(
                    sizeof(version())               +
                    sizeof(type())                  +
                    sizeof(public_key_algorithm())  +
                    sizeof(hashing_algorithm())     +
                    _hashed_subpackets.size()
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
