#pragma once

#include "signature_subpacket_set.h"
#include <mpark/variant.hpp>
#include "expected_number.h"
#include "eddsa_signature.h"
#include "signature_type.h"
#include "hash_algorithm.h"
#include "key_algorithm.h"
#include "dsa_signature.h"
#include "rsa_signature.h"
#include "fixed_number.h"
#include "packet_tag.h"
#include "decoder.h"


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
             *  @param  signature_bits          The 16 most significant bits of the signature
             *  @param  ...,                    The parameters for constructing the signature
             */
            template <class T, typename... Arguments>
            signature(signature_type type, key_algorithm public_key_algorithm, hash_algorithm hashing_algorithm, signature_subpacket_set hashed_subpackets, signature_subpacket_set unhashed_subpackets, uint16_t signature_bits, mpark::in_place_type_t<T>, Arguments&& ...parameters) :
                _type{ type },
                _key_algorithm{ public_key_algorithm },
                _hash_algorithm{ hashing_algorithm },
                _hashed_subpackets{ std::move(hashed_subpackets) },
                _unhashed_subpackets{ std::move(unhashed_subpackets) },
                _signature_bits{ signature_bits },
                _signature{ mpark::in_place_type_t<T>{}, std::forward<Arguments>(parameters)... }
            {}

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
                _signature_bits.encode(writer);

                // retrieve the signature itself
                mpark::visit([&writer](auto &signature) {
                    // encode the signature
                    signature.encode(writer);
                }, _signature);
            }
        private:
            expected_number<uint8_t, 4>         _version;               // the expected signature version format
            signature_type                      _type;                  // the signature type used
            key_algorithm                       _key_algorithm;         // the used key algorithm
            hash_algorithm                      _hash_algorithm;        // the used hashing algorithm
            signature_subpacket_set             _hashed_subpackets;     // the set of hashed subpackets
            signature_subpacket_set             _unhashed_subpackets;   // the set of unhashed subpackets
            uint16                              _signature_bits;        // the 16 most significant bits of the signature
            signature_variant                   _signature;             // the actual signature
    };

}
