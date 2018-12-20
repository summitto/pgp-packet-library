#pragma once

#include "signature_subpacket_set.h"
#include "expected_number.h"
#include "signature_type.h"
#include "hash_algorithm.h"
#include "key_algorithm.h"
#include "packet_tag.h"
#include "decoder.h"
#include "encoder.h"


namespace pgp {

    /**
     *  Class holding a pgp signature
     */
    class signature
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            signature(decoder &parser);

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
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            expected_number<uint8_t, 4>         _version;               // the expected signature version format
            signature_type                      _type;                  // the signature type used
            key_algorithm                       _key_algorithm;         // the used key algorithm
            hash_algorithm                      _hash_algorithm;        // the used hashing algorithm
            signature_subpacket_set             _hashed_subpackets;     // the set of hashed subpackets
            signature_subpacket_set             _unhashed_subpackets;   // the set of unhashed subpackets
    };

}
