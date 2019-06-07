#pragma once

#include "signature_subpacket/issuer_fingerprint.h"
#include "signature_subpacket/fixed_array.h"
#include "signature_subpacket/key_flags.h"
#include "signature_subpacket/unknown.h"
#include "signature_subpacket/numeric.h"
#include "signature_subpacket_type.h"
#include <mpark/variant.hpp>


namespace pgp {

    /**
     *  Class holding a set of signature subpackets
     */
    class signature_subpacket_set
    {
        public:
            /**
             *  The recognized subpacket types
             */
            using subpacket_variant = mpark::variant<
                signature_subpacket::unknown,
                signature_subpacket::issuer,
                signature_subpacket::signature_creation_time,
                signature_subpacket::signature_expiration_time,
                signature_subpacket::exportable_certification,
                signature_subpacket::primary_user_id,
                signature_subpacket::key_expiration_time,
                signature_subpacket::key_flags,
                signature_subpacket::issuer_fingerprint
            >;

            /**
             *  Default constructor
             */
            signature_subpacket_set() = default;

            /**
             *  Constructor
             *
             *  @param  parser      The decoder to parse the data
             */
            signature_subpacket_set(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  subpackets  The subpackets to keep in the set
             */
            signature_subpacket_set(std::vector<subpacket_variant> subpackets) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const pgp::signature_subpacket_set &other) const noexcept;
            bool operator!=(const pgp::signature_subpacket_set &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Iterator access to the subpackets
             */
            auto begin()    const noexcept { return _subpackets.cbegin();   }
            auto cbegin()   const noexcept { return _subpackets.cbegin();   }
            auto rbegin()   const noexcept { return _subpackets.crbegin();  }
            auto crbegin()  const noexcept { return _subpackets.crbegin();  }
            auto end()      const noexcept { return _subpackets.cend();     }
            auto cend()     const noexcept { return _subpackets.cend();     }
            auto rend()     const noexcept { return _subpackets.crend();    }
            auto crend()    const noexcept { return _subpackets.crend();    }

            /**
             *  Retrieve a specific subpacket
             *
             *  @param  offset  The offset for the subpacket to receive
             *  @throws std::out_of_range
             */
            const subpacket_variant &operator[](size_t offset) const;

            /**
             *  Retrieve all subpackets
             *
             *  @return The subpackets in the set
             */
            gsl::span<const subpacket_variant> data() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // add the size header; this is the size of the packet minus
                // the size of the header itself
                uint16{ gsl::narrow_cast<uint16_t>(size() - uint16::size()) }.encode(writer);

                // iterate over the subpackets
                for (auto &subpacket : _subpackets) {
                    // retrieve the specific type
                    mpark::visit([&writer](auto &&subpacket) {
                        // encode the subpacket as well
                        subpacket.encode(writer);
                    }, subpacket);
                }
            }
        private:
            std::vector<subpacket_variant>  _subpackets;    // the subpackets in the set
    };

}
