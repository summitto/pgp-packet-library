#pragma once

#include "unknown_signature_subpacket.h"
#include "numeric_signature_subpacket.h"
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
                unknown_signature_subpacket,
                signature_creation_time_subpacket,
                signature_expiration_time_subpacket,
                exportable_certification_subpacket,
                primary_user_id_subpacket,
                key_expiration_time_subpacket
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
            void encode(encoder &writer) const;
        private:
            std::vector<subpacket_variant>  _subpackets;    // the subpackets in the set
    };

}
