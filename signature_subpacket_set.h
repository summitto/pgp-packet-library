#pragma once

#include "signature_subpacket.h"


namespace pgp {

    /**
     *  Class holding a set of signature subpackets
     */
    class signature_subpacket_set
    {
        public:
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
            signature_subpacket_set(gsl::span<signature_subpacket> subpackets) noexcept;

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
            const signature_subpacket &operator[](size_t offset) const;

            /**
             *  Retrieve all subpackets
             *
             *  @return The subpackets in the set
             */
            gsl::span<const signature_subpacket> data() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            std::vector<signature_subpacket>    _subpackets;    // the subpackets in the set
    };

}
