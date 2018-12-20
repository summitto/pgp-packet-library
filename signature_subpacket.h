#pragma once

#include "signature_subpacket_type.h"
#include "decoder.h"
#include "encoder.h"
#include <vector>


namespace pgp {

    /**
     *  Class holding a single subpacket
     */
    class signature_subpacket
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            signature_subpacket(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  type    The signature subpacket type
             *  @param  data    The data contained in the subpacket
             */
            signature_subpacket(signature_subpacket_type type, gsl::span<const uint8_t> data);

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Get the signature subpacket type
             *  @return The type of signature subpacket
             */
            signature_subpacket_type type() const noexcept;

            /**
             *  Retrieve the data
             *  @return A span containing all the integer numbers
             */
            gsl::span<const uint8_t> data() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            signature_subpacket_type    _type;
            std::vector<uint8_t>        _data;
    };

}
