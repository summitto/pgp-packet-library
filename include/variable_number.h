#pragma once

#include "decoder.h"
#include "util/narrow_cast.h"


namespace pgp {

    /**
     *  Class implementing a number compatible with the
     *  PGP RFC, using a variable number of encoded octets
     */
    class variable_number
    {
        public:
            /**
             *  Constructor
             */
            variable_number() = default;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            variable_number(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  value   The value to hold
             */
            variable_number(uint32_t value) noexcept;

            /**
             *  Assignment operator
             *
             *  @param  value   The value to assign
             *  @return self, for chaining
             */            
            variable_number &operator=(uint32_t value) noexcept;

            /**
             *  Determine the size used in encoded format
             *
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Extract the stored value
             *
             *  @return The stored value
             */
            operator uint32_t() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // encoding depends on the value
                if (_value < 192) {
                    // directly encode the number
                    uint8_t value = util::narrow_cast<uint8_t>(_value);
                    writer.push(value);
                } else if (_value < 8384) {
                    // enable the two most significant bits and remove
                    // 192 from the number according to rfc 4880
                    uint16_t value = util::narrow_cast<uint16_t>(0b1100000000000000 | (_value - 192));
                    writer.push(value);
                } else {
                    // write the tag to indicate a full 4-byte number
                    writer.push(static_cast<uint8_t>(0xff));
                    // write the number to the encoder
                    writer.push(_value);
                }
            }
        private:
            uint32_t    _value{ 0 };
    };

}
