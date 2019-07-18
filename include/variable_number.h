#pragma once

#include "decoder_traits.h"
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
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            variable_number(decoder &parser)
            {
                // read the first byte to determine the strategy
                if (parser.template peek_number<uint8_t>() < 192) {
                    // single-octet number only
                    _value = parser.template extract_number<uint8_t>();
                } else if (parser.template peek_number<uint8_t>() < 224) {
                    // it's a two-octet number, remove upper two bits
                    // and append 192 to get to the correct number
                    _value = (parser.template extract_number<uint16_t>() & 0b0011111111111111) + 192;
                } else if (parser.template peek_number<uint8_t>() == 255) {
                    // skip the byte we just peeked
                    parser.template extract_number<uint8_t>();
                    // simple four-octet number
                    _value = parser.template extract_number<uint32_t>();
                } else {
                    // error: we don't support par
                    throw std::runtime_error{ "Partial body length not implemented" };
                }
            }

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
