#pragma once

#include "fixed_number.h"
#include "decoder_traits.h"
#include "util/span.h"
#include <vector>


namespace pgp {

    /**
     *  Class representing a curve object identifier
     */
    class curve_oid
    {
        public:
            /**
             *  Constructor
             */
            curve_oid() = default;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             *  @throws std::out_of_range
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            curve_oid(decoder &parser)
            {
                // first read the number of elements
                auto count = parser.template extract_number<uint8_t>();

                // allocate memory for the number
                _data.reserve(count);

                // and now read all the elements
                while (_data.size() < count) {
                    // add an element
                    _data.push_back(parser.template extract_number<uint8_t>());
                }
            }

            /**
             *  Constructor
             *
             *  @param  data    The range of numbers
             */
            curve_oid(span<const uint8_t> data) noexcept;

            /**
             *  Constructor
             *
             *  @param  data    The range of numbers
             */
            curve_oid(std::initializer_list<const uint8_t> data) noexcept;

            /**
             *  Some commonly used curves
             *
             *  @return The curve oid
             */
            static curve_oid ed25519()      { return {{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01         }};    }
            static curve_oid curve_25519()  { return {{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01   }};    }
            static curve_oid ecdsa()        { return {{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07               }};    }
            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const curve_oid &other) const noexcept;
            bool operator!=(const curve_oid &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the data
             *  @return A span containing all the integer numbers
             */
            span<const uint8_t> data() const;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // write out the number of elements first
                writer.push(static_cast<uint8_t>(_data.size()));

                // now add all the elements
                for (auto number : _data) {
                    // add the number
                    writer.push(number);
                }
            }
        private:
            std::vector<uint8_t>    _data;
    };

}
