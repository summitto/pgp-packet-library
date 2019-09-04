#pragma once

#include "../signature_subpacket_type.h"
#include "../variable_number.h"
#include "../util/span.h"
#include <vector>


namespace pgp::signature_subpacket {

    /**
     *  Class holding a single subpacket of unknown type
     */
    class unknown
    {
        public:
            /**
             *  Constructor
             *
             *  @param  type    The subpacket type
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            unknown(signature_subpacket_type type, decoder &parser) :
                _type{ type }
            {
                // reserve memory for the data
                _data.reserve(parser.size());
        
                // and fill the buffer
                while (!parser.empty()) {
                    // add another byte
                    _data.push_back(parser.template extract_number<uint8_t>());
                }
            }

            /**
             *  Constructor
             *
             *  @param  type    The signature subpacket type
             *  @param  data    The data contained in the subpacket
             */
            unknown(signature_subpacket_type type, span<const uint8_t> data);

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const unknown &other) const noexcept;
            bool operator!=(const unknown &other) const noexcept;

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
            span<const uint8_t> data() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // first encode the length of the subpacket
                variable_number{ static_cast<uint32_t>(sizeof(_type) + _data.size()) }.encode(writer);

                // add the subpacket type
                writer.push(_type);

                // now go over the whole data set
                for (auto number : _data) {
                    // add the number
                    writer.push(number);
                }
            }
        private:
            signature_subpacket_type    _type;
            std::vector<uint8_t>        _data;
    };

}
