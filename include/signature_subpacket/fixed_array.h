#pragma once

#include "../signature_subpacket_type.h"
#include "../variable_number.h"
#include "../fixed_number.h"


namespace pgp::signature_subpacket {

    /**
     *  Generic class for a simple signature subpacket
     *  with a fixed-size array of bytes
     */
    template <size_t data_size, signature_subpacket_type subpacket_type>
    class fixed_array
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The parser to decode the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            fixed_array(decoder &parser)
            {
                // retrieve data from the decoder
                auto data = parser.template extract_blob<uint8_t>(data_size);

                // copy the data over
                std::copy(data.begin(), data.end(), _data.begin());
            }

            /**
             *  Constructor
             *
             *  @param  data    The array of data
             */
            fixed_array(std::array<uint8_t, data_size> data) noexcept :
                _data{ data }
            {}

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const fixed_array<data_size, subpacket_type> &other) const noexcept
            {
                return data() == other.data();
            }

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator!=(const fixed_array<data_size, subpacket_type> &other) const noexcept
            {
                return !operator==(other);
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept
            {
                // we need to store the number plus the type
                uint32_t size = util::narrow_cast<uint32_t>(_data.size() + sizeof(subpacket_type));

                // and then store this number in a variable number
                return size + variable_number{ size }.size();
            }

            /**
             *  Get the signature subpacket type
             *  @return The type of signature subpacket
             */
            static constexpr signature_subpacket_type type() noexcept
            {
                // return the static type
                return subpacket_type;
            }

            /**
             *  Retrieve the stored array
             *
             *  @return The stored array
             */
            const std::array<uint8_t, data_size> &data() const noexcept
            {
                // retrieve the stored array
                return _data;
            }

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // first get the size for the data itself
                uint32_t size = util::narrow_cast<uint32_t>(_data.size() + sizeof(subpacket_type));

                // encode the size, the type, and the number
                variable_number{ size }.encode(writer);
                writer.push(subpacket_type);
                writer.template insert_blob<uint8_t>(_data);
            }
        private:
            std::array<uint8_t, data_size>  _data;  // the array of data
    };

    /**
     *  Specialize the different subpacket types available
     */
    using issuer  = fixed_array<8, signature_subpacket_type::issuer>;

}
