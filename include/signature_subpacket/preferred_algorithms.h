#pragma once

#include "../signature_subpacket_type.h"
#include "../symmetric_key_algorithm.h"
#include "../compression_algorithm.h"
#include "../hash_algorithm.h"
#include "../variable_number.h"
#include "../fixed_number.h"
#include <vector>


namespace pgp::signature_subpacket {

    /**
     *  Generic class for handling signature subpackets
     *  containing an array of one-octet values
     */
    template <signature_subpacket_type subpacket_type, typename algorithm>
    class preferred_algorithms
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The parser to decode the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            explicit preferred_algorithms(decoder &parser)
            {
                // allocate memory for the data
                _data.reserve(parser.size());

                // process bytes until we run out
                while (!parser.empty()) {
                    // one more octet
                    _data.push_back(algorithm{ parser.template extract_number<std::underlying_type_t<algorithm>>() });
                }
            }

            /**
             *  Constructor
             *
             *  @param  data    The data to store
             */
            explicit preferred_algorithms(std::vector<algorithm> data) :
                _data{ std::move(data) }
            {}

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const preferred_algorithms<subpacket_type, algorithm> &other) const noexcept
            {
                return data() == other.data();
            }

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator!=(const preferred_algorithms<subpacket_type, algorithm> &other) const noexcept
            {
                return !operator==(other);
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept
            {
                // we need to store the data plus the type
                uint32_t size = sizeof(std::underlying_type_t<algorithm>) * _data.size() + sizeof(subpacket_type);

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
             *  Retrieve the stored number
             *
             *  @return The stored number
             */
            gsl::span<const algorithm> data() const noexcept
            {
                // retrieve the stored number
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
                uint32_t size = sizeof(std::underlying_type_t<algorithm>) * _data.size() + sizeof(subpacket_type);

                // encode the size and type
                variable_number{ size }.encode(writer);
                writer.push(subpacket_type);

                // iterate over the data
                for (auto algo : _data) {
                    // write it to the encoder
                    writer.push(algo);
                }
            }
        private:
            std::vector<algorithm>  _data;
    };

    /**
     *  Specialize the different subpacket types available
     */
    using preferred_symmetric_algorithms    = preferred_algorithms<signature_subpacket_type::preferred_symmetric_algorithms,    symmetric_key_algorithm>;
    using preferred_hash_algorithms         = preferred_algorithms<signature_subpacket_type::preferred_hash_algorithms,         hash_algorithm>;
    using preferred_compression_algorithms  = preferred_algorithms<signature_subpacket_type::preferred_compression_algorithms,  compression_algorithm>;

}
