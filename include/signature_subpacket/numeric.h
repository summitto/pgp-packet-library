#pragma once

#include "../signature_subpacket_type.h"
#include "../variable_number.h"
#include "../fixed_number.h"


namespace pgp::signature_subpacket {

    /**
     *  Generic class for a simple, numeric signature subpacket
     */
    template <typename T, signature_subpacket_type subpacket_type>
    class numeric
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The parser to decode the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            numeric(decoder &parser) :
                _data{ parser }
            {
                // all data should be consumed
                if (!parser.empty()) {
                    // this is probably not the correct subpacket type
                    throw std::runtime_error{ "Incorrect subpacket type detected" };
                }
            }

            /**
             *  Constructor
             *
             *  @param  number  The number to store
             */
            numeric(T number) :
                _data{ number }
            {}

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const numeric<T, subpacket_type> &other) const noexcept
            {
                return data() == other.data();
            }

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator!=(const numeric<T, subpacket_type> &other) const noexcept
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
                uint32_t size = _data.size() + sizeof(subpacket_type);

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
            T data() const noexcept
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
                uint32_t size = _data.size() + sizeof(subpacket_type);

                // encode the size, the type, and the number
                variable_number{ size }.encode(writer);
                writer.push(subpacket_type);
                _data.encode(writer);
            }
        private:
            fixed_number<T> _data;  // the actual number we store
    };

    /**
     *  Specialize the different subpacket types available
     */
    using signature_creation_time     = numeric<uint32_t, signature_subpacket_type::signature_creation_time>;
    using signature_expiration_time   = numeric<uint32_t, signature_subpacket_type::signature_expiration_time>;
    using exportable_certification    = numeric<uint8_t,  signature_subpacket_type::exportable_certification>;
    using revocable                   = numeric<uint8_t,  signature_subpacket_type::revocable>;
    using primary_user_id             = numeric<uint8_t,  signature_subpacket_type::primary_user_id>;
    using key_expiration_time         = numeric<uint32_t, signature_subpacket_type::key_expiration_time>;

}
