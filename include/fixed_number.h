#pragma once

#include "decoder_traits.h"
#include <cstdint>
#include <cstddef>


namespace pgp {

    /**
     *  Class implementing a number compatible with the
     *  PGP RFC, using a fixed number of encoded octets
     */
    template <typename T>
    class fixed_number
    {
        public:
            /**
             *  Constructor
             */
            constexpr fixed_number() = default;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            fixed_number(decoder &&parser) :
                _value{ parser.template extract_number<T>() }
            {}

            /**
             *  Constructor
             *
             *  @param  value   The value to hold
             */
            constexpr fixed_number(T value) noexcept :
                _value{ value }
            {}

            /**
             *  Assignment operator
             *
             *  @param  parser  The parser to assign the value from
             *  @return self, for chaining
             */
            template <class decoder>
            std::enable_if_t<is_decoder_v<decoder>, fixed_number> &operator=(decoder &&parser)
            {
                // update value
                _value = parser.template extract_number<T>();

                // allow chaining
                return *this;
            }

            /**
             *  Assignment operator
             *
             *  @param  value   The value to assign
             *  @return self, for chaining
             */            
            constexpr fixed_number &operator=(T value) noexcept
            {              
                // update value
                _value = value;

                // allow chaining
                return *this;
            }

            /**
             *  Determine the size used in encoded format
             *
             *  @return The number of bytes used for encoded storage
             */
            static constexpr size_t size() noexcept
            {
                // just use the size of the value
                return sizeof(T);
            }

            /**
             *  Extract the stored value
             *
             *  @return The stored value
             */
            constexpr operator T() const noexcept
            {
                // return the stored value
                return _value;
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
                // write the number to the encoder
                writer.push(_value);
            }
        private:
            T   _value{ 0 };
    };

    /**
     *  Alias the commonly-used types
     */
    using uint8     = fixed_number<uint8_t>;
    using uint16    = fixed_number<uint16_t>;
    using uint32    = fixed_number<uint32_t>;

}
