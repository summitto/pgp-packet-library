#pragma once

#include "fixed_number.h"


namespace pgp {

    /**
     *  Class for holding the complete string-to-key
     *  convention used for a secret or symmetric key
     */
    class string_to_key
    {
        public:
            /**
             *  Constructor
             */
            string_to_key() = default;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            string_to_key(decoder &parser) :
                _convention{ parser }
            {
                // @TODO: support other conventions than "nothing"
            }

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const string_to_key &other) const noexcept;
            bool operator!=(const string_to_key &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the convention used
             *
             *  @return The string-to-key convention
             */
            uint8_t convention() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // encode the convention
                _convention.encode(writer);
            }
        private:
            uint8   _convention;    // the string-to-key usage convention
    };

}
