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
            string_to_key(decoder &parser);

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
            void encode(encoder &writer) const;
        private:
            uint8   _convention;    // the string-to-key usage convention
    };

}
