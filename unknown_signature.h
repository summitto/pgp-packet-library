#pragma once


namespace pgp {

    /**
     *  Class for holding an unknown signature
     */
    class unknown_signature
    {
        public:
            /**
             *  Constructor
             */
            unknown_signature() = default;
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            unknown_signature(decoder &parser) noexcept {}

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const
            {
                // we do not know the size
                throw std::runtime_error{ "Unknown signatures have an unknown size" };
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
                // unknown key cannot be encoded
                throw std::runtime_error{ "Failed to encode unknown signature" };
            }
    };

}
