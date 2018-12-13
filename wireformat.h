#include <gsl/span>

namespace pgp {

    /**
     *  Class to handle the encoded wire format used
     *  in RFC 4880
     */
    class wireformat
    {
        public:
            /**
             *  Constructor
             *
             *  @param  data    The range to (de|en)code from or to
             */
            wireformat(gsl::span<uint8_t> data) noexcept;

            /**
             *  Peek at bits at the current position, but
             *  do not consume them
             *
             *  @param  count   Number of bits to extract
             *  @return The extracted bits
             *  @throws std::out_of_range
             */
            uint8_t peek_bits(size_t count) const;

            /**
             *  Extract bits at the current position
             *
             *  @param  count   Number of bits to extract
             *  @return The extracted bits
             *  @throws std::out_of_range
             */
            uint8_t extract_bits(size_t count);

            /**
             *  Peek at a number at the current position,
             *  but do not consume it
             *
             *  @return The extracted number
             *  @throws std::out_of_range
             */
            template <typename T>
            T peek_number() const;

            /**
             *  Extract a number at the current position
             *
             *  @return The extracted number
             *  @throws std::out_of_range
             */
            template <typename T>
            T extract_number();
        private:
            /**
             *  Mask the number, removing already-ready bits
             *
             *  @param  number  The number to mask bytes in
             */
            template <typename T>
            T mask(T number) const noexcept;

            gsl::span<uint8_t>  _data;              // the raw data to work with
            uint8_t             _skip_bits  { 0 };  // number of bits to skip from data
    };

}
