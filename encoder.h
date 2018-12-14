#pragma once

#include <boost/endian/conversion.hpp>
#include <type_traits>
#include <gsl/span>
#include <cstring>
#include <limits>


namespace pgp {

    /**
     *  Class for encoding packet data
     */
    class encoder
    {
        public:
            /**
             *  Constructor
             *
             *  @param  data    The range to encode to
             */
            encoder(gsl::span<uint8_t> data);

            /**
             *  Flush the encoder, so any partial-written bytes
             *  are written out. Note that after this operation,
             *  bitwise operations start at the beginning again.
             *
             *  @throws std::out_of_range
             */
            void flush();

            /**
             *  Retrieve the number of encoded bytes
             *  @return The number of bytes stored in the encoder
             */
            size_t size() const noexcept;

            /**
             *  Insert one or more bits
             *
             *  @param  count   The number of bits to insert
             *  @param  value   The value to store in the bits
             *  @return self, for chaining
             *  @throws std::out_of_range, std::range_error
             */
            encoder &insert_bits(size_t count, uint8_t value);

            /**
             *  Insert a number
             *
             *  @param  value   The number to insert
             *  @return self, for chaining
             *  @throws std::out_of_range, std::range_error
             */
            template <typename T>
            encoder &insert_number(T value)
            {
                // make sure we have enough data for inserting the number
                if (_data.size() < _size + sizeof(T)) {
                    // trying to write out-of-bounds
                    throw std::out_of_range{ "Buffer too small for inserting number" };
                }

                // ensure that masking the number doesn't change it
                if ((value & (std::numeric_limits<T>::max() >> _skip_bits)) != value) {
                    // the number is out of range because it has bits set which should be masked
                    throw std::range_error{ "Cannot insert number, masked bits are set" };
                }

                // retrieve the currently-set bits and shift them to the left of the number
                T result = _current << ((sizeof(T) - 1) * 8);

                // add the new value to it
                result |= value;

                // convert it to big-endian
                boost::endian::native_to_big_inplace(result);

                // copy the data over
                std::memcpy(_data.data() + _size, &result, sizeof(T));

                // move to the next bytes
                _size += sizeof(T);
                _skip_bits = 0;

                // allow chaining
                return *this;
            }

            /**
             *  Insert an enum
             *
             *  @param  value   The enum to insert
             *  @return self, for chaining
             *  @throws std::out_of_range, std::range_error
             */
            template <typename T>
            encoder &insert_enum(T value)
            {
                // cast it to a number and insert it
                return insert_number(static_cast<typename std::underlying_type_t<T>>(value));
            }
        private:
            gsl::span<uint8_t>  _data;              // the range to encode to
            size_t              _size       { 0 };  // number of bytes written
            uint8_t             _current    { 0 };  // the current byte we are working on
            uint8_t             _skip_bits  { 0 };  // number of bits to skip from data
    };

}
