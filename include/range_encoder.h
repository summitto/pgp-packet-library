#pragma once

#include <boost/endian/conversion.hpp>
#include <type_traits>
#include "util/span.h"
#include <cstring>
#include <limits>
#include "util/transaction.h"


namespace pgp {

    /**
     *  Class for encoding packet data
     *  into a pre-allocated range of bytes
     */
    class range_encoder
    {
        public:
            /**
             *  Constructor
             *
             *  @param  data    The range to encode to
             */
            range_encoder(span<uint8_t> data);

            /**
             *  Flush the encoder, so any partial-written bytes
             *  are written out. Note that after this operation,
             *  bitwise operations start at the beginning again.
             */
            void flush() noexcept;

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
            range_encoder &insert_bits(size_t count, uint8_t value);

            /**
             *  Push a number to the encoder
             *
             *  @param  value   The number to push
             *  @return self, for chaining
             *  @throws std::out_of_range, std::range_error
             */
            template <typename T>
            typename std::enable_if_t<std::numeric_limits<T>::is_integer, range_encoder&>
            push(T value)
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
                T result = static_cast<T>(static_cast<T>(_current) << ((sizeof(T) - 1) * 8));

                // add the new value to it
                result |= value;

                // convert it to big-endian
                // Note that in some boost versions, boost::endian::endian_reverse is not
                // explicitly overloaded for 'char' but only for the {,u}int{8,16,32,64}_t
                // types. Since char != int8_t, the compiler selects the int=int32_t
                // overload over the int8_t overload, making the conversion go awry.
                // Explicitly converting to an unsigned type works around this issue.
                // (Explicitly converting back avoids a possible -Wsign-conversion.)
                result = static_cast<T>(
                    boost::endian::native_to_big(static_cast<std::make_unsigned_t<T>>(result))
                );

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
            typename std::enable_if_t<std::is_enum<T>::value, range_encoder&>
            push(T value)
            {
                // cast it to a number and insert it
                return push(static_cast<typename std::underlying_type_t<T>>(value));
            }

            /**
             *  Push a range of data
             *
             *  @param  begin   The iterator to the beginning of the data
             *  @param  end     The iterator to the end of the data
             *  @return self, for chaining
             *  @throws std::out_of_range, std::range_error
             */
            template <typename iterator_t>
            range_encoder &push(iterator_t begin, iterator_t end)
            {
                // note: possible c++20 optimization
                // // do we have a contiguous range of memory?
                // if constexpr(std::is_same_v<std::iterator_traits<iterator_t>::iterator_category, std::contiguous_iterator_tag>) {
                //     // make sure we have enough data for inserting the data
                //     if (_data.size() < _size + sizeof(T) * value.size()) {
                //         // trying to write out-of-bounds
                //         throw std::out_of_range{ "Buffer too small for inserting blob" };
                //     }
                //
                //     // push the whole range at once
                //     std::memcpy(_data.data() + _size, value.data(), value.size() * sizeof(T));
                //
                //     // register the bytes in the buffer
                //     _size += value.size() * sizeof(T);
                // }

                util::transaction transaction([this, size_val=_size, current_val=_current, skip_bits_val=_skip_bits]() {
                    _size = size_val;
                    _current = current_val;
                    _skip_bits = skip_bits_val;
                });

                // iterate over the range
                while (begin != end) {
                    // push the data
                    push(*begin);

                    // move to next element
                    ++begin;
                }

                transaction.commit();

                // allow chaining
                return *this;
            }

            /**
             *  Insert a blob of data
             *
             *  @param  value   The data to insert
             *  @return self, for chaining
             *  @throws std::out_of_range, std::range_error
             */
            template <typename T>
            range_encoder &insert_blob(span<const T> value)
            {
                if (value.empty()) {
                    // nothing to do if the input is empty
                    return *this;
                }

                // make sure we have enough data for inserting the number
                if (_data.size() < _size + sizeof(T) * value.size()) {
                    // trying to write out-of-bounds
                    throw std::out_of_range{ "Buffer too small for inserting blob" };
                }

                // add the first value using push() to merge in the possible queued bits
                push(value[0]);

                // then copy the rest of the data into the buffer
                std::memcpy(_data.data() + _size, value.data() + 1, (value.size() - 1) * sizeof(T));

                // register the bytes in the buffer
                _size += (static_cast<size_t>(value.size()) - 1) * sizeof(T);

                // allow chaining
                return *this;
            }
        private:
            span<uint8_t>       _data;              // the range to encode to
            size_t              _size       { 0 };  // number of bytes written
            uint8_t             _current    { 0 };  // the current byte we are working on
            uint8_t             _skip_bits  { 0 };  // number of bits to skip from data
    };

}
