#include "multiprecision_integer.h"
#include "util/narrow_cast.h"
#include <type_traits>


namespace pgp {

    namespace {

        template <typename T, typename = typename std::enable_if<std::is_integral<T>::value && sizeof(T) <= 8>::type>
        uint8_t count_leading_zeros(T value)
        {
            // lookup table for number of leading zeroes
            static constexpr std::array<uint8_t, 16> clz_lookup{ 4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 };

            // for each nibble (4 bits) in the number, starting with the most
            // significant nibble
            for (int i = 2 * sizeof(T) - 1; i >= 0; i--) {
                // get the current nibble from the value
                uint8_t nibble = (value >> (4 * i)) & 0x0f;

                // if the leading zeros end here
                if (nibble != 0) {
                    // compute the number of leading zeros and return
                    uint8_t preceding_nibbles = 2 * sizeof(T) - 1 - i;
                    return 4 * preceding_nibbles + clz_lookup[nibble];
                }
            }

            // the number must be zero in this case
            return 8 * sizeof(T);
        }

    }

    /**
     *  Constructor
     *
     *  @param  data    The range of numbers
     */
    multiprecision_integer::multiprecision_integer(span<const uint8_t> data) noexcept
    {
        // assign the data
        operator=(data);
    }

    /**
     *  Constructor
     *
     *  @param  data    The range of numbers
     */
    multiprecision_integer::multiprecision_integer(std::vector<uint8_t> data) noexcept
    {
        // assign the data
        operator=(data);
    }

    /**
     *  Constructor
     *
     *  @param  integer The Crypto++ integer to convert
     */
    multiprecision_integer::multiprecision_integer(const CryptoPP::Integer &integer) noexcept
    {
        // assign the integer
        operator=(integer);
    }


    /**
     *  Assignment
     *
     *  @param  data    The data to assign
     *  @return Same object for chaining
     */
    multiprecision_integer &multiprecision_integer::operator=(span<const uint8_t> data) noexcept
    {
        // eliminate leading zeroes
        while (!data.empty() && data[0] == 0) {
            // detected zero entry - eliminating
            data = data.subspan<1>();
        }

        // if there is no data, just clear out
        if (data.empty()) {
            // store the empty integer (zero)
            _data.clear();
            _bits = 0;
            return *this;
        }

        // calculate number of leading zeroes
        auto leading_zeroes = count_leading_zeros(data[0]);

        // assign bit count and the data
        _bits = util::narrow_cast<uint16_t>(data.size() * 8 - leading_zeroes);
        _data.assign(data.begin(), data.end());

        // allow chaining
        return *this;
    }

    multiprecision_integer &multiprecision_integer::operator=(std::vector<uint8_t> data) noexcept
    {
        // erase any leading zero bytes
        data.erase(
            std::begin(data),
            std::find_if(std::begin(data), std::end(data), [](uint8_t b) { return b != 0; })
        );

        // if the given range is empty, just clear out
        if (data.empty()) {
            // store the empty integer (zero)
            _data.clear();
            _bits = 0;
            return *this;
        }

        // otherwise, move in the data buffer
        _data = std::move(data);

        // calculate number of leading zeroes
        auto leading_zeroes = count_leading_zeros(_data[0]);

        // assign bit count
        _bits = util::narrow_cast<uint16_t>(_data.size() * 8 - leading_zeroes);

        // allow chaining
        return *this;
    }

    /**
     *  Assignment
     *
     *  @param  integer The data to assign
     *  @return Same object for chaining
     */
    multiprecision_integer &multiprecision_integer::operator=(const CryptoPP::Integer &integer) noexcept
    {
        // get the number of bytes required
        size_t encoded_size = integer.MinEncodedSize();

        // resize our buffer to match
        _data.resize(encoded_size);

        // encode the Crypto++ integer to our buffer
        integer.Encode(_data.data(), encoded_size);

        // calculate number of leading zeroes
        auto leading_zeroes = count_leading_zeros(_data[0]);

        // assign bit count
        _bits = util::narrow_cast<uint16_t>(_data.size() * 8 - leading_zeroes);

        // allow chaining
        return *this;
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool multiprecision_integer::operator==(const multiprecision_integer &other) const noexcept
    {
        return data() == other.data();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool multiprecision_integer::operator!=(const multiprecision_integer &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t multiprecision_integer::size() const noexcept
    {
        // two bytes for the header plus all the fields
        return _bits.size() + _data.size();
    }

    /**
     *  Retrieve the data
     *  @return A span containing all the integer numbers
     */
    span<const uint8_t> multiprecision_integer::data() const noexcept
    {
        // provide access to the underlying vector
        return _data;
    }

    multiprecision_integer::operator CryptoPP::Integer() const noexcept
    {
        // construct the Crypto++ Integer with our data bytes; note that this
        // is correct since both are in big-endian
        return CryptoPP::Integer(_data.data(), _data.size());
    }

}
