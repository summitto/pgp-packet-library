#pragma once

#include "../signature_subpacket_type.h"
#include "../variable_number.h"
#include "../expected_number.h"
#include "../fixed_number.h"


namespace pgp::signature_subpacket {

    /**
     *  Class for the issuer fingerprint subpacket
     */
    class issuer_fingerprint
    {
        public:
            /**
             *  The size in bytes of an issuer fingerprint
             */
            static constexpr size_t fingerprint_size = 20;

            /**
             *  Constructor
             *
             *  @param  parser  The parser to decode the data
             */
            issuer_fingerprint(decoder &parser) :
                _version{ parser }
            {
                // retrieve data from the decoder
                auto data = parser.extract_blob<uint8_t>(fingerprint_size);

                // copy the data over
                std::copy(data.begin(), data.end(), _data.begin());
            }

            /**
             *  Constructor
             *
             *  @param  data    The array of data
             */
            issuer_fingerprint(std::array<uint8_t, fingerprint_size> data) noexcept :
                _data{ data }
            {}

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const issuer_fingerprint &other) const noexcept
            {
                return data() == other.data();
            }

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator!=(const issuer_fingerprint &other) const noexcept
            {
                return !operator==(other);
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept
            {
                // we need to store the number, together with the type and the key version
                uint32_t size = gsl::narrow_cast<uint32_t>(_data.size() + _version.size() + sizeof(type()));

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
                return signature_subpacket_type::issuer_fingerprint;
            }

            /**
             *  Retrieve the stored array
             *
             *  @return The stored array
             */
            const std::array<uint8_t, fingerprint_size> &data() const noexcept
            {
                // retrieve the stored array
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
                uint32_t size = gsl::narrow_cast<uint32_t>(_data.size() + _version.size() + sizeof(type()));

                // encode the size, the type, and the number
                variable_number{ size }.encode(writer);
                writer.push(type());
                _version.encode(writer);
                writer.template insert_blob<uint8_t>(_data);
            }
        private:
            expected_number<uint8_t, 4>            _version;  // the expected key version format
            std::array<uint8_t, fingerprint_size>  _data;     // the array of data
    };

}
