#pragma once

#include "decoder.h"
#include "encoder.h"


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
            fixed_number() = default;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            fixed_number(decoder &parser) :
                _value{ parser.extract_number<T>() }
            {}

            /**
             *  Constructor
             *
             *  @param  value   The value to hold
             */
            fixed_number(T value) noexcept :
                _value{ value }
            {}

            /**
             *  Assignment operator
             *
             *  @param  value   The value to assign
             *  @return self, for chaining
             */            
            fixed_number &operator=(T value) noexcept
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
            size_t size() const noexcept
            {
                // just use the size of the value
                return sizeof(T);
            }

            /**
             *  Extract the stored value
             *
             *  @return The stored value
             */
            operator T() const noexcept
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
            void encode(encoder &writer) const
            {
                // write the number to the encoder
                writer.insert_number(_value);
            }
        private:
            T   _value{ 0 };
    };

}
