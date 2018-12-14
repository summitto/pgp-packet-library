#pragma once

#include <gsl/span>
#include <stdexcept>
#include <boost/optional.hpp>
#include "packet_tag.h"
#include "decoder.h"
#include "encoder.h"


namespace pgp {

    /**
     *  Class for working with a single packet encoded
     *  according to the specification in RFC 4880
     *  @see: https://tools.ietf.org/html/rfc4880#section-4
     */
    class packet
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             *  @throws std::runtime_error
             */
            packet(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  tag     The packet tag
             *  @param  size    The size of the body
             *  @throws std::runtime_error
             */
            packet(packet_tag tag, boost::optional<size_t> size);

            /**
             *  Retrieve the packet tag
             *  @return The packet tag, as described in https://tools.ietf.org/html/rfc4880#section-4.3
             */
            packet_tag tag() const noexcept;

            /**
             *  Retrieve the body length
             *
             *  @note   If the body length is unknown, no size will be returned
             *  @return The number of bytes in the body of the packet
             */
            boost::optional<size_t> size() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            packet_tag              _tag    { packet_tag::reserved  };  // the packet tag
            boost::optional<size_t> _size   { 0                     };  // number of bytes in the body
    };

}
