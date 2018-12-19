#pragma once

#include <gsl/span>
#include <stdexcept>
#include <mpark/variant.hpp>
#include "unknown_packet.h"
#include "public_key.h"
#include "secret_key.h"
#include "packet_tag.h"
#include "signature.h"
#include "user_id.h"
#include "decoder.h"
#include "encoder.h"


namespace pgp {

    /**
     *  Class for working with a single packet header encoded
     *  according to the specification in RFC 4880
     *  @see: https://tools.ietf.org/html/rfc4880#section-4
     */
    class packet
    {
        public:
            /**
             *  The valid packets we can decode
             */
            using packet_variant = mpark::variant<
                unknown_packet,
                signature,
                secret_key,
                public_key,
                user_id
            >;

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
             *  @param  ...,    The parameters to provide to the body constructor
             *  @throws Forwards exception from body constructor
             */
            template <class T, typename... Arguments>
            packet(mpark::in_place_type_t<T>, Arguments&& ...parameters) :
                _body{ mpark::in_place_type_t<T>{}, std::forward<Arguments>(parameters)... }
            {}

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
            size_t size() const;

            /**
             *  Retrieve the decoded packet
             *
             *  @return The packet that was parsed
             */
            const packet_variant &body() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            packet_variant  _body;  // the decoded packet
    };

}
