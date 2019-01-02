#include "packet.h"
#include <boost/optional.hpp>
#include "variable_number.h"
#include <cstring>


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     *  @throws TODO
     */
    packet::packet(decoder &parser)
    {
        // check whether we have the required true bit
        if (!parser.extract_bits(1)) {
            // a bit that is required to be set is not set
            throw std::runtime_error{ "Invalid packet: Required header tag bit not set"};
        }

        // the packet tag we are processing and the size of it
        packet_tag                  tag;
        boost::optional<uint32_t>   size;

        // is this a packet using the new formatting?
        if (parser.extract_bits(1)) {
            // extract packet type and size
            tag  = packet_tag{ parser.extract_bits(6) };
            size = variable_number{ parser };
        } else {
            // extract packet type
            tag = packet_tag{ parser.extract_bits(4) };

            // what length type do we have
            switch (parser.extract_bits(2)) {
                case 0: size = parser.extract_number<uint8_t>();    break;
                case 1: size = parser.extract_number<uint16_t>();   break;
                case 2: size = parser.extract_number<uint32_t>();   break;
                case 3:  /* no size is known */                     break;
            }
        }

        // create a parser to hold only the body data
        // and a pointer to the parser we will use
        decoder body_parser;
        decoder *parser_ptr;

        // if we have a known size, we splice off the data,
        // otherwise we keep using the existing decoder
        if (size) {
            // splice off the data and use the body parser
            body_parser = parser.splice(*size);
            parser_ptr  = &body_parser;
        } else {
            // we don't know the size, so we will use
            // the entire, unrestrained parser instead
            parser_ptr  = &parser;
        }

        // can we decode the packet?
        switch (tag) {
            case packet_tag::signature:     _body.emplace<signature>(*parser_ptr);      break;
            case packet_tag::secret_key:    _body.emplace<secret_key>(*parser_ptr);     break;
            case packet_tag::public_key:    _body.emplace<public_key>(*parser_ptr);     break;
            case packet_tag::secret_subkey: _body.emplace<secret_subkey>(*parser_ptr);  break;
            case packet_tag::user_id:       _body.emplace<user_id>(*parser_ptr);        break;
            case packet_tag::public_subkey: _body.emplace<public_subkey>(*parser_ptr);  break;
            default:
                // TODO
                break;
        }
    }

    /**
     *  Retrieve the packet tag
     *  @return The packet tag, as described in https://tools.ietf.org/html/rfc4880#section-4.3
     */
    packet_tag packet::tag() const noexcept
    {
        // the tag to return
        packet_tag result;

        // retrieve the body
        mpark::visit([&result](auto &body) {
            // retrieve the tag from the body
            result = body.tag();
        }, _body);

        // return the retrieved tag
        return result;
    }

    /**
     *  Retrieve the body length
     *
     *  @note   If the body length is unknown, no size will be returned
     *  @return The number of bytes in the body of the packet
     */
    size_t packet::size() const
    {
        // the body size to return
        size_t result;

        // retrieve the body
        mpark::visit([&result](auto &body) {
            // retrieve the size from the body
            result = body.size();
        }, _body);

        // return the retrieved size
        return result;
    }

    /**
     *  Retrieve the decoded packet
     *
     *  @return The packet that was parsed
     */
    const packet::packet_variant &packet::body() const noexcept
    {
        // return the decoded body
        return _body;
    }

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void packet::encode(encoder &writer) const
    {
        // write the required bit
        writer.insert_bits(1, 1);

        // can we encode the packet in the old format?
        if (packet_tag_compatible_with_old_format(tag())) {
            // we are using the old packet format
            writer.insert_bits(1, 0);
            writer.insert_bits(4, static_cast<typename std::underlying_type_t<packet_tag>>(tag()));

            // do we know the size? determine the right storage type
            if (size() > 65535) {
                // we are using a 4-octet length field
                writer.insert_bits(2, 2);
                writer.insert_number(static_cast<uint32_t>(size()));
            } else if (size() > 255) {
                // we are using a 2-octet length field
                writer.insert_bits(2, 1);
                writer.insert_number(static_cast<uint16_t>(size()));
            } else {
                // it fits in a single octet
                writer.insert_bits(2, 0);
                writer.insert_number(static_cast<uint8_t>(size()));
            }
        } else {
            // we are using the new packet format
            writer.insert_bits(1, 1);
            writer.insert_bits(6, static_cast<typename std::underlying_type_t<packet_tag>>(tag()));

            // add the size of the packet as well
            variable_number{ static_cast<uint32_t>(size()) }.encode(writer);
        }

        // now retrieve the body
        mpark::visit([&writer](auto &body) {
            // and encode it as well
            body.encode(writer);
        }, body());
    }

}
