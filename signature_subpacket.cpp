#include "signature_subpacket.h"
#include "variable_number.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    signature_subpacket::signature_subpacket(decoder &parser)
    {
        // first, read the size of the subpacket
        uint32_t length = variable_number{ parser };

        // now read the subpacket type
        _type = signature_subpacket_type{ parser.extract_number<uint8_t>() };

        // the length includes the type - which we already read
        --length;

        // reserve memory for the data
        _data.reserve(length);

        // and fill the buffer
        while (_data.size() < length) {
            // add another byte
            _data.push_back(parser.extract_number<uint8_t>());
        }
    }
        

    /**
     *  Constructor
     *
     *  @param  type    The signature subpacket type
     *  @param  data    The data contained in the subpacket
     */
    signature_subpacket::signature_subpacket(signature_subpacket_type type, gsl::span<const uint8_t> data) :
        _type{ type },
        _data{ data.begin(), data.end() }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t signature_subpacket::size() const noexcept
    {
        // we need to encode the type and the data and encode that
        // size again using variable-length packet encoding
        uint32_t size = sizeof(_type) + _data.size();

        // now add the size necessary to encode the size itself
        return size + variable_number{ size }.size();
    }

    /**
     *  Get the signature subpacket type
     *  @return The type of signature subpacket
     */
    signature_subpacket_type signature_subpacket::type() const noexcept
    {
        // return the stored type
        return _type;
    }

    /**
     *  Retrieve the data
     *  @return A span containing all the integer numbers
     */
    gsl::span<const uint8_t> signature_subpacket::data() const noexcept
    {
        // return the stored data
        return _data;
    }

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void signature_subpacket::encode(encoder &writer) const
    {
        // first encode the length of the subpacket
        variable_number{ static_cast<uint32_t>(sizeof(_type) + _data.size()) }.encode(writer);

        // add the subpacket type
        writer.insert_enum(_type);

        // now go over the whole data set
        for (auto number : _data) {
            // add the number
            writer.insert_number<uint8_t>(number);
        }
    }

}
