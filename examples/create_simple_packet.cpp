#include <pgp-packet/packet.h>
#include <sodium.h>
#include <iostream>

int main()
{
    // initialize libsodium
    if (sodium_init() == -1) {
        return 1;
    }

    // when constructing a packet we must specify the body type that
    // is to be contained within the packet; the constructor for the
    // packet uses the same pattern a regular std::variant uses when
    // forwarding constructors. the first - unnamed - parameter sets
    // the alternative to construct inside the variant, while others
    // get forwarded to the constructor of the selected alternative.
    //
    // since a user_id packet has a constructor using an std::string
    // we can construct a user_id packet like this:
    pgp::packet packet{
        pgp::in_place_type_t<pgp::user_id>{},
        std::string{ "Anne Onymous <anonymous@example.org>" }
    };

    // packets have a tag function, which returns an enum indicating
    // the type of packet contained inside the body. there is a free
    // function called packet_tag_description which can be used when
    // debugging or otherwise creating a description of a packet.
    std::cout
        << "Packet type: "
        << pgp::packet_tag_description(packet.tag())
        << std::endl;

    // besides getting the packet type, using the tag() function, it
    // is also possible to get to the body of the packet through the
    // body() function of the packet. since this is simply a variant
    // as provided by the STL, it can either be visit()'ed (whenever
    // writing generic code), or an explicit std::get can be done to
    // retrieve a specific type of body - which could throw an error
    // if the body is of a different type than the one requested. in
    // this case we are certain that the body will contain a user_id
    auto &body = pgp::get<pgp::user_id>(packet.body());

    // now we have access to the user_id body, which provides simple
    // getters for its relevant members. in this case, it's only the
    // id itself that is stored, which can be retrieved using the id
    // member function.
    std::cout
        << "Stored user id: "
        << body.id()
        << std::endl;

    return 0;
}
