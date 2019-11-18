#pragma once

#include <boost/utility/string_view.hpp>


namespace pgp {

    /**
     *  The available compression algorithms
     */
    enum class compression_algorithm : uint8_t
    {
        uncompressed    =  0,
        zip             =  1,
        zlib            =  2,
        bzip2           =  3,
    };

    /**
     *  Get a description of the compression algorithm
     *
     *  @param  algorithm   The algorithm to get a description for
     *  @return The description of the algorithm
     */
    constexpr boost::string_view compression_algorithm_description(compression_algorithm algorithm) noexcept
    {
        // check the given algorithm
        switch (algorithm) {
            case compression_algorithm::uncompressed:   return "uncompressed";
            case compression_algorithm::zip:            return "zip";
            case compression_algorithm::zlib:           return "zlib";
            case compression_algorithm::bzip2:          return "bzip2";
        }

        // unknown algorithm found
        return "unknown compression algorithm";
    }

}
