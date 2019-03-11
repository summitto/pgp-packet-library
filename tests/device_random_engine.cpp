#include "device_random_engine.h"


namespace tests {
    device_random_engine::device_random_engine() :
        engine(std::random_device()())
    {}

    device_random_engine::result_type device_random_engine::operator()() noexcept
    {
        return engine();
    }

    device_random_engine::result_type device_random_engine::min() noexcept
    {
        return driver_engine::min();
    }

    device_random_engine::result_type device_random_engine::max() noexcept
    {
        return driver_engine::max();
    }
}
