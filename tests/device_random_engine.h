#pragma once

#include <random>


namespace tests {
    class device_random_engine {
    public:
        using driver_engine = std::mt19937;
        using result_type = driver_engine::result_type;

        device_random_engine();

        result_type operator()() noexcept;

        static constexpr result_type min() noexcept
        {
            return driver_engine::min();
        }
        static constexpr result_type max() noexcept
        {
            return driver_engine::max();
        }

    private:
        driver_engine engine;
    };
}
