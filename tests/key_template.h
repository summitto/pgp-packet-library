#pragma once

/**
 *  The aim of the utilities in this file is to streamline the writing of tests
 *  for the basic key classes like rsa_public_key, eddsa_secret_key, etc.
 *  The common pattern between these classes is that they store just a couple of
 *  fields and don't do any other processing besides encoding and decoding from
 *  a stream. Therefore, to test those classes, all that is necessary is to test
 *  whether the fields are stored correctly in the constructor, and whether they
 *  are kept over an encode-decode cycle.
 *
 *  Usage is by calling the 'key_test' function with the right template
 *  parameters. The 'Class' parameter is the key class to test, and the
 *  subsequent parameters describe the fields stored in the key class. These
 *  descriptors should be instantiations of one of the classes in the
 *  'parameters' namespace, which take as argument the member function pointer
 *  of the getter for the particular field.
 *
 *  An example, for ecdh_public_key:
 *      using key_type = pgp::ecdh_public_key;
 *      tests::key_test<key_type,
 *          tests::parameters::oid<&key_type::curve>,
 *          tests::parameters::mpi<&key_type::Q>,
 *          tests::parameters::hashalgo<&key_type::hash_function>,
 *          tests::parameters::keyalgo<&key_type::algorithm>>();
 *
 *  It is important that the arguments to the constructor of the key class are
 *  in this precise order.
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <random>
#include <vector>
#include <tuple>
#include <gtest/gtest.h>
#include "../range_encoder.h"
#include "../decoder.h"
#include "../multiprecision_integer.h"
#include "../curve_oid.h"
#include "../hash_algorithm.h"
#include "../symmetric_key_algorithm.h"
#include "device_random_engine.h"


namespace tests {
    namespace {
        template <typename ProxyT, typename ContainedT>
        struct type_proxy {
            using Proxy = ProxyT;
            using Contained = ContainedT;
            Contained value;

            template <typename DeducedContained>
            type_proxy(DeducedContained value) :
                value{std::forward<DeducedContained>(value)}
            {}

            bool operator==(const type_proxy<ProxyT, ContainedT> &other) const noexcept
            { return value == other.value; }

            bool operator!=(const type_proxy<ProxyT, ContainedT> &other) const noexcept
            { return !(*this == other); }
        };

        template <typename Class>
        void assert_eq(const Class&, const Class&)
        {}

        template <typename Class, typename Head, typename... Tail>
        void assert_eq(const Class &instance1, const Class &instance2)
        {
            ASSERT_EQ(Head::eq_project(instance1), Head::eq_project(instance2));
            assert_eq<Class, Tail...>(instance1, instance2);
        }

        template <std::size_t I, typename Visitor, typename... Args>
        typename std::enable_if<I >= sizeof...(Args), void>::type
        map_parameters(const std::tuple<Args...>&, Visitor)
        {}

        template <std::size_t I, typename Visitor, typename... Args>
        typename std::enable_if<I < sizeof...(Args), void>::type
        map_parameters(const std::tuple<Args...>& values, Visitor visitor)
        {
            visitor.template visit<typename std::remove_reference_t<decltype(std::get<I>(values))>::Proxy>(std::get<I>(values).value);
            map_parameters<I + 1, Visitor, Args...>(values, visitor);
        }

        template <typename Class>
        class assert_eq_visitor {
        public:
            assert_eq_visitor(const Class &instance) :
                _instance{instance}
            {}

            template <typename Arg>
            void visit(const typename Arg::Type &value)
            {
                ASSERT_EQ(Arg::eq_project(_instance), Arg::eq_project_type(value));
            }

        private:
            const Class &_instance;
        };

        template <typename Class, typename... Args>
        void assert_eq_original(const Class &instance, const std::tuple<Args...> &parameters)
        {
            map_parameters<0>(parameters, assert_eq_visitor<Class>{instance});
        }

        template <class T, class Tuple, std::size_t... I>
        constexpr T make_from_tuple_proxy_impl(Tuple&& tuple, std::index_sequence<I...>)
        {
            return T(std::get<I>(std::forward<Tuple>(tuple)).value...);
        }

        template <class T, class Tuple>
        constexpr T make_from_tuple_proxy(Tuple&& tuple)
        {
            return make_from_tuple_proxy_impl<T>(
                    std::forward<Tuple>(tuple),
                    std::make_index_sequence<std::tuple_size<std::remove_reference_t<Tuple>>::value>{});
        }
    }

    namespace detail {
        std::ostream& operator<<(std::ostream &os, const gsl::span<const uint8_t> &sp);
    }

    template <typename Class, typename... Args>
    void key_test()
    {
        // Give the randomiser a chance to do its work
        for (int iter = 0; iter < 100; iter++) {
            // First generate the parameters that this instance will be taking
            const std::tuple<type_proxy<Args, typename Args::Type>...> parameters =
                std::make_tuple<type_proxy<Args, typename Args::Type>...>(Args::generate()...);

            // std::cout << "argument 0: " << std::remove_reference_t<decltype(std::get<0>(parameters))>::Proxy::output_project_type(std::get<0>(parameters).value) << std::endl;

            // Construct the instance
            Class instance = make_from_tuple_proxy<Class>(parameters);

            // std::cout << "member 0:   " << std::remove_reference_t<decltype(std::get<0>(parameters))>::Proxy::output_project(instance) << std::endl;

            // Assert that the parameters are stored correctly in the instance
            assert_eq_original<Class, type_proxy<Args, typename Args::Type>...>(instance, parameters);

            // Encode the instance into a vector
            std::vector<uint8_t> data(instance.size());
            pgp::range_encoder encoder{data};
            instance.encode(encoder);

            // Assert that the .size() method does the right thing
            ASSERT_EQ(encoder.size(), instance.size());

            // Decode the encoded data and assert that its fields are equal to the original's fields
            pgp::decoder decoder{data};
            Class instance2{decoder};
            assert_eq<Class, Args...>(instance, instance2);

            // Also check the equality operator
            ASSERT_EQ(instance, instance2);

            // Make some different parameters to check operator!=
            const std::tuple<type_proxy<Args, typename Args::Type>...> diff_params =
                std::make_tuple<type_proxy<Args, typename Args::Type>...>(Args::generate()...);
            Class diff_instance = make_from_tuple_proxy<Class>(diff_params);

            if (parameters != diff_params) {
                ASSERT_NE(instance, diff_instance);
            }
        }
    }

    namespace parameters {
        namespace generate {
            extern thread_local device_random_engine random_engine;

            template <typename T>
            T random_choice(std::vector<T> options)
            {
                std::uniform_int_distribution<size_t> distr(0, options.size() - 1);
                return options[distr(random_engine)];
            }

            pgp::multiprecision_integer mpi();
            pgp::curve_oid oid();
            pgp::hash_algorithm hashalgo();
            pgp::symmetric_key_algorithm keyalgo();
        }

        template <auto member_function>
        struct oid {
            using Type = pgp::curve_oid;

            static Type generate()
            { return generate::oid(); }

            static gsl::span<const uint8_t> eq_project_type(const Type &value)
            { return value.data(); }

            template <typename T>
            static auto eq_project(const T &instance)
            { return eq_project_type((instance.*member_function)()); }

            static std::string output_project_type(const Type &value)
            {
                using namespace tests::detail;
                std::ostringstream ss;
                ss << value.data();
                return ss.str();
            }

            template <typename T>
            static auto output_project(const T &instance)
            { return output_project_type((instance.*member_function)()); }
        };

        template <auto member_function>
        struct mpi {
            using Type = pgp::multiprecision_integer;

            static Type generate()
            { return generate::mpi(); }

            static gsl::span<const uint8_t> eq_project_type(const Type &value)
            { return value.data(); }

            template <typename T>
            static auto eq_project(const T &instance)
            { return eq_project_type((instance.*member_function)()); }

            static std::string output_project_type(const Type &value)
            {
                using namespace tests::detail;
                std::ostringstream ss;
                ss << value.data();
                return ss.str();
            }

            template <typename T>
            static auto output_project(const T &instance)
            { return output_project_type((instance.*member_function)()); }
        };

        template <auto member_function>
        struct hashalgo {
            using Type = pgp::hash_algorithm;

            static Type generate()
            { return generate::hashalgo(); }

            static pgp::hash_algorithm eq_project_type(const Type &value)
            { return value; }

            template <typename T>
            static auto eq_project(const T &instance)
            { return eq_project_type((instance.*member_function)()); }

            static unsigned output_project_type(const Type &value)
            { return static_cast<unsigned>(value); }

            template <typename T>
            static auto output_project(const T &instance)
            { return output_project_type((instance.*member_function)()); }
        };

        template <auto member_function>
        struct keyalgo {
            using Type = pgp::symmetric_key_algorithm;

            static Type generate()
            { return generate::keyalgo(); }

            static pgp::symmetric_key_algorithm eq_project_type(const Type &value)
            { return value; }

            template <typename T>
            static auto eq_project(const T &instance)
            { return eq_project_type((instance.*member_function)()); }

            static unsigned output_project_type(const Type &value)
            { return static_cast<unsigned>(value); }

            template <typename T>
            static auto output_project(const T &instance)
            { return output_project_type((instance.*member_function)()); }
        };
    }
}


#define DEFINE_MEMBER_CLASS_BY_VALUE(_member_name) \
        struct Member_ ## _member_name { \
            template <typename T> \
            static auto member(const T &instance) { return instance. _member_name(); } \
        }

#define DEFINE_MEMBER_CLASS_BY_REF(_member_name) \
        struct Member_ ## _member_name { \
            template <typename T> \
            static const auto& member(const T &instance) { return instance. _member_name(); } \
        }
