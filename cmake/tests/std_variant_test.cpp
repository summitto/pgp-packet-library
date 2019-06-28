#include <iostream>
#include <variant>
#include <cstdlib>

void okassert(bool ok, const char *description) {
    if (!ok) {
        std::cerr << "FAIL: " << description << std::endl;
        exit(1);
    }
}

int main() {
    std::variant<int, char> v{std::in_place_type_t<char>(), 'a'};

    okassert(std::get<char>(v) == 'a', "std::get not working");

    bool error_thrown = false;
    try { std::get<int>(v); }
    catch (std::bad_variant_access &) { error_thrown = true; }
    okassert(error_thrown, "std::get should throw error");

    std::visit([](auto &&value) {
        okassert(value == 'a', "std::visit not working");
    }, v);
}
