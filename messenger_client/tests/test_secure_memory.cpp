#include "catch_amalgamated.hpp"
#include "crypto/secure_memory.h"
#include <type_traits>
#include <utility>

// T1: secureZero(Bytes&) затирает всё и не меняет размер
TEST_CASE("secureZero wipes the whole vector", "[secure]")
{
    Bytes data(32, 0xAB);
    // TODO: вызвать CryptoUtils::secureZero(data);
    CryptoUtils::secureZero(data);

    // TODO: REQUIRE, что size() всё ещё 32.
    REQUIRE(data.size() == 32);
    // TODO: в цикле REQUIRE, что каждый байт равен 0.
    for (const auto byte : data)
    {
        REQUIRE(byte == 0);
    }
}

// T2: пустые и нулевые входы не должны ронять программу
TEST_CASE("secureZero is safe for empty input", "[secure][edge]")
{
    // TODO: вызвать secureZero(nullptr, 0);
    CryptoUtils::secureZero(nullptr, 0);
    // TODO: создать пустой Bytes и вызвать secureZero(пустой);
    Bytes data;
    CryptoUtils::secureZero(data);

    // TODO: что-нибудь вроде REQUIRE(true) — главное, что вызовы не упали (ASan проверит остальное).
    REQUIRE(true);
}

// T3: новый буфер состоит из нулей
TEST_CASE("SecureBuffer starts zero-initialized", "[secure]")
{
    SecureBuffer buf(32);
    // TODO: REQUIRE, что size() == 32 и empty() == false.
    REQUIRE(buf.size() == 32);
    REQUIRE_FALSE(buf.empty());
    // TODO: в цикле REQUIRE, что buf.data()[i] == 0 для всех i.
    for (size_t index = 0; index < buf.size(); ++index)
    {
        REQUIRE(buf.data()[index] == 0);
    }
}

// T4: запись и чтение через data()
TEST_CASE("SecureBuffer stores and returns bytes", "[secure]")
{
    SecureBuffer buf(4);
    // TODO: записать в buf.data()[0..3] значения 1, 2, 3, 4.
    for (size_t index = 0; index < buf.size(); ++index)
    {
        buf.data()[index] = static_cast<uint8_t>(index + 1);
    }

    // TODO: REQUIRE, что прочитал то же самое.
    for (size_t index = 0; index < buf.size(); ++index)
    {
        REQUIRE(buf.data()[index] == index + 1);
    }
}

// T5: move-конструктор
TEST_CASE("SecureBuffer move constructor transfers ownership", "[secure]")
{
    SecureBuffer a(8);
    a.data()[0] = 0x42;
    // TODO: SecureBuffer b(std::move(a));
    SecureBuffer b(std::move(a));

    // TODO: REQUIRE, что b.size() == 8 и b.data()[0] == 0x42.
    REQUIRE(b.size() == 8);
    REQUIRE(b.data()[0] == 0x42);
    // TODO: REQUIRE, что a.size() == 0, a.empty() и a.data() == nullptr.
    REQUIRE(a.size() == 0);
    REQUIRE(a.empty());
    REQUIRE(a.data() == nullptr);
}

// T6: move-присваивание (и присваивание самому себе)
TEST_CASE("SecureBuffer move assignment transfers ownership", "[secure]")
{
    SecureBuffer a(8);
    SecureBuffer b(16);
    a.data()[0] = 0x11;
    b.data()[0] = 0x22;

    // TODO: b = std::move(a);
    b = std::move(a);

    // TODO: REQUIRE, что b.size() == 8 и b.data()[0] == 0x11.
    REQUIRE(b.size() == 8);
    REQUIRE(b.data()[0] == 0x11);
    // TODO: REQUIRE, что a теперь пустой.
    REQUIRE(a.size() == 0);
    REQUIRE(a.empty());
    REQUIRE(a.data() == nullptr);

    SECTION("self-assignment keeps the data")
    {
        SecureBuffer c(4);
        c.data()[0] = 0x33;
        SecureBuffer &ref = c;   // через ссылку, чтобы компилятор не ругался на self-move
        // TODO: c = std::move(ref);
        c = std::move(ref);

        // TODO: REQUIRE, что c.size() == 4 и c.data()[0] == 0x33.
        REQUIRE(c.size() == 4);
        REQUIRE(c.data()[0] == 0x33);
    }
}

// T7: свойства типа проверяются на этапе компиляции
TEST_CASE("SecureBuffer cannot be copied but can be moved", "[secure]")
{
    // TODO: static_assert(!std::is_copy_constructible_v<SecureBuffer>);
    static_assert(!std::is_copy_constructible_v<SecureBuffer>);
    // TODO: static_assert(!std::is_copy_assignable_v<SecureBuffer>);
    static_assert(!std::is_copy_assignable_v<SecureBuffer>);
    // TODO: static_assert(std::is_nothrow_move_constructible_v<SecureBuffer>);
    static_assert(std::is_nothrow_move_constructible_v<SecureBuffer>);
    // TODO: static_assert(std::is_nothrow_move_assignable_v<SecureBuffer>);
    static_assert(std::is_nothrow_move_assignable_v<SecureBuffer>);
    REQUIRE(true);   // сам тест — это то, что файл скомпилировался
}

// T8: нулевой размер — допустимый случай
TEST_CASE("SecureBuffer of size zero is valid", "[secure][edge]")
{
    SecureBuffer buf(0);
    // TODO: REQUIRE, что size() == 0 и empty() == true.
    REQUIRE(buf.size() == 0);
    REQUIRE(buf.empty());
}