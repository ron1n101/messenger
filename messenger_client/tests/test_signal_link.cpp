#include "catch_amalgamated.hpp"
#include "signal_protocol.h"

TEST_CASE("libsignal-protocol-c is linked and creates a context", "[signal]")
{
    signal_context *context = nullptr;
    REQUIRE(signal_context_create(&context, nullptr) == SG_SUCCESS);

    REQUIRE (context != nullptr);
    signal_context_destroy(context);
}