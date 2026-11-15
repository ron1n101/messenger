#pragma once
#include <string>
#include <utility>
#include "signal_protocol.h"


using AddressKey = std::pair<std::string, int>;

inline AddressKey toAddressKey(const signal_protocol_address *address)
{
    return std::make_pair(std::string(address->name, address->name_len), address->device_id);
}

