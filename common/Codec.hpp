#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace net_ops::common::wire
{
    inline void append_u32_be(std::vector<std::uint8_t>& out, std::uint32_t value)
    {
        std::uint32_t be = htonl(value);
        const auto* p = reinterpret_cast<const std::uint8_t*>(&be);
        out.insert(out.end(), p, p + 4);
    }

    inline bool read_u32_be(const std::vector<std::uint8_t>& in, std::size_t& offset, std::uint32_t& value_out)
    {
        if (offset + 4 > in.size())
            return false;

        std::uint32_t be = 0;
        std::memcpy(&be, in.data() + offset, 4);
        value_out = ntohl(be);
        offset += 4;
        return true;
    }

    inline void append_string(std::vector<std::uint8_t>& out, std::string_view s)
    {
        append_u32_be(out, static_cast<std::uint32_t>(s.size()));
        out.insert(out.end(), s.begin(), s.end());
    }

    inline bool read_string(const std::vector<std::uint8_t>& in, std::size_t& offset, std::string& out)
    {
        std::size_t tmp = offset;

        std::uint32_t len = 0;
        if (!read_u32_be(in, tmp, len))
            return false;

        if (tmp + len > in.size())
            return false;

        out.assign(reinterpret_cast<const char*>(in.data() + tmp), len);
        tmp += len;

        offset = tmp;
        return true;
    }
}
