#pragma once

#include <cstdint>
#include <vector>
#include <cstddef>
#include <arpa/inet.h>
#include <string>
#include <optional>
#include <cstring>

namespace net_ops::protocol
{
    inline constexpr uint16_t EXPECTED_MAGIC = 0xBBBB;
    inline constexpr uint8_t PROTOCOL_VERSION = 0x01;
    inline constexpr uint32_t MAX_PAYLOAD_LENGTH = 10 * 1024 * 1024; // 10MB
    inline constexpr size_t HEADER_SIZE = 12;                        // 2(magic) + 1(ver) + 1(type) + 4(len) + 4(res)

    struct Header
    {
        uint16_t magic;
        uint8_t version;
        uint8_t msg_type;
        uint32_t payload_length;
        uint32_t reserved;
    };

    enum class MessageType : uint8_t
    {
        LoginReq = 0x01,
        LoginResp = 0x02,
        SignupReq = 0x03,
        SignupResp = 0x04,

        DeviceAddReq = 0x0B,
        DeviceAddResp = 0x0C,
        DeviceListReq = 0x0D,
        DeviceListResp = 0x0E,

        LogUploadReq = 0x0F,
        LogUploadResp = 0x10,
        DeviceStatusReq = 0x11,
        DeviceStatusResp = 0x12,

        LogQueryReq = 0x15,
        LogQueryResp = 0x16,

        LogoutReq = 0x17,
        LogoutResp = 0x18,

        MetricsReq = 0x19,
        MetricsResp = 0x20,

        DashboardConfigReq = 0x21,
        DashboardConfigResp = 0x22,

        ErrorResp = 0xFF
    };

    inline void SerializeHeader(const Header &hdr, std::uint8_t *buffer)
    {
        buffer[0] = static_cast<uint8_t>((hdr.magic >> 8) & 0xFF);
        buffer[1] = static_cast<uint8_t>(hdr.magic & 0xFF);
        buffer[2] = hdr.version;
        buffer[3] = hdr.msg_type;

        uint32_t netLen = htonl(hdr.payload_length);
        std::memcpy(buffer + 4, &netLen, 4);

        uint32_t netRes = htonl(hdr.reserved);
        std::memcpy(buffer + 8, &netRes, 4);
    }

    inline Header DeserializeHeader(const std::uint8_t *buffer)
    {
        Header hdr;
        hdr.magic = (static_cast<uint16_t>(buffer[0]) << 8) | static_cast<uint16_t>(buffer[1]);
        hdr.version = buffer[2];
        hdr.msg_type = buffer[3];

        uint32_t netLen;
        std::memcpy(&netLen, buffer + 4, 4);
        hdr.payload_length = ntohl(netLen);

        uint32_t netRes;
        std::memcpy(&netRes, buffer + 8, 4);
        hdr.reserved = ntohl(netRes);

        return hdr;
    }

    inline void PackUint32(std::vector<uint8_t> &buf, uint32_t val)
    {
        uint32_t netVal = htonl(val);
        const uint8_t *p = reinterpret_cast<const uint8_t *>(&netVal);
        buf.insert(buf.end(), p, p + 4);
    }

    inline void PackString(std::vector<uint8_t> &buf, const std::string &s)
    {
        PackUint32(buf, static_cast<uint32_t>(s.length()));
        buf.insert(buf.end(), s.begin(), s.end());
    }

    inline std::optional<uint32_t> UnpackUint32(const std::vector<uint8_t> &buf, size_t &offset)
    {
        if (offset + 4 > buf.size())
            return std::nullopt;
        uint32_t netVal;
        std::memcpy(&netVal, buf.data() + offset, 4);
        offset += 4;
        return ntohl(netVal);
    }

    inline std::optional<std::string> UnpackString(const std::vector<uint8_t> &buf, size_t &offset)
    {
        auto len = UnpackUint32(buf, offset);
        if (!len || offset + *len > buf.size())
            return std::nullopt;

        std::string s(reinterpret_cast<const char *>(buf.data() + offset), *len);
        offset += *len;
        return s;
    }
}
