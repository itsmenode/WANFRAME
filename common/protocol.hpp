#pragma once

#include <cstdint>
#include <vector>
#include <cstddef>

namespace net_ops::protocol
{

    inline constexpr uint16_t EXPECTED_MAGIC = 0xBBBB;
    inline constexpr uint32_t MAX_PAYLOAD_LENGTH = 10 * 1024 * 1024; // 10MB
    inline constexpr size_t HEADER_SIZE = 8;

    struct Header
    {
        uint16_t magic;
        uint8_t msg_type;
        uint32_t payload_length;
        uint8_t reserved;
    };

    enum class MessageType : std::uint8_t
    {
        Test = 0x00,

        LoginReq = 0x01,
        LoginResp = 0x02,
        LogoutReq = 0x03,
        LogoutResp = 0x04,
        SignupReq = 0x07,
        SignupResp = 0x08,

        HeartbeatReq = 0x05,
        HeartbeatResp = 0x06,

        DeviceReportReq = 0x10,
        DeviceReportResp = 0x11,

        GroupListReq = 0x20,
        GroupListResp = 0x21,
        GroupCreateReq = 0x22,
        GroupCreateResp = 0x23,
        GroupDeleteReq = 0x24,
        GroupDeleteResp = 0x25,
        GroupUpdateReq = 0x26,
        GroupUpdateResp = 0x27,
        GroupMembershipSetReq = 0x28,
        GroupMembershipSetResp = 0x29,

        LogQueryReq = 0x30,
        LogQueryResp = 0x31,
        LiveLogSubscribeReq = 0x32,
        LiveLogSubscribeResp = 0x33,
        LiveLogEvent = 0x34,

        ErrorResp = 0xFF
    };

    inline void SerializeHeader(const Header& hdr, std::uint8_t* buffer) 
    {
        buffer[0] = static_cast<uint8_t>((hdr.magic >> 8) & 0xFF);
        buffer[1] = static_cast<uint8_t>(hdr.magic & 0xFF);

        buffer[2] = hdr.msg_type;

        buffer[3] = static_cast<uint8_t>((hdr.payload_length >> 24) & 0xFF);
        buffer[4] = static_cast<uint8_t>((hdr.payload_length >> 16) & 0xFF);
        buffer[5] = static_cast<uint8_t>((hdr.payload_length >> 8) & 0xFF);
        buffer[6] = static_cast<uint8_t>(hdr.payload_length & 0xFF);

        buffer[7] = hdr.reserved;
    }

    inline Header DeserializeHeader(const std::uint8_t* buffer) 
    {
        Header hdr;
        
        hdr.magic = (static_cast<uint16_t>(buffer[0]) << 8) | 
                     static_cast<uint16_t>(buffer[1]);

        hdr.msg_type = buffer[2];

        hdr.payload_length = (static_cast<uint32_t>(buffer[3]) << 24) |
                             (static_cast<uint32_t>(buffer[4]) << 16) |
                             (static_cast<uint32_t>(buffer[5]) << 8)  |
                             static_cast<uint32_t>(buffer[6]);

        hdr.reserved = buffer[7];

        return hdr;
    }

}