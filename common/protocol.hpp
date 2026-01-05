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

    enum class MessageType : uint8_t {
        LoginReq = 0x01,
        LoginResp = 0x02,
        SignupReq = 0x03,
        SignupResp = 0x04,
        
        GroupCreateReq = 0x05, 
        GroupCreateResp = 0x06,
        GroupListReq = 0x07,
        GroupListResp = 0x08,

        GroupAddMemberReq = 0x09,
        GroupAddMemberResp = 0x0A,

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