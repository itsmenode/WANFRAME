#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <stdio.h>
#include <string.h>



namespace netops::protocol
{

    inline constexpr std::uint8_t CURRENT_PROTOCOL_VERSION = 1;
    inline constexpr std::uint16_t EXPECTED_MAGIC = 0xABCD;
    inline constexpr std::uint32_t MAX_PAYLOAD_SIZE = 1024 * 1024;

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

    enum class HeaderParseError {
        None,
        InvalidMagic,
        UnsupportedVersion,
        UnknownMessageType,
        InvalidPayloadLength,
        InvalidFlags
    };

    struct Header
    {
        std::uint16_t magic;
        std::uint8_t version;
        MessageType msg_type;
        std::uint16_t flags;
        std::uint32_t payload_length;
        std::uint32_t request_id;
        std::uint16_t reserved;
    };

    bool send_all(int socket_fd, const std::uint8_t* data, std::size_t length);
    bool recv_exact(int socket_fd, std::uint8_t* dest, std::size_t length);






    std::array<std::uint8_t, 16> fill_header(std::array<std::uint8_t, 16> &header,
                    std::uint16_t magic,
                    std::uint8_t version,
                    MessageType msg_type,
                    std::uint16_t flags,
                    std::uint32_t payload_length,
                    std::uint32_t request_id,
                    std::uint16_t reserved);

    void serialize_header(const Header& hdr, std::uint8_t out[16]);

    bool parse_header(std::array<std::uint8_t, 16> &header, HeaderParseError& err);

    void message_type_to_byte(const MessageType &msg_type, std::uint8_t &raw);
    MessageType message_type_from_byte(MessageType &msg_type, const std::uint8_t &raw);






    bool send_message(int socket_fd,
                    MessageType type,
                    std::uint32_t request_id,
                    const std::uint8_t* payload,
                    std::uint32_t payload_len);

    bool recv_message(int socket_fd,
                    Header& out_header,
                    std::vector<std::uint8_t>& out_payload,
                    HeaderParseError& err);


}