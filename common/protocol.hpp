#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <stdio.h>
#include <string.h>

enum class MessageType : std::uint8_t
{
    // Phase 1 / testing
    Test                 = 0x00,

    // Authentication
    LoginReq             = 0x01,
    LoginResp            = 0x02,
    LogoutReq            = 0x03,
    LogoutResp           = 0x04,
    SignupReq            = 0x07,
    SignupResp           = 0x08,

    // Heartbeat / health
    HeartbeatReq         = 0x05,
    HeartbeatResp        = 0x06,

    // Device discovery / inventory
    DeviceReportReq      = 0x10,
    DeviceReportResp     = 0x11,

    // Groups / logical networks
    GroupListReq         = 0x20,
    GroupListResp        = 0x21,
    GroupCreateReq       = 0x22,
    GroupCreateResp      = 0x23,
    GroupDeleteReq       = 0x24,
    GroupDeleteResp      = 0x25,
    GroupUpdateReq       = 0x26,
    GroupUpdateResp      = 0x27,
    GroupMembershipSetReq  = 0x28,
    GroupMembershipSetResp = 0x29,

    // Logs
    LogQueryReq          = 0x30,
    LogQueryResp         = 0x31,
    LiveLogSubscribeReq  = 0x32,
    LiveLogSubscribeResp = 0x33,
    LiveLogEvent         = 0x34,

    // Errors
    ErrorResp            = 0xFF
};

inline std::array<std::uint8_t, 16> fill_header(std::array<std::uint8_t, 16>& header, std::uint16_t magic, std::uint8_t version, std::uint8_t msg_type, std::uint16_t flags, std::uint32_t payload_length, std::uint32_t request_id, std::uint16_t reserved);

