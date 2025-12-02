#include "./protocol.hpp"

inline std::array<std::uint8_t, 16> fill_header(std::array<std::uint8_t, 16>& header, std::uint16_t magic, std::uint8_t version, std::uint8_t msg_type, std::uint16_t flags, std::uint32_t payload_length, std::uint32_t request_id, std::uint16_t reserved){
    memcpy(&header[0], &magic, sizeof(magic));
    memcpy(&header[2], &version, sizeof(version));
    memcpy(&header[3], &msg_type, sizeof(msg_type));
    memcpy(&header[4], &flags, sizeof(flags));
    memcpy(&header[6], &payload_length, sizeof(payload_length));
    memcpy(&header[10], &request_id, sizeof(request_id));
    memcpy(&header[14], &version, sizeof(version));
}

inline bool parse_header(std::array<std::uint8_t, 16>& header, Header& buffer) {
    memcpy(&buffer.magic, &header[0], 2);
}