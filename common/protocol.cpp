#include "./protocol.hpp"

namespace netops::protocol
{

    bool send_all(int socket_fd, const std::uint8_t *data, std::size_t length);
    bool recv_exact(int socket_fd, std::uint8_t *dest, std::size_t length);

    std::array<std::uint8_t, 16> fill_header(std::uint8_t header[16],
                                             std::uint16_t magic,
                                             std::uint8_t version,
                                             MessageType msg_type,
                                             std::uint16_t flags,
                                             std::uint32_t payload_length,
                                             std::uint32_t request_id,
                                             std::uint16_t reserved)
    {
        memcpy(&header[0], &magic, sizeof(magic));
        memcpy(&header[2], &version, sizeof(version));
        memcpy(&header[3], &msg_type, sizeof(msg_type));
        memcpy(&header[4], &flags, sizeof(flags));
        memcpy(&header[6], &payload_length, sizeof(payload_length));
        memcpy(&header[10], &request_id, sizeof(request_id));
        memcpy(&header[14], &reserved, sizeof(reserved));
    }

    void serialize_header(const Header &header, std::uint8_t buffer[16]){
        std::uint16_t magic_be = htons(header.magic);
        buffer[0] = static_cast<std::uint8_t> ((magic_be >> 8) & 0xFF);
        buffer[1] = static_cast<std::uint8_t> (magic_be & 0xFF);

        buffer[2] = header.version;

        buffer[3] = message_type_to_byte(header.msg_type);

        std::uint16_t flags_be = htons(header.flags);
        buffer[4] = static_cast<std::uint8_t> ((flags_be >> 8) & 0xFF);
        buffer[5] = static_cast<std::uint8_t> (flags_be & 0xFF);

        std::uint32_t payload_length_be = htons(header.payload_length);
        buffer[6] = static_cast<std::uint8_t> ((payload_length_be >> 24) & 0xFF);
        buffer[7] = static_cast<std::uint8_t> ((payload_length_be >> 16) & 0xFF);
        buffer[8] = static_cast<std::uint8_t> ((payload_length_be >> 8) & 0xFF);
        buffer[9] = static_cast<std::uint8_t> (payload_length_be & 0xFF);

        std::uint32_t request_id_be = htons(header.request_id);
        buffer[10] = static_cast<std::uint8_t> ((request_id_be >> 24) & 0xFF);
        buffer[11] = static_cast<std::uint8_t> ((request_id_be >> 16) & 0xFF);
        buffer[12] = static_cast<std::uint8_t> ((request_id_be >> 8) & 0xFF);
        buffer[13] = static_cast<std::uint8_t> (request_id_be & 0xFF);
    }

    bool parse_header(std::uint8_t header[16], Header &buffer, HeaderParseError &err)
    {
        memcpy(&buffer.magic, &header[0], 2);
        memcpy(&buffer.version, &header[2], 1);
        memcpy(&buffer.msg_type, &header[3], 1);
        memcpy(&buffer.flags, &header[4], 2);
        memcpy(&buffer.payload_length, &header[6], 4);
        memcpy(&buffer.request_id, &header[10], 4);
        memcpy(&buffer.reserved, &header[14], 2);
    }

    std::uint8_t message_type_to_byte(MessageType msg_type)
    {
        return static_cast<std::uint8_t>(msg_type);
    }

}