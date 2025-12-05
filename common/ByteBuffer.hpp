#pragma once

#include <cstdint>
#include <vector>
#include <cstring>
#include "protocol.hpp"

namespace net_ops::common
{

    class ByteBuffer
    {
    private:
        std::vector<uint8_t> m_buffer;

    public:
        ByteBuffer() = default;
        void Append(const uint8_t *data, size_t size);
        bool HasHeader() const;
        net_ops::protocol::Header PeekHeader() const;
        bool HasCompleteMessage(const net_ops::protocol::Header &hdr) const;
        void Consume(size_t bytes);
        std::vector<uint8_t> ExtractPayload(size_t payload_len);
        size_t Size() const { return m_buffer.size(); }
    };

}