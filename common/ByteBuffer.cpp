#include "ByteBuffer.hpp"
#include <stdexcept>
#include <cstdlib>
#include <iterator>

namespace net_ops::common
{
    void ByteBuffer::Append(const uint8_t *data, size_t size)
    {
        m_buffer.insert(m_buffer.end(), data, data + size);
    }

    bool ByteBuffer::HasHeader() const
    {
        return (m_buffer.size() - m_readPos) >= net_ops::protocol::HEADER_SIZE;
    }

    net_ops::protocol::Header ByteBuffer::PeekHeader() const
    {
        if (!HasHeader())
            throw std::runtime_error("ByteBuffer::PeekHeader - Not enough bytes");
        return net_ops::protocol::DeserializeHeader(m_buffer.data() + m_readPos);
    }

    bool ByteBuffer::HasCompleteMessage(const net_ops::protocol::Header &hdr) const
    {
        if (hdr.payload_length > net_ops::protocol::MAX_PAYLOAD_LENGTH)
            return false;
        return (m_buffer.size() - m_readPos) >= (net_ops::protocol::HEADER_SIZE + hdr.payload_length);
    }

    void ByteBuffer::Consume(size_t bytes)
    {
        m_readPos += bytes;
        if (m_readPos >= m_buffer.size())
        {
            m_buffer.clear();
            m_readPos = 0;
        }
    }

    std::vector<uint8_t> ByteBuffer::ExtractPayload(size_t payload_len)
    {
        auto start_it = m_buffer.begin() + m_readPos + net_ops::protocol::HEADER_SIZE;
        auto end_it = start_it + payload_len;

        if (end_it > m_buffer.end())
            throw std::runtime_error("ByteBuffer::ExtractPayload - Buffer underflow");

        return std::vector<uint8_t>(start_it, end_it);
    }
}