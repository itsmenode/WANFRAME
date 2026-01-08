#pragma once

#include <functional>
#include <string>

namespace net_ops::client
{
    enum class DataRecordType
    {
        Syslog,
        DeviceStatus,
        SnmpStatus
    };

    struct DataRecord
    {
        DataRecordType type;
        std::string ip;
        std::string message;
        std::string status;
        std::string info;
    };

    using DataCallback = std::function<void(const DataRecord &record)>;

    class DataSource
    {
    public:
        virtual ~DataSource() = default;
        virtual void Start(DataCallback callback) = 0;
        virtual void Stop() = 0;
    };
}
