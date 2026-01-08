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

        int priority = -1;
        int facility = -1;
        int severity = -1;
        std::string timestamp;
        std::string hostname;
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
