#pragma once
#include "DataSource.hpp"

namespace net_ops::client
{
    class LogFilter
    {
    public:
        virtual ~LogFilter() = default;
        virtual bool IsMatch(const DataRecord &record) = 0;
    };

    class SeverityFilter : public LogFilter
    {
    public:
        explicit SeverityFilter(int maxSeverity) : m_maxSeverity(maxSeverity) {}
        bool IsMatch(const DataRecord &record) override
        {
            return record.severity <= m_maxSeverity;
        }

    private:
        int m_maxSeverity;
    };
}