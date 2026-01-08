#pragma once

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include "DataSource.hpp"
#include "LogFilter.hpp"

namespace net_ops::client
{
    class DataSourceRegistry
    {
    public:
        void RegisterSource(const std::string &name, std::shared_ptr<DataSource> source);
        std::shared_ptr<DataSource> GetSource(const std::string &name) const;

        void AddFilter(std::shared_ptr<LogFilter> filter);

        void StartAll(const DataCallback &callback);
        void StopAll();

    private:
        std::unordered_map<std::string, std::shared_ptr<DataSource>> m_sources;
        std::vector<std::shared_ptr<LogFilter>> m_filters;
    };
}