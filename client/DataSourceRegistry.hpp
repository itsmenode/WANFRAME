#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include "DataSource.hpp"

namespace net_ops::client
{
    class DataSourceRegistry
    {
    public:
        void RegisterSource(const std::string &name, std::shared_ptr<DataSource> source);
        std::shared_ptr<DataSource> GetSource(const std::string &name) const;
        void StartAll(const DataCallback &callback);
        void StopAll();

    private:
        std::unordered_map<std::string, std::shared_ptr<DataSource>> m_sources;
    };
}
