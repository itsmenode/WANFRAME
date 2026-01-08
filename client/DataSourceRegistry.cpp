#include "DataSourceRegistry.hpp"

namespace net_ops::client
{
    void DataSourceRegistry::RegisterSource(const std::string &name, std::shared_ptr<DataSource> source)
    {
        if (!source)
            return;
        m_sources[name] = std::move(source);
    }

    std::shared_ptr<DataSource> DataSourceRegistry::GetSource(const std::string &name) const
    {
        auto it = m_sources.find(name);
        if (it == m_sources.end())
            return nullptr;
        return it->second;
    }

    void DataSourceRegistry::StartAll(const DataCallback &callback)
    {
        for (const auto &pair : m_sources)
        {
            if (pair.second)
            {
                pair.second->Start(callback);
            }
        }
    }

    void DataSourceRegistry::StopAll()
    {
        for (const auto &pair : m_sources)
        {
            if (pair.second)
            {
                pair.second->Stop();
            }
        }
    }
}
