#pragma once

#include "../../Library/memflow/memflow.h"

#include <string>
#include <vector>
#include <optional>
#include <cstring>
#include <iostream>
#include <sstream>
#include <memory>

class Memflow {
public:
    Memflow(const std::string& connector = "kvm", const std::string& os = "win32");

    template <typename T>
    std::optional<T> read(uintptr_t address)
    {
        T value;
        CSliceMut<uint8_t> buf{reinterpret_cast<uint8_t*>(&value), sizeof(T)};
        
        if (this->process.read_raw_into({address}, buf) == 0)
        {
            return value;
        }

        return std::nullopt;
    }
    
    template <typename T>
    bool write(uintptr_t address, const T& value)
    {
        CSliceRef<uint8_t> buf{reinterpret_cast<const uint8_t*>(&value), sizeof(T)};
        return this->process.write_raw({address}, buf) == 0;
    }
    
    std::optional<std::string> readString(uintptr_t address, size_t size = 64);
    std::string addressToString(uintptr_t address);

    std::optional<uintptr_t> scan(const ModuleInfo& module, const std::string& signature);
    std::vector<int> patternToBytes(const std::string& pattern);
    
    std::vector<MemoryRange> listMemoryRanges();

    std::optional<ModuleInfo> findModule(const std::string& name);
    std::optional<ModuleInfo> findModule(const uintptr_t& address);
    std::optional<ModuleInfo> findPrimaryModule();
    std::vector<ModuleInfo> listModules();

    std::optional<ProcessInfo> findProcess(const std::string& name);
    bool openProcess(const ProcessInfo& info);

private:
    Inventory* inventory = nullptr;
    ConnectorInstance<> connector;
    OsInstance<> operating_system;
    ProcessInstance<> process;
};

inline std::unique_ptr<Memflow> memflow = std::make_unique<Memflow>();