#include <iostream>
#include <chrono>
#include <thread>

#include "Core/Memflow/Memflow.h"

// Original memflow.hpp:
// https://github.com/memflow/memflow/blob/main/memflow-ffi/memflow.hpp
//
// Their example file for reference:
// https://github.com/memflow/memflow/blob/main/memflow-ffi/examples/cpp/plist.cpp

int main(int argc, char *argv[])
{
    const std::string process_name = "notepad.exe";
    auto process = memflow->findProcess(process_name);
    if (!process)
    {
        std::cerr << "Couldn't find process " << process_name << std::endl;
        return 1;
    }

    std::cout << "Found target " << process_name << " (" << process->pid << ") at " << memflow->addressToString(process->address) << std::endl;
    memflow->openProcess(*process);

    /*
    auto module = memflow->findPrimaryModule();
    if (module)
    {
        std::cout << "Primary Module: " << module->name << " at " << memflow->addressToString(module->address) << std::endl;
    }
    */

    /*
    auto modules = memflow->listModules();
    for (auto& module : modules)
    {
        std::cout << "Module: " << module.name << " at " << memflow->addressToString(module.address) << std::endl;
    }
    */

    
    // Module: KERNELBASE.dll at 0x5531b0
    /*
    auto module = memflow->findModule(0x57e470);
    if (module)
    {
        std::cout << "Module: " << module->name << " at " << memflow->addressToString(module->address) << std::endl;
    }
    */
    
    /*
    auto memory_ranges = memflow->listMemoryRanges();
    for (size_t i = 0; i < memory_ranges.size(); ++i)
    {
        const auto& r = memory_ranges[i];
    
        std::cout << "Range " << i << ": "
                  << memflow->addressToString(r._0) << " - "
                  << memflow->addressToString(r._0 + r._1)
                  << " (" << std::dec << r._1 << " bytes, protection=" << std::hex << r._2 << ")\n";
    }
    */

    return 0;
}