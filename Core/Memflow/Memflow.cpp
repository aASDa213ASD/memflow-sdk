#include "Memflow.h"

/*
Initializez underlying memflow dependencies such as:
- Inventory
- Connector (default: `kvm`)
- Operating System (default: `win32`)

Possible connector values are `qemu` and `kvm`.
Possible os values are `win32`, `native` or `linux`.
*/
Memflow::Memflow(const std::string& connector, const std::string& os)
{
    mf_log_init(LevelFilter::LevelFilter_Off);
    
    this->inventory = mf_inventory_scan();
    if (!this->inventory)
    {
        return;
    }

    if (mf_inventory_create_connector(inventory, connector.c_str(), "", &this->connector) != 0)
    {
        return;
    }
    
    if (mf_inventory_create_os(inventory, os.c_str(), "", &this->connector, &this->operating_system) != 0)
    {
        return;
    }
    
    mf_inventory_free(this->inventory);
}

/*
Reads a string of fixed length from the target process's memory.
This method reads `size` bytes starting from `address` to construct a string.

Usage:
```cpp
auto result = memflow->readString(0x7ffdf00000, 32);
result
    ? std::cout << "String: " << *result << "\n";
    : std::cerr << "Failed to read string." << std::endl;
```
*/
std::optional<std::string> Memflow::readString(uintptr_t address, size_t size)
{
    std::vector<char> buffer(size, 0);
    CSliceMut<uint8_t> buf;
    buf.data = reinterpret_cast<uint8_t*>(buffer.data());
    buf.len = size;

    if (this->process.read_raw_into({address}, buf) != 0)
    {
        std::cerr << "Failed to read string at: " << this->addressToString(address) << "\n";
        return "";
    }

    // This one should be better performance wise because
    // it returns static buffer size (begin to end)
    // which is technically full buffer, while
    // buffer.data() will read until \0 terminator
    //
    // return std::string(buffer.begin(), buffer.end());
    return std::string(buffer.data());
}

/*
A simple wrapper around std::cout << std::hex << address << std::endl;
Keeping this one only for standartized formatting across outputs / logs.

Usage:
```cpp
std::cout << memflow->addressToString(0x57e470) << std::endl;
```
*/
std::string Memflow::addressToString(uintptr_t address)
{
    std::ostringstream oss;
    oss << "0x" << std::hex << address;

    return oss.str();
}

/*
Scans a memory region defined by a module for a given byte signature
pattern by reading the entire memory region of the given ModuleInfo,
converting signature string to a byte pattern, and searching for the
first matching sequence in memory.

Usage:
```cpp
auto module = memflow->findModule("notepad.exe");
if (module)
{
    auto match = memflow->scan(*module, "48 8B ?? ?? 89 ??");
    if (match)
    {
        std::cout 
            << "Found pattern at: 0x" 
            << std::hex << *match 
            << std::endl;
    }
}
```
*/
std::optional<uintptr_t> Memflow::scan(const ModuleInfo& module, const std::string& signature)
{
    auto pattern = this->patternToBytes(signature);
    const size_t pattern_size = pattern.size();
    const int* pattern_data = pattern.data();

    const uintptr_t base = module.base;
    const size_t module_size = module.size;
    const size_t scan_size = module_size - pattern_size;

    std::vector<uint8_t> buffer(module_size);

    CSliceMut<uint8_t> buf;
    buf.data = buffer.data();
    buf.len = buffer.size();

    if (this->process.read_raw_into({base}, buf) != 0)
    {
        std::cerr << "Failed to read module memory at base: 0x" << std::hex << base << std::endl;
        return std::nullopt;
    }

    for (size_t i = 0; i < scan_size; ++i)
    {
        bool found = true;
        for (size_t j = 0; j < pattern_size; ++j)
        {
            if (pattern_data[j] != -1 && buffer[i + j] != pattern_data[j])
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return base + i;
        }
    }

    return std::nullopt;
}

/*
Converts a signature pattern string into a byte vector.
Parses a string like "48 8B ?? ?? 89 ??" into a vector of bytes,
where each byte is either an exact match (e.g. 0x48) or -1 to represent a wildcard.

Usage:
```cpp
// std::vector<int> pattern = {0x48, 0x8B, -1, 0x89}
auto pattern = memflow->patternToBytes("48 8B ?? 89");
```
*/
std::vector<int> Memflow::patternToBytes(const std::string& pattern)
{
    std::vector<int> bytes;
    const char* start = pattern.c_str();
    const char* end = start + pattern.length();

    for (const char* current = start; current < end; ++current)
    {
        if (*current == '?')
        {
            ++current;
            if (*current == '?') ++current;
            bytes.push_back(-1);
        }
        else
        {
            bytes.push_back(strtoul(current, const_cast<char**>(&current), 16));
        }
    }

    return bytes;
}

/*
MemoryRange represents a region of virtual memory inside the target process that is currently:
- Mapped (i.e., has valid memory backing)
- Potentially readable/writable/executable
- Identified via Memflow’s page table walking from the process’s CR3 / DTB

Usage:
```cpp
auto memory_ranges = memflow->listMemoryRanges();
for (size_t i = 0; i < memory_ranges.size(); ++i)
{
    const auto& r = memory_ranges[i];

    std::cout << "Range " << i << ": "
        << memflow->addressToString(r._0) << " - "
        << memflow->addressToString(r._0 + r._1)
        << " (" << std::dec << r._1 << " bytes, protection=" << std::hex << r._2 << ")\n";
}
```
*/
std::vector<MemoryRange> Memflow::listMemoryRanges()
{
    std::vector<MemoryRange> ranges;
    
    this->process.mapped_mem(0x1000, [&](MemoryRange range)
    {
        ranges.push_back(range);
        return true;
    });

    return ranges;
}

/*
Attempts to locate a loaded module in the target process by name.

Usage:
```cpp
auto module = memflow->findModule("KERNEL32.DLL");
if (module)
{
    std::cout << "Module: "
        << module->name << " at "
        << memflow->addressToString(module->address)
        << std::endl;
}
```
*/
std::optional<ModuleInfo> Memflow::findModule(const std::string& name)
{
    std::optional<ModuleInfo> result;

    this->process.module_list_callback(nullptr, [&](ModuleInfo mod)
    {
        if (name == mod.name)
        {
            result = mod;
            return false;
        }

        return true;
    });

    return result;
}

/*
Attempts to locate a loaded module in the target process by address.

Usage:
```cpp
auto module = memflow->findModule(0x5531b0);
if (module)
{
    std::cout << "Module: "
        << module->name << " at "
        << memflow->addressToString(module->address)
        << std::endl;
}
```
*/
std::optional<ModuleInfo> Memflow::findModule(const uintptr_t& address)
{
    std::optional<ModuleInfo> result;

    this->process.module_list_callback(nullptr, [&](ModuleInfo mod)
    {
        if (address == mod.address)
        {
            result = mod;
            return false;
        }

        return true;
    });

    return result;
}

/*
Attempts to find a primary module of the process.
Useful for identifying image base.

Usage:
```cpp
auto module = memflow->findPrimaryModule();
if (module)
{
    std::cout << "Primary Module: "
        << module->name << " at "
        << memflow->addressToString(module->address)
        << std::endl;
}
```
*/
std::optional<ModuleInfo> Memflow::findPrimaryModule()
{
    ModuleInfo module;
    if (this->process.primary_module(&module) == 0)
    {
        return module;
    }
}

/*
Lists all loaded modules in the target process.

Usage:
```cpp
auto modules = memflow->listModules();
for (auto& module : modules)
{
    std::cout << "Module: "
        << module.name << " at "
        << memflow->addressToString(module.address)
        << std::endl;
}
```
*/
std::vector<ModuleInfo> Memflow::listModules()
{
    std::vector<ModuleInfo> modules;

    this->process.module_list_callback(nullptr, [&](ModuleInfo mod)
    {
        modules.push_back(mod);
        return true;
    });

    return modules;
}

/*
Attempts to find a process by name.

Usage:
```cpp
std::string process_name = "notepad.exe";
auto process = memflow->findProcess(process_name);
if (!process)
{
    std::cerr << "Couldn't find process " << process_name << std::endl;
}
```
*/
std::optional<ProcessInfo> Memflow::findProcess(const std::string& name)
{
    ProcessInfo match{};
    bool found = false;

    this->operating_system.process_info_list_callback([&](ProcessInfo info)
    {
        if (name == info.name)
        {
            match = info;
            found = true;
            return false;
        }

        return true;
    });

    return found
        ? std::optional<ProcessInfo>{match}
        : std::nullopt;
}

/*
Opens a handle to a process by ProcessInfo.

Usage:
```cpp
auto process = memflow->findProcess(process_name);
if (process)
{
    memflow->openProcess(*process);
}
```
*/
bool Memflow::openProcess(const ProcessInfo& info)
{
    return this->operating_system.process_by_info(info, &this->process) == 0;
}