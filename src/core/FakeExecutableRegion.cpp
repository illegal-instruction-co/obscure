#include "obscure/core/FakeExecutableRegion.h"

#include <cstring>

#include <windows.h>

using namespace obscure::core;

FakeExecutableRegion::FakeExecutableRegion()
    : _size(0x1000)
{
    void* region = VirtualAlloc(nullptr, _size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!region)
        return;

    // Fill with NOPs and RETs (e.g., for plausible return addresses)
    unsigned char* p = reinterpret_cast<unsigned char*>(region);
    for (size_t i = 0; i < _size - 1; ++i)
        p[i] = 0x90; // NOP

    p[_size - 1] = 0xC3; // RET at the end

    _region = std::shared_ptr<void>(region, [](void* p) {
        if (p)
            VirtualFree(p, 0, MEM_RELEASE);
    });
}
