#include "obscure/core/FakeCallstackAllocator.h"

#include <cstring>

#include <windows.h> 

using namespace std;

using namespace obscure::core;

FakeCallstackAllocator::FakeCallstackAllocator(size_t maxFrames)
    : _stackSize(maxFrames * sizeof(void*))
{
    void* stack = VirtualAlloc(nullptr, _stackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stack)
        return;

    _fakeStack = shared_ptr<void>(stack, [](void* p) {
        if (p)
            VirtualFree(p, 0, MEM_RELEASE);
    });
}

void FakeCallstackAllocator::BuildFakeCallstack(const vector<void*>& returnAddresses)
{
    if (!_fakeStack)
        return;

    // Ensure the stack is large enough
    uintptr_t* stackPtr = reinterpret_cast<uintptr_t*>(_fakeStack.get());
    size_t count = min(returnAddresses.size(), _stackSize / sizeof(void*));

    for (size_t i = 0; i < count; ++i)
        stackPtr[i] = reinterpret_cast<uintptr_t>(returnAddresses[i]);

    // Fill the rest of the stack with zeros
    for (size_t i = count; i < _stackSize / sizeof(void*); ++i)
        stackPtr[i] = 0;
}
