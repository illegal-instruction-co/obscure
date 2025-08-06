#include "obscure/def.h"

#include "obscure/core/ExtendedFakeTeb.h"

#include <cstring>

#include <windows.h>

using namespace std;

using namespace obscure::core;

void ExtendedFakeTeb::InitializeFakeTeb()
{
    void* teb = VirtualAlloc(nullptr, sizeof(FAKE_TEB), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!teb)
        return;

    memset(teb, 0, sizeof(FAKE_TEB));

    auto* fakeTeb = reinterpret_cast<FAKE_TEB*>(teb);

    PNT_TIB realTib = reinterpret_cast<PNT_TIB>(NtCurrentTeb());
    if (realTib) {
        fakeTeb->ExceptionList = realTib->ExceptionList;
        fakeTeb->StackBase = reinterpret_cast<ULONG_PTR>(realTib->StackBase);
        fakeTeb->StackLimit = reinterpret_cast<ULONG_PTR>(realTib->StackLimit);
    } else {
        fakeTeb->ExceptionList = reinterpret_cast<PVOID>(0xDEADBEEF);
        fakeTeb->StackBase = 0x10000000;
        fakeTeb->StackLimit = 0x0FFF0000;
    }

    fakeTeb->Self = teb;

    fakeTeb->ClientId.UniqueProcess = GetCurrentProcess();
    fakeTeb->ClientId.UniqueThread = GetCurrentThread();

    fakeTeb->LastErrorValue = GetLastError();

    _fakeTeb = shared_ptr<void>(teb, [](void* p) {
        if (p)
            VirtualFree(p, 0, MEM_RELEASE);
    });
}
