#include "obscure/def.h"

#include "obscure/core/FakePeb.h"

#include <cstring>
#include <array>
#include <string_view>

#include <psapi.h>
#include <windows.h>

using namespace std;

using namespace obscure::core;

bool FakePeb::AllocateFakePeb()
{
    void* region = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!region)
        return false;

    memset(region, 0, 0x1000);

    _fakePeb = shared_ptr<void>(region, [](void* p) {
        if (p)
            VirtualFree(p, 0, MEM_RELEASE);
    });

    return true;
}

bool FakePeb::InitializeModules()
{
    HMODULE hMods[1024];
    DWORD cbNeeded;

    HANDLE hProcess = GetCurrentProcess();

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return false;

    size_t modulesCount = cbNeeded / sizeof(HMODULE);

    for (size_t i = 0; i < modulesCount; i++) {
        MODULEINFO modInfo;
        if (!GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
            continue;

        wchar_t modulePath[MAX_PATH];
        if (!GetModuleFileNameExW(hProcess, hMods[i], modulePath, MAX_PATH))
            continue;

        wchar_t* baseName = wcsrchr(modulePath, L'\\');

        FakeModuleInfo mod;
        mod.baseAddress = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
        mod.size = static_cast<size_t>(modInfo.SizeOfImage);
        mod.fullDllName = modulePath;
        mod.baseDllName = baseName ? (baseName + 1) : modulePath;

        _modules.push_back(move(mod));
    }

    return !_modules.empty();
}

bool FakePeb::Initialize()
{
    if (!AllocateFakePeb())
        return false;

    if (!InitializeModules())
        return false;

    auto pebPtr = static_cast<PEB*>(_fakePeb.get());
    memset(pebPtr, 0, sizeof(PEB));

    auto ldrData = static_cast<PEB_LDR_DATA*>(VirtualAlloc(nullptr, sizeof(PEB_LDR_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!ldrData)
        return false;
    memset(ldrData, 0, sizeof(PEB_LDR_DATA));

    pebPtr->Ldr = ldrData;
    ldrData->Length = sizeof(PEB_LDR_DATA);
    ldrData->Initialized = TRUE;

    PLDR_DATA_TABLE_ENTRY firstEntry = nullptr;
    PLDR_DATA_TABLE_ENTRY prevEntry = nullptr;

    for (const auto& mod : _modules) {
        auto entry = static_cast<LDR_DATA_TABLE_ENTRY*>(VirtualAlloc(nullptr, sizeof(LDR_DATA_TABLE_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!entry)
            return false;

        memset(entry, 0, sizeof(LDR_DATA_TABLE_ENTRY));

        entry->DllBase = reinterpret_cast<void*>(mod.baseAddress);
        entry->SizeOfImage = static_cast<ULONG>(mod.size);

        entry->FullDllName.Buffer = const_cast<PWSTR>(mod.fullDllName.c_str());
        entry->FullDllName.Length = static_cast<USHORT>(mod.fullDllName.size() * sizeof(wchar_t));
        entry->FullDllName.MaximumLength = entry->FullDllName.Length + sizeof(wchar_t);

        entry->BaseDllName.Buffer = const_cast<PWSTR>(mod.baseDllName.c_str());
        entry->BaseDllName.Length = static_cast<USHORT>(mod.baseDllName.size() * sizeof(wchar_t));
        entry->BaseDllName.MaximumLength = entry->BaseDllName.Length + sizeof(wchar_t);

        if (!firstEntry) {
            firstEntry = entry;
            ldrData->InLoadOrderModuleList.Flink = &entry->InLoadOrderLinks;
            ldrData->InLoadOrderModuleList.Blink = &entry->InLoadOrderLinks;
        } else {
            prevEntry->InLoadOrderLinks.Flink = &entry->InLoadOrderLinks;
            entry->InLoadOrderLinks.Blink = &prevEntry->InLoadOrderLinks;
        }
        prevEntry = entry;
    }


    return true;
}
