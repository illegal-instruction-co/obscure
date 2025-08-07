#include "obscure/def.h"

#include "obscure/core/ThreadSpoofer.h"
#include "obscure/core/FakeCallstackAllocator.h"
#include "obscure/core/FakeExecutableRegion.h"
#include "obscure/core/FakePeb.h"

#include <minhook/include/MinHook.h>
#include <cstring>
#include <windows.h>

using namespace std;
using namespace obscure::core;

static NtQueryInformationThreadFn _originalNtQueryInformationThread = nullptr;
static GetThreadContextFn _originalGetThreadContext = nullptr;
static ZwQueryVirtualMemoryFn _originalZwQueryVirtualMemory = nullptr;
static NtQueryInformationProcessFn _originalNtQueryInformationProcess = nullptr;

static void* globalFakeTeb = nullptr;
static void* globalFakePeb = nullptr;

static FakeExecutableRegion fakeCodeRegion;
static FakeCallstackAllocator fakeStackAllocator;
static FakePeb fakePeb;

bool ThreadSpoofer::CreateSpoofedTeb()
{
    void* teb = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!teb)
        return false;

    memset(teb, 0xAA, 0x1000);

    _fakeTeb = shared_ptr<void>(teb, [](void* p) {
        if (p)
            VirtualFree(p, 0, MEM_RELEASE);
    });

    globalFakeTeb = teb;

    if (!fakePeb.Initialize())
        return false;

    void* peb = fakePeb.GetPebAddress().get();
    _fakePeb = fakePeb.GetPebAddress();
    globalFakePeb = peb;

    _fakeCodeRegion = fakeCodeRegion.GetBase();

    return true;
}

static NTSTATUS WINAPI NtQueryInformationThread_Hook(
    HANDLE threadHandle,
    THREADINFOCLASS threadInformationClass,
    PVOID threadInformation,
    ULONG threadInformationLength,
    PULONG returnLength
)
{
    if (threadInformationClass == ThreadBasicInformation &&
        threadInformationLength >= sizeof(THREAD_BASIC_INFORMATION)) {

        NTSTATUS status = _originalNtQueryInformationThread(
            threadHandle,
            threadInformationClass,
            threadInformation,
            threadInformationLength,
            returnLength
        );

        if (NT_SUCCESS(status)) {
            auto* info = reinterpret_cast<THREAD_BASIC_INFORMATION*>(threadInformation);
            info->TebBaseAddress = globalFakeTeb;
        }

        return status;
    }

    return _originalNtQueryInformationThread(
        threadHandle,
        threadInformationClass,
        threadInformation,
        threadInformationLength,
        returnLength
    );
}

static BOOL WINAPI GetThreadContext_Hook(HANDLE hThread, LPCONTEXT lpContext)
{
    if (!_originalGetThreadContext(hThread, lpContext))
        return FALSE;

    if ((lpContext->ContextFlags & CONTEXT_FULL) == CONTEXT_FULL) {
#ifdef _M_X64
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32)
            lpContext->Rip = reinterpret_cast<DWORD64>(fakeCodeRegion.GetBase().get());

        fakeStackAllocator.BuildFakeCallstack({
            fakeCodeRegion.GetBase().get(),
            GetProcAddress(kernel32, "Sleep")
        });

        lpContext->Rsp = reinterpret_cast<DWORD64>(fakeStackAllocator.GetFakeStackBase().get()) + 0x800;
        lpContext->Rbp = lpContext->Rsp + 0x20;
        lpContext->Rax = 1;
        lpContext->Rbx = reinterpret_cast<DWORD64>(globalFakeTeb) + 0x100;
        lpContext->Rsi = 0x42424242;
        lpContext->Rdi = 0x43434343;
#else
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32)
            lpContext->Eip = reinterpret_cast<DWORD>(fakeCodeRegion.GetBase().get());

        fakeStackAllocator.BuildFakeCallstack({
            fakeCodeRegion.GetBase().get(),
            GetProcAddress(kernel32, "Sleep")
        });

        lpContext->Esp = reinterpret_cast<DWORD>(fakeStackAllocator.GetFakeStackBase().get()) + 0x800;
        lpContext->Ebp = lpContext->Esp + 0x20;
        lpContext->Eax = 1;
        lpContext->Ebx = reinterpret_cast<DWORD>(globalFakeTeb) + 0x100;
        lpContext->Esi = 0x42424242;
        lpContext->Edi = 0x43434343;
#endif
    }

    return TRUE;
}

static NTSTATUS WINAPI ZwQueryVirtualMemory_Hook(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
)
{
    if (MemoryInformationClass == MemoryBasicInformation &&
        BaseAddress == fakeCodeRegion.GetBase().get()) {

        if (MemoryInformationLength < sizeof(MEMORY_BASIC_INFORMATION))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto mbi = reinterpret_cast<MEMORY_BASIC_INFORMATION*>(MemoryInformation);
        mbi->BaseAddress = fakeCodeRegion.GetBase().get();
        mbi->AllocationBase = fakeCodeRegion.GetBase().get();
        mbi->AllocationProtect = PAGE_EXECUTE_READWRITE;
        mbi->RegionSize = fakeCodeRegion.GetSize();
        mbi->State = MEM_COMMIT;
        mbi->Protect = PAGE_EXECUTE_READWRITE;
        mbi->Type = MEM_IMAGE;

        if (ReturnLength)
            *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);

        return STATUS_SUCCESS;
    }

    return _originalZwQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

static NTSTATUS WINAPI NtQueryInformationProcess_Hook(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
)
{
    if (ProcessInformationClass == ProcessBasicInformation &&
        ProcessInformationLength >= sizeof(PROCESS_BASIC_INFORMATION)) {

        NTSTATUS status = _originalNtQueryInformationProcess(
            ProcessHandle,
            ProcessInformationClass,
            ProcessInformation,
            ProcessInformationLength,
            ReturnLength
        );

        if (NT_SUCCESS(status)) {
            auto* pbi = reinterpret_cast<PROCESS_BASIC_INFORMATION*>(ProcessInformation);
            pbi->PebBaseAddress = globalFakePeb;
        }

        return status;
    }

    return _originalNtQueryInformationProcess(
        ProcessHandle,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationLength,
        ReturnLength
    );
}

bool ThreadSpoofer::InstallHook()
{
    if (!_fakeTeb)
        return false;

    if (MH_Initialize() != MH_OK)
        return false;

    FARPROC target1 = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    if (!target1)
        return false;

    if (MH_CreateHook(target1, &NtQueryInformationThread_Hook, reinterpret_cast<void**>(&_originalNtQueryInformationThread)) != MH_OK)
        return false;

    if (MH_EnableHook(target1) != MH_OK)
        return false;

    FARPROC target2 = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetThreadContext");
    if (!target2)
        return false;

    if (MH_CreateHook(target2, &GetThreadContext_Hook, reinterpret_cast<void**>(&_originalGetThreadContext)) != MH_OK)
        return false;

    if (MH_EnableHook(target2) != MH_OK)
        return false;

    FARPROC target3 = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwQueryVirtualMemory");
    if (!target3)
        return false;

    if (MH_CreateHook(target3, &ZwQueryVirtualMemory_Hook, reinterpret_cast<void**>(&_originalZwQueryVirtualMemory)) != MH_OK)
        return false;

    if (MH_EnableHook(target3) != MH_OK)
        return false;

    FARPROC target4 = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!target4)
        return false;

    if (MH_CreateHook(target4, &NtQueryInformationProcess_Hook, reinterpret_cast<void**>(&_originalNtQueryInformationProcess)) != MH_OK)
        return false;

    if (MH_EnableHook(target4) != MH_OK)
        return false;

    return true;
}
