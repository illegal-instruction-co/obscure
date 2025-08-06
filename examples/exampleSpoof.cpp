#include "obscure/def.h"

#include "obscure/core/ThreadSpoofer.h"

#include <iostream>
#include <thread>
#include <vector>

#include <windows.h>

using namespace std;
using namespace obscure::core;

extern "C" __declspec(dllimport) NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE,
    THREADINFOCLASS,
    PVOID,
    ULONG,
    PULONG
);

extern "C" __declspec(dllimport) BOOL WINAPI GetThreadContext(
    HANDLE hThread,
    LPCONTEXT lpContext
);

extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

// Helper to print CONTEXT registers (x64 or x86)
void PrintContext(const CONTEXT& ctx)
{
#ifdef _M_X64
    cout << "[+] Context RIP: 0x" << hex << ctx.Rip << endl;
    cout << "[+] Context RSP: 0x" << hex << ctx.Rsp << endl;
    cout << "[+] Context RBP: 0x" << hex << ctx.Rbp << endl;
    cout << "[+] Context RAX: 0x" << hex << ctx.Rax << endl;
    cout << "[+] Context RBX: 0x" << hex << ctx.Rbx << endl;
#else
    cout << "[+] Context EIP: 0x" << hex << ctx.Eip << endl;
    cout << "[+] Context ESP: 0x" << hex << ctx.Esp << endl;
    cout << "[+] Context EBP: 0x" << hex << ctx.Ebp << endl;
    cout << "[+] Context EAX: 0x" << hex << ctx.Eax << endl;
    cout << "[+] Context EBX: 0x" << hex << ctx.Ebx << endl;
#endif
}

// Test 1: NtQueryInformationThread Hook Test
bool TestNtQueryInformationThread(const ThreadSpoofer& spoofer)
{
    cout << "[*] Querying NtQueryInformationThread..." << endl;

    THREAD_BASIC_INFORMATION info{};
    NTSTATUS status = NtQueryInformationThread(
        GetCurrentThread(),
        ThreadBasicInformation,
        &info,
        sizeof(info),
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        cerr << "[!] NtQueryInformationThread failed with code: 0x" << hex << status << endl;
        return false;
    }

    cout << "[+] Reported TEB Address: " << info.TebBaseAddress << endl;
    cout << "[*] Actual Fake TEB pointer: " << spoofer.GetFakeTeb().get() << endl;

    return true;
}

// Test 2: GetThreadContext Hook Test
bool TestGetThreadContext()
{
    cout << "[*] Querying GetThreadContext..." << endl;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        cerr << "[!] GetThreadContext failed. Error: " << GetLastError() << endl;
        return false;
    }

    PrintContext(ctx);
    return true;
}

// Test 3: ZwQueryVirtualMemory Hook Test
bool TestZwQueryVirtualMemory(const ThreadSpoofer& spoofer)
{
    cout << "[*] Querying ZwQueryVirtualMemory..." << endl;

    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T retLen = 0;

    NTSTATUS status = ZwQueryVirtualMemory(
        GetCurrentProcess(),
        spoofer.GetFakeTeb().get(),
        MemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        &retLen
    );

    if (status == 0 /* STATUS_SUCCESS */) {
        cout << "[+] ZwQueryVirtualMemory succeeded." << endl;
        cout << "    BaseAddress: " << mbi.BaseAddress << endl;
        cout << "    AllocationBase: " << mbi.AllocationBase << endl;
        cout << "    RegionSize: " << mbi.RegionSize << endl;
        cout << "    State: " << mbi.State << endl;
        cout << "    Protect: " << mbi.Protect << endl;
        cout << "    Type: " << mbi.Type << endl;
        return true;
    }
    else {
        cerr << "[-] ZwQueryVirtualMemory failed: 0x" << hex << status << endl;
        return false;
    }
}

// Test 4: Multi-thread Hook Consistency Test
void ThreadRoutine()
{
    THREAD_BASIC_INFORMATION info{};
    if (NT_SUCCESS(NtQueryInformationThread(GetCurrentThread(), ThreadBasicInformation, &info, sizeof(info), nullptr))) {
        cout << "[Thread] Reported TEB Address: " << info.TebBaseAddress << endl;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
#ifdef _M_X64
        cout << "[Thread] Context RIP: 0x" << hex << ctx.Rip << endl;
#else
        cout << "[Thread] Context EIP: 0x" << hex << ctx.Eip << endl;
#endif
    }
}

bool TestMultiThread()
{
    cout << "[*] Starting multi-thread test..." << endl;
    thread t(ThreadRoutine);
    t.join();
    cout << "[*] Multi-thread test done." << endl;
    return true;
}

// Main function running all tests sequentially
int main()
{
    cout << "[*] Creating spoofed TEB..." << endl;
    ThreadSpoofer spoofer;

    if (!spoofer.CreateSpoofedTeb()) {
        cerr << "[!] Failed to create spoofed TEB." << endl;
        return 1;
    }

    cout << "[*] Installing thread hooks..." << endl;
    if (!spoofer.InstallHook()) {
        cerr << "[!] Failed to install hooks." << endl;
        return 1;
    }

    bool ok = true;

    ok &= TestNtQueryInformationThread(spoofer);
    ok &= TestGetThreadContext();
    ok &= TestZwQueryVirtualMemory(spoofer);
    ok &= TestMultiThread();

    cout << (ok ? "[*] All tests passed." : "[!] Some tests failed.") << endl;

    this_thread::sleep_for(chrono::seconds(3));

    return ok ? 0 : 1;
}
