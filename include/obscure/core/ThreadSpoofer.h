#pragma once

#include <memory>

#include <cstdint>

#include <windows.h>

namespace obscure::core {

class ThreadSpoofer final {
public:
    __forceinline ThreadSpoofer() : _fakeTeb(nullptr) {}
    
    __forceinline ~ThreadSpoofer() {
         _fakeTeb.reset();
    }

    bool CreateSpoofedTeb();
    __forceinline [[nodiscard]] std::shared_ptr<void> GetFakeTeb() const {
        return _fakeTeb;
    }
    __forceinline [[nodiscard]] std::shared_ptr<void> GetFakePeb() const {
        return _fakePeb;
    }
    __forceinline [[nodiscard]] std::shared_ptr<void> GetFakeCodeRegion() const {
        return _fakeCodeRegion;
    }

    bool InstallHook();

    __forceinline static void SetFiberEntryFunction(void(*entryFunction)()) {
        _entryFunction = entryFunction;
    }

    static void RunAsFiber(std::shared_ptr<void>, size_t);

private:

    inline static thread_local void(*_entryFunction)() = nullptr;

    static __forceinline void __stdcall FiberEntry(void* /*param*/) {
        if (_entryFunction)
            _entryFunction(); 
    }

    std::shared_ptr<void> _fakePeb;
    std::shared_ptr<void> _fakeCodeRegion;
    std::shared_ptr<void> _fakeTeb;
};

}
