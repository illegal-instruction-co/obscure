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

    bool InstallHook();

private:
    std::shared_ptr<void> _fakeTeb;
};

}
