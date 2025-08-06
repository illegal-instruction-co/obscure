#pragma once

#include <memory>
#include <string>
#include <vector>

namespace obscure::core {

struct FakeModuleInfo final {
    uintptr_t baseAddress;
    size_t size;
    std::wstring fullDllName;
    std::wstring baseDllName;
};

class FakePeb final {
public:
    __forceinline FakePeb() 
        : _fakePeb(nullptr) {}

    __forceinline ~FakePeb() {
        _fakePeb.reset();
    }

    bool Initialize();

    __forceinline [[nodiscard]] std::shared_ptr<void> GetPebAddress() const {
        return _fakePeb;
    }
    __forceinline const [[nodiscard]] std::vector<FakeModuleInfo>& GetModules() const {
        return _modules;
    }

private:
    std::shared_ptr<void> _fakePeb;

    std::vector<FakeModuleInfo> _modules;

    bool AllocateFakePeb();
    bool InitializeModules();
};

}
