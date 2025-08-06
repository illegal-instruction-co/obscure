#pragma once

#include <memory>

namespace obscure::core {

class ExtendedFakeTeb {
public:
    __forceinline ExtendedFakeTeb() 
        : _fakeTeb(nullptr) {}

    __forceinline ~ExtendedFakeTeb() {
        _fakeTeb.reset();
    }

    __forceinline [[nodiscard]] std::shared_ptr<void> GetBase() const {
        return _fakeTeb;
    }

    void InitializeFakeTeb();

private:
    std::shared_ptr<void> _fakeTeb;
};

}
