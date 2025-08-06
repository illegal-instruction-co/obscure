#pragma once

#include <memory>

#include <cstdint>

namespace obscure::core {

class FakeExecutableRegion final {
public:
    FakeExecutableRegion();
    __forceinline ~FakeExecutableRegion() {
         _region.reset();
    }

    __forceinline [[nodiscard]] std::shared_ptr<void> GetBase() const {
        return _region;
    }
    __forceinline [[nodiscard]] size_t GetSize() const {
        return _size;
    }

private:
    std::shared_ptr<void> _region;
    size_t _size;
};

} 
