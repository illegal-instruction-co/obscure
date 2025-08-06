#pragma once

#include <memory>
#include <vector>

#include <cstdint>

namespace obscure::core {

class FakeCallstackAllocator final {
public:
    FakeCallstackAllocator(size_t maxFrames = 16);
    __forceinline ~FakeCallstackAllocator() {
         _fakeStack.reset();
    }

    __forceinline std::shared_ptr<void> GetFakeStackBase() const {
        return _fakeStack;
    }

    void BuildFakeCallstack(const std::vector<void*>&);

private:
    std::shared_ptr<void> _fakeStack;
    size_t _stackSize;
};

} // namespace obscure::core
