add_library(obscure STATIC
    ThreadSpoofer.cpp
    FakeExecutableRegion.cpp
    FakeCallstackAllocator.cpp
    FakePeb.cpp
    ExtendedFakeTeb.cpp
)

target_include_directories(obscure PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_features(obscure PUBLIC cxx_std_20)

target_link_libraries(obscure PUBLIC psapi ntdll minhook)
