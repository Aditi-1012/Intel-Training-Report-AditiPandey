#ifndef UTILS_H
#define UTILS_H

#include <cstddef>
#include <memory>

using BYTE = unsigned char;
using ByteSmartPtr = std::unique_ptr<BYTE[]>;

namespace Utils {
    bool generateRandom(BYTE* buffer, size_t size);
    ByteSmartPtr readBufferFromFile(const char* filename);
    void secureCleanMemory(void* buffer, size_t size);
}

#endif 
