#include "utils.h"
#include <random>
#include <fstream>
#include <iostream>
#include <cstring>

bool Utils::generateRandom(BYTE* buffer, size_t size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < size; ++i) {
        buffer[i] = static_cast<BYTE>(dis(gen));
    }
    return true;
}

ByteSmartPtr Utils::readBufferFromFile(const char* filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return nullptr;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    ByteSmartPtr buffer(new BYTE[size]);
    if (file.read(reinterpret_cast<char*>(buffer.get()), size)) {
        return buffer;
    } else {
        return nullptr;
    }
}

void Utils::secureCleanMemory(void* buffer, size_t size) {
    std::memset(buffer, 0, size);
}
