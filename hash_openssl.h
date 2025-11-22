#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

// double SHA256 using OpenSSL (implemented in hash_openssl.cpp)
void open_double_sha256(const uint8_t* data, size_t len, uint8_t out[32]);

// convenience overload for vector
inline void open_double_sha256(const std::vector<uint8_t>& v, uint8_t out[32]) {
    open_double_sha256(v.data(), v.size(), out);
}
