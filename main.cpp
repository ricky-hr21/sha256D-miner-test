// main.cpp — uses libbtc for header/serialize/hex utils, uses open_double_sha256 from hash_openssl
#include <btc/utils.h>
#include <btc/block.h>
#include <btc/serialize.h>
#include <btc/buffer.h> // for cstring
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <inttypes.h>
#include <chrono>
#include <thread>
#include <atomic>

#include "hash_openssl.h" // wrapper that DOES NOT include OpenSSL headers

std::atomic<bool> hash_found(false);
std::atomic<bool> run_miner(false);
std::atomic<uint32_t> found_nonce(0);

// ---------- Endian helpers ----------
static inline void write_le32(uint8_t *buf, uint32_t v) {
    buf[0] = (uint8_t)(v & 0xFF);
    buf[1] = (uint8_t)((v >> 8) & 0xFF);
    buf[2] = (uint8_t)((v >> 16) & 0xFF);
    buf[3] = (uint8_t)((v >> 24) & 0xFF);
}

// hash <= target compare: both arrays are big-endian (MSB first) as bytes
static inline bool hash_leq_target_be(const uint8_t hash_be[32], const uint8_t target_be[32]) {
    return memcmp(hash_be, target_be, 32) <= 0;
}

// double SHA256 helper that uses OpenSSL backend
void double_sha256_constbuf(const uint8_t* data, size_t len, uint8_t out[32]) {
    open_double_sha256(data, len, out);
}

void double_sha256(const std::vector<uint8_t>& data, uint8_t out[32]) {
    open_double_sha256(data.data(), data.size(), out);
}

// Build target (nBits compact -> 32-byte big-endian target)
void target_build(uint32_t nBits, uint8_t target[32]) {
    memset(target, 0, 32);
    uint32_t exponent = (nBits >> 24) & 0xff;
    uint32_t mantissa = nBits & 0x007fffff;

    // mantissa occupies 3 bytes
    int shift = (int)exponent - 3;
    if (shift < 0) {
        // rare, right shift mantissa if exponent < 3
        int right = -shift;
        int start = 32 - 3 - right;
        if (start < 0) start = 0;
        target[start + 0] = (mantissa >> 16) & 0xff;
        target[start + 1] = (mantissa >> 8) & 0xff;
        target[start + 2] = (mantissa) & 0xff;
    } else {
        int start = 32 - 3 - shift;
        if (start < 0) start = 0;
        if (start > 29) start = 29;
        target[start + 0] = (mantissa >> 16) & 0xff;
        target[start + 1] = (mantissa >> 8) & 0xff;
        target[start + 2] = (mantissa) & 0xff;
    }
}

// Merkle combine using OpenSSL double sha256
void merkle_combine(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
    uint8_t buf[64];
    memcpy(buf, left, 32);
    memcpy(buf + 32, right, 32);
    double_sha256_constbuf(buf, 64, out);
}

void build_merkle_root(const uint8_t coinbase_hash[32],
                       const std::vector<std::string>& branches,
                       uint8_t merkle_root[32])
{
    memcpy(merkle_root, coinbase_hash, 32);
    for (const auto& branch_hex : branches) {
        uint8_t branch[32];
        int outlen = 0;
        utils_hex_to_bin(branch_hex.c_str(), branch, branch_hex.size(), &outlen);
        uint8_t new_hash[32];
        merkle_combine(merkle_root, branch, new_hash);
        memcpy(merkle_root, new_hash, 32);
    }
}

void miner_worker(const uint8_t base_header[80], const uint8_t target[32], int thread_id, int total_threads)
{
    uint8_t local_header[80];
    uint8_t out_hash[32];

    memcpy(local_header, base_header, 80);

    uint32_t counter = (uint32_t)thread_id;

    while (run_miner && counter != 0xffffffff) {
        // write nonce as little-endian into header[76..79]
        write_le32(local_header + 76, counter);

        // compute double-sha256 (OpenSSL backend)
        double_sha256_constbuf(local_header, 80, out_hash);

        // note: OpenSSL returns big-endian bytes (MSB first). Our target built as big-endian
        if (hash_leq_target_be(out_hash, target)) {
            hash_found = true;
            found_nonce = counter;
            printf("Thread %d menemukan hash! nonce = %u\n", thread_id, counter);

            printf("✅ Hash memenuhi target nonce = %" PRIu32 "\n", counter);
            std::cout << "Raw 80-byte header:\n";
            for (size_t i = 0; i < 80; ++i) printf("%02x", local_header[i]);
            printf("\n");

            printf("Hash (hex MSB..LSB):\n");
            for (int i = 0; i < 32; i++) printf("%02x", out_hash[i]);
            printf("\n");
            break;
        }

        // increment by number of threads (work distribution)
        counter += (uint32_t)total_threads;
    }
}

int main() {
    btc_block_header header;
    memset(&header, 0, sizeof(header));

    std::string version = "20000000";
    std::string prevblock = "ec2817f4c5803da6214c8d56c3707fc7e3b9af24000042660000000000000000";
    std::string ntime = "69120519";
    std::string nbits = "1701cdfb";
    std::string coinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5903";
    std::string coinb2 = "ffffffff0200f2052a010000001976a91409ab49fbb2d7c0f2b3c3b95b00000000";
    std::string extranonce1 = "00000001";
    std::string extranonce2 = "abcdef1200000000";
    uint32_t dif_target = 0x1e00ffff;

    uint8_t version_[4];
    uint8_t ntime_[4];
    uint8_t nbits_[4];
    int out = 0;
    utils_hex_to_bin(version.c_str(), version_, 4, &out);
    utils_hex_to_bin(ntime.c_str(), ntime_, 4, &out);
    utils_hex_to_bin(nbits.c_str(), nbits_, 4, &out);

    // gabungkan coinbase
    std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;

    // ubah ke biner
    std::vector<uint8_t> coinbase_bin(coinbase_hex.size() / 2);
    int outlen = 0;
    utils_hex_to_bin(coinbase_hex.c_str(), coinbase_bin.data(), coinbase_hex.size(), &outlen);

    // hitung coinbase hash (double sha256) — using OpenSSL wrapper
    uint8_t coinbase_hash[32];
    double_sha256_constbuf(coinbase_bin.data(), coinbase_bin.size(), coinbase_hash);

    // contoh branch (dari pool stratum)
    std::vector<std::string> branches = {
        "3bbe020a099447272f7c5ef8dbb7629a94abcbe7ac726d2c6748a1d530d1228d",
        "f6923076105a7b1f60726f94dbab30536e3c4ddfa80d4c0e403b52c06844dd8e",
        "90f7db6855eee312c5ddc7a9f3c6d7be1aa860caa3cefcec117beec3ea911b99"
    };

    uint8_t merkle_root[32];
    build_merkle_root(coinbase_hash, branches, merkle_root);

    // tampilkan hasil merkle (hex)
    char hexbuf[65];
    utils_bin_to_hex(merkle_root, 32, hexbuf);
    hexbuf[64] = 0;
    std::cout << "Merkle root: " << hexbuf << std::endl;

    // build header using libbtc utilities
    utils_uint256_sethex(const_cast<char*>(prevblock.c_str()), header.prev_block);
    memcpy(header.merkle_root, merkle_root, 32);
    memcpy(&header.version, version_, 4);
    memcpy(&header.bits, nbits_, 4);
    memcpy(&header.timestamp, ntime_, 4);
    header.nonce = 0;

    cstring* s = cstr_new_sz(80);
    btc_block_header_serialize(s, &header);

    std::cout << "Raw 80-byte header (from libbtc serialize):\n";
    for (size_t i = 0; i < s->len; ++i) printf("%02x", (unsigned char)s->str[i]);
    printf("\n");

    uint8_t target[32];
    target_build(dif_target, target);
    std::cout << "Target difficulty (32-byte big-endian):\n";
    for (int i = 0; i < 32; i++) printf("%02x", target[i]);
    printf("\n");

    const int THREAD_COUNT = std::max(1u, std::thread::hardware_concurrency());
    printf("Menjalankan %d thread...\n", THREAD_COUNT);

    uint8_t header_bin[80];
    memcpy(header_bin, s->str, 80);
    cstr_free(s, true);

    auto start = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> threads;
    run_miner = true;

    for (int t = 0; t < THREAD_COUNT; t++) {
        threads.emplace_back(
            miner_worker,
            header_bin,
            target,
            t,
            THREAD_COUNT
        );
    }

    for (auto &th : threads) th.join();

    auto end = std::chrono::high_resolution_clock::now();
    double seconds = std::chrono::duration<double>(end - start).count();
    printf("Waktu: %.3f s\n", seconds);

    if (hash_found)
        printf("Nonce ditemukan: %u\n", found_nonce.load());
    else
        printf("Tidak ditemukan\n");

    return 0;
}
