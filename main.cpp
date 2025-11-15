#include <btc/hash.h>
#include <btc/utils.h>
#include <btc/block.h>
#include <btc/serialize.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <inttypes.h>
#include <openssl/evp.h>
#include <chrono>
#include <thread>
#include <atomic>


std::atomic<bool> hash_found(false);
std::atomic<bool> run_miner(false);
std::atomic<uint32_t> found_nonce(0);


// 🔁 Helper untuk double SHA256
void double_sha256(const std::vector<uint8_t>& data, uint8_t out[32]) {
    uint8_t tmp[32];
    btc_hash_sngl_sha256(data.data(), data.size(), tmp);
    btc_hash_sngl_sha256(tmp, 32, out);
}

void double_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t tmp[32];
    btc_hash_sngl_sha256(data, len, tmp);
    btc_hash_sngl_sha256(tmp, 32, out);
}

void open_double_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    uint8_t first[32];
    unsigned int outlen;

    // hash pertama
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, first, &outlen);

    // hash kedua
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, first, 32);
    EVP_DigestFinal_ex(ctx, out, &outlen);

    EVP_MD_CTX_free(ctx);
}

// Fungsi konversi nBits → target 32-byte (uint8_t[32])
void target_build(uint32_t nBits, uint8_t target[32]) {
    memset(target, 0, 32);

    uint32_t exponent = nBits >> 24;
    uint32_t mantissa = nBits & 0x007fffff;

    // kalau bit ke-23 diset, itu menandakan nilai negatif (tapi tidak digunakan di Bitcoin)
    if (nBits & 0x00800000)
        mantissa = -mantissa;

    // Hitung posisi byte awal
    int shift = exponent - 3;

    if (shift >= 0 && shift < 29) {
        // mantissa dalam bentuk big endian
        target[31 - shift - 0] = (mantissa >> 16) & 0xff;
        target[31 - shift - 1] = (mantissa >> 8) & 0xff;
        target[31 - shift - 2] = (mantissa) & 0xff;
    }
}

// 🔁 Helper untuk gabung dua hash (Merkle combine)
void merkle_combine(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
    std::vector<uint8_t> buf(64);
    memcpy(buf.data(), left, 32);
    memcpy(buf.data() + 32, right, 32);
    double_sha256(buf, out);
}

// 🔨 Bangun merkle root dari coinbase_hash + merkle_branch[]
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


void miner_worker(uint8_t base_header[80], const uint8_t target[32], int thread_id, int total_threads)
{
    uint8_t local_header[80];
    uint8_t out_hash[32];

    memcpy(local_header, base_header, 80);

    // Pembagian nonce per thread
    uint32_t counter = thread_id;
    
    while (run_miner && counter < 0xffffffff) {

        // tulis nonce
        memcpy(local_header + 76, &counter, 4);

        open_double_sha256(local_header, 80, out_hash);

        // perbandingan hash
        if (memcmp(out_hash, target, 32) < 0) {
            hash_found = true;
            found_nonce = counter;

            printf("Thread %d menemukan hash! nonce = %u\n", thread_id, counter);

            printf("✅ Hash memenuhi target nonce = %" PRIu32 "\n", counter);
            std::cout << "Raw 80-byte header:\n";
            for (size_t i = 0; i <80; ++i) {
                printf("%02x", local_header[i]);
            }
            printf("\n");

            printf("Hash:\n");
            for (int i = 0; i < 32; i++)
                printf("%02x", out_hash[i]);
            printf("\n");

            break;
        }

        counter += total_threads;
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
    uint32_t dif_target = 0x1d00ffff;

    uint8_t version_[4];
    uint8_t ntime_[4];
    uint8_t nbits_[4];
    int out = 0;
    utils_hex_to_bin(version.c_str(),version_,4,&out);
    utils_hex_to_bin(ntime.c_str(),ntime_,4,&out);
    utils_hex_to_bin(nbits.c_str(),nbits_,4,&out);

    // gabungkan coinbase
    std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;

    // ubah ke biner
    std::vector<uint8_t> coinbase_bin(coinbase_hex.size() / 2);
    int outlen = 0;
    utils_hex_to_bin(coinbase_hex.c_str(), coinbase_bin.data(), coinbase_hex.size(), &outlen);

    // hitung coinbase hash
    uint8_t coinbase_hash[32];
    double_sha256(coinbase_bin, coinbase_hash);

    // contoh branch (dari pool stratum)
    std::vector<std::string> branches = {
        "3bbe020a099447272f7c5ef8dbb7629a94abcbe7ac726d2c6748a1d530d1228d",
        "f6923076105a7b1f60726f94dbab30536e3c4ddfa80d4c0e403b52c06844dd8e",
        "90f7db6855eee312c5ddc7a9f3c6d7be1aa860caa3cefcec117beec3ea911b99"
    };

    uint8_t merkle_root[32];
    build_merkle_root(coinbase_hash, branches, merkle_root);

    // tampilkan hasil
    char hex[65];
    utils_bin_to_hex(merkle_root, 32, hex);
    hex[64] = 0;

    std::cout << "Merkle root: " << hex << std::endl;

    // build header
    utils_uint256_sethex(const_cast<char*>(prevblock.c_str()), header.prev_block);
    memcpy(header.merkle_root,merkle_root,32);
    memcpy(&header.version,version_,4);
    memcpy(&header.bits,nbits_,4);
    memcpy(&header.timestamp,ntime_,4);
    header.nonce = 0;

    cstring* s = cstr_new_sz(80);
    btc_block_header_serialize(s, &header);

    // tampilkan isi header 80-byte dalam hex
    std::cout << "Raw 80-byte header:\n";
    for (size_t i = 0; i < s->len; ++i) {
        printf("%02x", (unsigned char)s->str[i]);
    }
    printf("\n");

    uint8_t target[32];
    target_build(dif_target,target);
    std::cout << "Target dificulty:\n";
    for (int i = 0; i < 32; i++)
        printf("%02x", target[i]);
    printf("\n");

    const int THREAD_COUNT = std::thread::hardware_concurrency();
    printf("Menjalankan %d thread...\n", THREAD_COUNT);

    uint8_t out_hash[32];
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

    for (auto &th : threads)
        th.join();

    auto end = std::chrono::high_resolution_clock::now();
    double seconds = std::chrono::duration<double>(end - start).count();

    printf("Waktu: %.3f s\n", seconds);

    if (hash_found)
        printf("Nonce ditemukan: %u\n", found_nonce.load());
    else
        printf("Tidak ditemukan\n");

/*
    for(int i=0;i<0xffffffff;i++)
    {
        header.nonce = counter;
        // tulis 4 byte terakhir (nonce) ke buffer
        memcpy(header_bin + 76, &counter, 4);

        double_sha256(header_bin, 80, out_hash);

        if (memcmp(out_hash, target, 32) < 0) {
            printf("✅ Hash memenuhi target nonce = %" PRIu32 "\n", counter);
            std::cout << "Raw 80-byte header:\n";
            for (size_t i = 0; i <80; ++i) {
                printf("%02x", header_bin[i]);
            }
            printf("\n");
            std::cout << "Hash valid:\n";
            for (int i = 0; i < 32; i++)
                printf("%02x", out_hash[i]);
            printf("\n");

            auto end = std::chrono::high_resolution_clock::now();
            double seconds = std::chrono::duration<double>(end - start).count();

            double hashes_per_second = counter / seconds;

            printf("Time elapsed: %.3f s\n", seconds);
            printf("Hashrate: %.2f H/s (%.2f MH/s)\n", hashes_per_second, hashes_per_second / 1e6);

            hash_found = true;
        }

        counter++;

    }
    printf("Hash selesai nonce = %" PRIu32 "\n", counter);
*/

    return 0;
}
