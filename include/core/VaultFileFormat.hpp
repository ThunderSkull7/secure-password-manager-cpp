#pragma once

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "core/CryptoParameters.hpp"
#include "core/Result.hpp"

namespace password_manager::core {

struct VaultFileFormat {
    // Magic: "SPMV" (Secure Password Manager Vault)
    static constexpr std::array<unsigned char, 4> MAGIC{'S', 'P', 'M', 'V'};

    // Supported versions and algorithms
    static constexpr std::uint32_t CURRENT_VERSION = 1;
    static constexpr std::uint32_t CIPHER_ALGO_XCHACHA20_POLY1305 = 1;
    static constexpr std::uint32_t KDF_ALGO_ARGON2ID13 = 2;  // crypto_pwhash_ALG_ARGON2ID13

    // Field sizes (in bytes)
    static constexpr std::size_t MAGIC_SIZE = 4;
    static constexpr std::size_t VERSION_SIZE = 4;
    static constexpr std::size_t CIPHER_ALGO_SIZE = 4;
    static constexpr std::size_t KDF_ALGO_SIZE = 4;
    static constexpr std::size_t OPS_LIMIT_SIZE = 8;
    static constexpr std::size_t MEM_LIMIT_SIZE = 8;
    static constexpr std::size_t SALT_SIZE = CryptoConstants::SALT_BYTES;    // 16
    static constexpr std::size_t NONCE_SIZE = CryptoConstants::NONCE_BYTES;  // 24
    static constexpr std::size_t CIPHERTEXT_LEN_SIZE = 8;

    // Additional Authenticated Data (AAD) size: 48 bytes
    static constexpr std::size_t AAD_SIZE = MAGIC_SIZE + VERSION_SIZE + CIPHER_ALGO_SIZE +
                                            KDF_ALGO_SIZE + OPS_LIMIT_SIZE + MEM_LIMIT_SIZE +
                                            SALT_SIZE;

    // Total fixed-width header size: 80 bytes
    static constexpr std::size_t HEADER_SIZE = AAD_SIZE + NONCE_SIZE + CIPHERTEXT_LEN_SIZE;

    // Safe KDF Resource limits (validated before calling Argon2id)
    static constexpr std::uint64_t MIN_KDF_OPS_LIMIT = crypto_pwhash_OPSLIMIT_MIN;  // 1
    static constexpr std::uint64_t MAX_KDF_OPS_LIMIT = 10;
    static constexpr std::uint64_t MIN_KDF_MEM_LIMIT = crypto_pwhash_MEMLIMIT_MIN;  // 8192 (8 KiB)
    static constexpr std::uint64_t MAX_KDF_MEM_LIMIT = 512 * 1024 * 1024;           // 512 MiB

    // Maximum file and payload limits to guard against memory exhaustion attacks
    static constexpr std::size_t MAX_VAULT_FILE_SIZE = 16 * 1024 * 1024;                 // 16 MiB
    static constexpr std::size_t MAX_PAYLOAD_SIZE = CryptoConstants::MAX_PAYLOAD_BYTES;  // 16 MiB
    static constexpr std::size_t MAX_CREDENTIAL_COUNT = 100'000;
};

struct VaultHeader {
    std::uint32_t version{VaultFileFormat::CURRENT_VERSION};
    std::uint32_t cipher_algorithm{VaultFileFormat::CIPHER_ALGO_XCHACHA20_POLY1305};
    std::uint32_t kdf_algorithm{VaultFileFormat::KDF_ALGO_ARGON2ID13};
    std::uint64_t kdf_ops_limit{crypto_pwhash_OPSLIMIT_INTERACTIVE};
    std::uint64_t kdf_mem_limit{crypto_pwhash_MEMLIMIT_INTERACTIVE};
    std::array<unsigned char, CryptoConstants::SALT_BYTES> salt{};
    std::array<unsigned char, CryptoConstants::NONCE_BYTES> nonce{};
    std::uint64_t ciphertext_length{0};

    [[nodiscard]] std::array<unsigned char, VaultFileFormat::AAD_SIZE> serialize_aad()
        const noexcept {
        std::array<unsigned char, VaultFileFormat::AAD_SIZE> aad{};
        aad[0] = VaultFileFormat::MAGIC[0];
        aad[1] = VaultFileFormat::MAGIC[1];
        aad[2] = VaultFileFormat::MAGIC[2];
        aad[3] = VaultFileFormat::MAGIC[3];

        write_uint32_le(&aad[4], version);
        write_uint32_le(&aad[8], cipher_algorithm);
        write_uint32_le(&aad[12], kdf_algorithm);
        write_uint64_le(&aad[16], kdf_ops_limit);
        write_uint64_le(&aad[24], kdf_mem_limit);
        std::copy_n(salt.data(), CryptoConstants::SALT_BYTES, &aad[32]);

        return aad;
    }

    [[nodiscard]] std::array<unsigned char, VaultFileFormat::HEADER_SIZE> serialize_header()
        const noexcept {
        std::array<unsigned char, VaultFileFormat::HEADER_SIZE> hdr{};
        const auto aad = serialize_aad();
        std::copy(aad.begin(), aad.end(), hdr.begin());

        std::copy_n(nonce.data(), CryptoConstants::NONCE_BYTES, &hdr[VaultFileFormat::AAD_SIZE]);
        write_uint64_le(&hdr[VaultFileFormat::AAD_SIZE + VaultFileFormat::NONCE_SIZE],
                        ciphertext_length);

        return hdr;
    }

    [[nodiscard]] static Result<VaultHeader> deserialize(std::span<const unsigned char> bytes) {
        if (bytes.size() < VaultFileFormat::HEADER_SIZE) {
            return Result<VaultHeader>::failure(
                VaultErrorCode::CorruptedVault,
                "Vault header is smaller than required 80-byte header size.");
        }

        if (bytes[0] != VaultFileFormat::MAGIC[0] || bytes[1] != VaultFileFormat::MAGIC[1] ||
            bytes[2] != VaultFileFormat::MAGIC[2] || bytes[3] != VaultFileFormat::MAGIC[3]) {
            return Result<VaultHeader>::failure(
                VaultErrorCode::InvalidVaultFormat,
                "Invalid magic identifier: file is not a valid Secure Password Manager Vault.");
        }

        const auto version = read_uint32_le(&bytes[4]);
        if (version != VaultFileFormat::CURRENT_VERSION) {
            return Result<VaultHeader>::failure(
                VaultErrorCode::UnsupportedVersion,
                "Unsupported vault version: " + std::to_string(version) + " (expected " +
                    std::to_string(VaultFileFormat::CURRENT_VERSION) + ").");
        }

        const auto cipher_algo = read_uint32_le(&bytes[8]);
        if (cipher_algo != VaultFileFormat::CIPHER_ALGO_XCHACHA20_POLY1305) {
            return Result<VaultHeader>::failure(
                VaultErrorCode::InvalidVaultFormat,
                "Unsupported cipher algorithm ID: " + std::to_string(cipher_algo));
        }

        const auto kdf_algo = read_uint32_le(&bytes[12]);
        if (kdf_algo != VaultFileFormat::KDF_ALGO_ARGON2ID13) {
            return Result<VaultHeader>::failure(
                VaultErrorCode::InvalidKdfParameters,
                "Unsupported KDF algorithm ID: " + std::to_string(kdf_algo) +
                    " (expected Argon2id v1.3).");
        }

        const auto ops_limit = read_uint64_le(&bytes[16]);
        if (ops_limit < VaultFileFormat::MIN_KDF_OPS_LIMIT ||
            ops_limit > VaultFileFormat::MAX_KDF_OPS_LIMIT) {
            return Result<VaultHeader>::failure(
                VaultErrorCode::ResourceLimitExceeded,
                "Argon2id operations limit (" + std::to_string(ops_limit) +
                    ") is outside safe resource bounds [" +
                    std::to_string(VaultFileFormat::MIN_KDF_OPS_LIMIT) + ", " +
                    std::to_string(VaultFileFormat::MAX_KDF_OPS_LIMIT) + "].");
        }

        const auto mem_limit = read_uint64_le(&bytes[24]);
        if (mem_limit < VaultFileFormat::MIN_KDF_MEM_LIMIT ||
            mem_limit > VaultFileFormat::MAX_KDF_MEM_LIMIT) {
            return Result<VaultHeader>::failure(
                VaultErrorCode::ResourceLimitExceeded,
                "Argon2id memory limit (" + std::to_string(mem_limit) +
                    " bytes) is outside safe resource bounds [" +
                    std::to_string(VaultFileFormat::MIN_KDF_MEM_LIMIT) + ", " +
                    std::to_string(VaultFileFormat::MAX_KDF_MEM_LIMIT) + "].");
        }

        VaultHeader header;
        header.version = version;
        header.cipher_algorithm = cipher_algo;
        header.kdf_algorithm = kdf_algo;
        header.kdf_ops_limit = ops_limit;
        header.kdf_mem_limit = mem_limit;

        std::copy_n(&bytes[32], CryptoConstants::SALT_BYTES, header.salt.data());
        std::copy_n(&bytes[48], CryptoConstants::NONCE_BYTES, header.nonce.data());

        const auto ct_len = read_uint64_le(&bytes[72]);
        if (ct_len < CryptoConstants::TAG_BYTES) {
            return Result<VaultHeader>::failure(
                VaultErrorCode::CorruptedVault,
                "Ciphertext length is smaller than the required AEAD authentication tag.");
        }

        if (ct_len > VaultFileFormat::MAX_PAYLOAD_SIZE + CryptoConstants::TAG_BYTES) {
            return Result<VaultHeader>::failure(
                VaultErrorCode::ResourceLimitExceeded,
                "Ciphertext length exceeds maximum permitted limit.");
        }

        header.ciphertext_length = ct_len;
        return Result<VaultHeader>(header);
    }

  private:
    static void write_uint32_le(unsigned char* dest, std::uint32_t val) noexcept {
        dest[0] = static_cast<unsigned char>(val & 0xFF);
        dest[1] = static_cast<unsigned char>((val >> 8) & 0xFF);
        dest[2] = static_cast<unsigned char>((val >> 16) & 0xFF);
        dest[3] = static_cast<unsigned char>((val >> 24) & 0xFF);
    }

    static void write_uint64_le(unsigned char* dest, std::uint64_t val) noexcept {
        for (std::size_t i = 0; i < 8; ++i) {
            dest[i] = static_cast<unsigned char>((val >> (i * 8)) & 0xFF);
        }
    }

    static std::uint32_t read_uint32_le(const unsigned char* src) noexcept {
        return static_cast<std::uint32_t>(src[0]) | (static_cast<std::uint32_t>(src[1]) << 8) |
               (static_cast<std::uint32_t>(src[2]) << 16) |
               (static_cast<std::uint32_t>(src[3]) << 24);
    }

    static std::uint64_t read_uint64_le(const unsigned char* src) noexcept {
        std::uint64_t val = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            val |= (static_cast<std::uint64_t>(src[i]) << (i * 8));
        }
        return val;
    }
};

}  // namespace password_manager::core
