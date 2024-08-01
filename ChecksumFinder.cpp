#include <iostream>
#include <thread>
#include <future>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <vector>
#include <Windows.h>
#include <bcrypt.h>
#include <ntstatus.h>

#pragma comment(lib, "bcrypt.lib")

namespace ChecksumFinder {
    std::string get_checksum(const std::string& path);
}

int main()
{
    try {
        std::string path = "";

        while (true) {
            std::cout << "Enter file path: ";
            std::getline(std::cin, path);

            if (!path.empty()) {
                std::ifstream check_stream(path);
                if (check_stream.good()) {
                    break;
                }
                else {
                    std::cout << "This file doesn't exist." << std::endl;
                }
            }
            else {
                std::cout << "File path cannot be empty." << std::endl;
            }
        }

        std::string checksum = ChecksumFinder::get_checksum(path);
        std::cout << checksum;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

std::string ChecksumFinder::get_checksum(const std::string& path) {
    BCRYPT_ALG_HANDLE hAlgo = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = 0;
    DWORD cbData = 0, cbHashObject = 0, cbHash = 0;
    std::vector<BYTE> pbHashObject;
    std::vector<BYTE> pbHash;

    // Open an algorithm handle
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlgo, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed.");
    }

    // Calculate the size of the buffer to hold the hash object
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlgo, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
        BCryptCloseAlgorithmProvider(hAlgo, 0);
        throw std::runtime_error("BCryptGetProperty failed.");
    }

    pbHashObject.resize(cbHashObject);

    // Calculate the length of the hash
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlgo, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0))) {
        BCryptCloseAlgorithmProvider(hAlgo, 0);
        throw std::runtime_error("BCryptGetProperty failed.");
    }

    pbHash.resize(cbHash);

    // Create a hash
    if (!BCRYPT_SUCCESS(status = BCryptCreateHash(hAlgo, &hHash, pbHashObject.data(), cbHashObject, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlgo, 0);
        throw std::runtime_error("BCryptCreateHash failed.");
    }

    // Open the file
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgo, 0);
        throw std::runtime_error("Could not open file.");
    }

    // Read file and hash data
    std::vector<char> buffer(8192);
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        if (!BCRYPT_SUCCESS(status = BCryptHashData(hHash, reinterpret_cast<PUCHAR>(buffer.data()), file.gcount(), 0))) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlgo, 0);
            throw std::runtime_error("BCryptHashData failed.");
        }
    }

    // Finalize the hash
    if (!BCRYPT_SUCCESS(status = BCryptFinishHash(hHash, pbHash.data(), cbHash, 0))) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgo, 0);
        throw std::runtime_error("BCryptFinishHash failed.");
    }

    // Cleanup
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlgo, 0);

    // Convert hash to hex string
    std::stringstream ss;
    for (BYTE b : pbHash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }

    return ss.str();
}
