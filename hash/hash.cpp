#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

std::string ComputeFileHash(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        std::cerr << "Error opening file: " << filename << std::endl;
        return "";
    }

    SHA256 hash;
    byte buffer[1024];
    size_t bytesRead;
    while ((bytesRead = file.readsome(reinterpret_cast<char*>(buffer), sizeof(buffer))))
    {
        hash.Update(buffer, bytesRead);
    }

    std::string result;
    result.resize(hash.DigestSize());
    hash.Final(reinterpret_cast<byte*>(&result[0]));

    return result;
}

std::string HexEncode(const std::string& input)
{
    std::string output;
    StringSource(input, true, new HexEncoder(new StringSink(output), false));
    return output;
}

int main()
{
    std::string filename;
    std::cout << "Enter the file name: ";
    std::cin >> filename;

    std::string hashResult = ComputeFileHash(filename);
    if (!hashResult.empty())
    {
        std::cout << "Hash (SHA-256): " << HexEncode(hashResult) << std::endl;
    }

    return 0;
}

