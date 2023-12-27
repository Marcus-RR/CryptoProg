#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

class FileEncryptor
{
public:
    static void EncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password);
    static void DecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password);
};

void FileEncryptor::EncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte*>(password.data()), password.size(), nullptr, 0, 1000);

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv);

    FileSink fileSink(outputFile.c_str());

    // Записываем IV в выходной файл
    fileSink.Put(iv, AES::BLOCKSIZE);

    FileSource fileSource(inputFile.c_str(), true, new StreamTransformationFilter(encryptor, new Redirector(fileSink), BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING));
    fileSource.PumpAll();
}

void FileEncryptor::DecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte*>(password.data()), password.size(), nullptr, 0, 1000);

    byte iv[AES::BLOCKSIZE];

    // Считываем IV из входного файла
    FileSource(inputFile.c_str(), true, new ArraySink(iv, AES::BLOCKSIZE));

    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv);

    FileSource fileSource(inputFile.c_str(), true, new StreamTransformationFilter(decryptor, new FileSink(outputFile.c_str()), BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING));
    fileSource.PumpAll();
}



int main()
{
    std::string inputFile, outputFile, password;
    char mode;

    std::cout << "Enter mode (E: Encrypt, D: Decrypt): ";
    std::cin >> mode;

    std::cout << "Enter input file name: ";
    std::cin >> inputFile;

    std::cout << "Enter output file name: ";
    std::cin >> outputFile;

    std::cout << "Enter password: ";
    std::cin >> password;

    if (mode == 'E' || mode == 'e') {
        FileEncryptor::EncryptFile(inputFile, outputFile, password);
        std::cout << "Encryption complete.\n";
    } else if (mode == 'D' || mode == 'd') {
        FileEncryptor::DecryptFile(inputFile, outputFile, password);
        std::cout << "Decryption complete.\n";
    } else {
        std::cerr << "Invalid mode. Please enter 'E' for encrypt or 'D' for decrypt.\n";
        return 1;
    }

    return 0;
}
