#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h> 

using namespace CryptoPP;


void encrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, (byte*)password.data(), password.size(), NULL, 0, 1024, 0.0f);

    byte iv[AES::BLOCKSIZE];
    memset(iv, 0x00, AES::BLOCKSIZE); 

    CBC_Mode<AES>::Encryption enc(key, key.size(), iv);
    FileSource fs(inputFile.c_str(), true, 
                  new StreamTransformationFilter(enc, 
                  new FileSink(outputFile.c_str())));
}

void decrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, (byte*)password.data(), password.size(), NULL, 0, 1024, 0.0f);

    byte iv[AES::BLOCKSIZE];	
    memset(iv, 0x00, AES::BLOCKSIZE);

    CBC_Mode<AES>::Decryption dec(key, key.size(), iv);
    FileSource fs(inputFile.c_str(), true, new StreamTransformationFilter(dec, new FileSink(outputFile.c_str())));
}

int main() {
    std::string mode, inputFile, outputFile, password;
    std::cout << "Введите режим работы (e(ncrypt)/d(ecrypt)): ";
    std::cin >> mode;
    std::cout << "Введите путь к входному файлу: ";
    std::cin >> inputFile;
    std::cout << "Введите путь к выходному файлу: ";
    std::cin >> outputFile;
    std::cout << "Введите пароль: ";
    std::cin >> password;
    if (mode == "e") {
        encrypt(inputFile, outputFile, password);
    } 
    else if (mode == "d") {
        decrypt(inputFile, outputFile, password);
    } 
    else {
        std::cout << "Неверный режим" << std::endl;
    }

    return 0;
}
