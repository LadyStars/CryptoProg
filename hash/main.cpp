#include <iostream>  
#include <fstream>  
#include <cryptopp/sha.h>  
#include <cryptopp/hex.h>  
#include <cryptopp/filters.h>  
#include <cryptopp/files.h>  
  
using namespace CryptoPP;  
  

int main()
{
    CryptoPP::SHA256 hash;
    std::string message = "Welcome";

    byte digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, (byte*)message.c_str(), message.length());

    std::cout << "Hash: ";
    for (int i = 0; i < CryptoPP::SHA256::DIGESTSIZE; i++) {
        std::cout << std::hex << (int)digest[i];
    }
    std::cout << std::endl;

    return 0;
}
