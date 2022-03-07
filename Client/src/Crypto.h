#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <tuple>
#include <array>

#ifdef __APPLE__
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#endif
#ifdef WIN32
#include <modes.h>
#include <osrng.h>
#include <rsa.h>
#include <aes.h>
#include <files.h>
#include <base64.h>
#endif

#define KEY_SIZE 1024
#define SYMMETRIC_KEY_SIZE 16
#define PUBLIC_KEY_SIZE 160

class Crypto
{
private:
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSA::PrivateKey private_key;
    CryptoPP::RSA::PublicKey public_key;

    std::string getPrivateKey() const;
    std::string decodePrvKey(std::string &encoded) const;

public:
    Crypto();
    Crypto(std::string &encoded_private);

    // RSA Cipher Suite
    std::string encodePubKey() const;
    std::string encodePrvKey() const;
    std::string getPublicKey() const;

    // void encryptData(std::string &plain_string, CryptoPP::SecByteBlock *cipher) const;
    // void decryptData(CryptoPP::SecByteBlock &cipher, std::string &recovered) const;

    std::string encryptData(std::string &plain_string, std::string &public_key);
    std::string decryptData(std::string &cipher);

    // AES Cipher Suite

    static std::string generateAESKey();
    static void encryptAES(const std::string &plain, std::array<char, SYMMETRIC_KEY_SIZE> &key, std::string &cipher);
    static void decryptAES(std::string &cipher, std::array<char, SYMMETRIC_KEY_SIZE> &key, std::string &recovered);
};

#endif