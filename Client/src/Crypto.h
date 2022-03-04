#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <tuple>

#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

#define KEY_SIZE 1024
#define SYMMETRIC_KEY_SIZE 128
#define PUBLIC_KEY_SIZE 160

class Crypto
{
private:
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

    void encryptData(std::string &plain_string, CryptoPP::SecByteBlock *cipher) const;
    void decryptData(CryptoPP::SecByteBlock &cipher, std::string &recovered) const;

    // AES Cipher Suite
    static void generateAESKey(CryptoPP::SecByteBlock *key_out, CryptoPP::SecByteBlock *iv_out);
    static void encryptAES(std::string &plain, CryptoPP::SecByteBlock &key, CryptoPP::SecByteBlock &iv, std::string &cipher);
    static void decryptAES(std::string &cipher, CryptoPP::SecByteBlock &key, CryptoPP::SecByteBlock &iv, std::string &recovered);
};

#endif