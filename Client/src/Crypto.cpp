#include "Crypto.h"

Crypto::Crypto()
{
    private_key.Initialize(rng, KEY_SIZE);
    if (!private_key.Validate(rng, 2))
    {
        throw std::runtime_error("Rsa private key validation failed");
    }

    public_key = CryptoPP::RSA::PublicKey(private_key);
}

Crypto::Crypto(std::string &encoded_private)
{

    std::string decoded = decodePrvKey(encoded_private);

    CryptoPP::StringSource source(decoded, true);
    private_key.Load(source);
    if (!private_key.Validate(rng, 2))
    {
        throw std::runtime_error("Rsa private key validation failed");
    }
    public_key = CryptoPP::RSA::PublicKey(private_key);
}

std::string Crypto::encodePrvKey() const
{
    std::string encoded;
    std::string private_raw = getPrivateKey();
    CryptoPP::StringSource ss(private_raw, true,
                              new CryptoPP::Base64Encoder(
                                  new CryptoPP::StringSink(encoded), false));

    return encoded;
    // std::string encoded;
    // CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded), false);
    // // private_key.DEREncode(encoder);
    // private_key.DEREncodePrivateKey(encoder);
    // encoder.MessageEnd();

    // std::cout << "(WORKS) PRIVATE KEY: " << encoded.size() << std::endl;

    // return eklncoded;
}

std::string Crypto::encodePubKey() const
{
    std::string encoded;
    std::string public_raw = getPublicKey();
    CryptoPP::StringSource ss(public_raw, true,
                              new CryptoPP::Base64Encoder(
                                  new CryptoPP::StringSink(encoded)));

    return encoded;
    // std::string encoded;
    // CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded));
    // public_key.DEREncodePublicKey(encoder);
    // encoder.MessageEnd();

    // return encoded;
}

std::string Crypto::decodePrvKey(std::string &encoded) const
{
    std::string decoded;
    CryptoPP::StringSource ss(encoded, true,
                              new CryptoPP::Base64Decoder(
                                  new CryptoPP::StringSink(decoded)));

    return decoded;

    // std::string decoded;
    // CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(decoded));
    // decoder.Put((CryptoPP::byte *)encoded.data(), encoded.size());
    // decoder.MessageEnd();

    // std::cout << "(WORKS?) DECODED: String " << decoded.size() << std::endl;

    // return decoded;
}

std::string Crypto::getPrivateKey() const
{
    std::string key;
    CryptoPP::StringSink ss(key);
    private_key.Save(ss);
    return key;
}

std::string Crypto::getPublicKey() const
{
    std::string key;
    CryptoPP::StringSink ss(key);
    public_key.Save(ss);
    return key;
}

// void Crypto::encryptData(std::string &plain_string, CryptoPP::SecByteBlock *cipher_text) const
std::string Crypto::encryptData(std::string &plain_string, std::string &public_key)
{
    CryptoPP::RSA::PublicKey pub;

    CryptoPP::StringSource pub_source(reinterpret_cast<const CryptoPP::byte *>(public_key.c_str()), public_key.size(), true);
    pub.Load(pub_source);

    std::string cipher;

    CryptoPP::RSAES_OAEP_SHA_Encryptor e(pub);
    CryptoPP::StringSource ss(plain_string, true, new CryptoPP::PK_EncryptorFilter(rng, e, new CryptoPP::StringSink(cipher)));
    return cipher;
}

// void Crypto::decryptData(CryptoPP::SecByteBlock &cipher, std::string &recovered) const
std::string Crypto::decryptData(std::string &cipher)
{
    std::string decrypted;

    std::cout << "Z1" << std::endl;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(private_key);
    std::cout << "Z2" << std::endl;
    CryptoPP::StringSource ss_cipher(cipher, true, new CryptoPP::PK_DecryptorFilter(rng, d, new CryptoPP::StringSink(decrypted)));
    std::cout << "Z3" << std::endl;

    return decrypted;
}

std::string Crypto::generateAESKey()
{
    CryptoPP::AutoSeededRandomPool rng;

    // CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];

    rng.GenerateBlock(key, sizeof(key));

    std::string out((char *)key, sizeof(key));
    return out;
}

void Crypto::encryptAES(const std::string &plain, std::array<char, SYMMETRIC_KEY_SIZE> &key, std::string &cipher)
{
    // CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
    // CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    // iv.Assign(CryptoPP::AES::BLOCKSIZE, (CryptoPP::byte)'\0');

    // e.SetKeyWithIV(key, key.size(), iv);

    // CryptoPP::StringSource s(plain, true, new CryptoPP::StreamTransformationFilter(e, new CryptoPP::StringSink(cipher)));

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {0}; // for practical use iv should never be a fixed value!

    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const CryptoPP::byte *>(key.data()), key.size());
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    std::string cipher_txt;
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher_txt));
    stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte *>(plain.data()), plain.size());
    stfEncryptor.MessageEnd();

    cipher = cipher_txt;
    // return cipher;
}

void Crypto::decryptAES(std::string &cipher, std::array<char, SYMMETRIC_KEY_SIZE> &key, std::string &recovered)
{
    // CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
    // CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    // iv.Assign(CryptoPP::AES::BLOCKSIZE, (CryptoPP::byte)'\0');

    // d.SetKeyWithIV(key, key.size(), iv);

    // CryptoPP::StringSource s(cipher, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered))); // StringSource

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {0}; // for practical use iv should never be a fixed value!

    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const CryptoPP::byte *>(key.data()), key.size());
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    std::string decrypted;
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
    stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte *>(cipher.data()), cipher.size());
    stfDecryptor.MessageEnd();

    recovered = decrypted;
    // return decrypted;
}
