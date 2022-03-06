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

    CryptoPP::StringSource pub_source(reinterpret_cast<const CryptoPP::byte *>(public_key.data()), public_key.size(), true);
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

    CryptoPP::RSAES_OAEP_SHA_Decryptor d(private_key);
    CryptoPP::StringSource ss_cipher(cipher, true, new CryptoPP::PK_DecryptorFilter(rng, d, new CryptoPP::StringSink(decrypted)));

    return decrypted;
}

void Crypto::generateAESKey(CryptoPP::SecByteBlock *key_out)
{
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);

    rng.GenerateBlock(key, key.size());

    *key_out = key;
}

void Crypto::encryptAES(std::string &plain, CryptoPP::SecByteBlock &key, std::string &cipher)
{
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    iv.Assign(CryptoPP::AES::BLOCKSIZE, (CryptoPP::byte)'\0');

    e.SetKeyWithIV(key, key.size(), iv);

    CryptoPP::StringSource s(plain, true, new CryptoPP::StreamTransformationFilter(e, new CryptoPP::StringSink(cipher)));
}

void Crypto::decryptAES(std::string &cipher, CryptoPP::SecByteBlock &key, std::string &recovered)
{
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    iv.Assign(CryptoPP::AES::BLOCKSIZE, (CryptoPP::byte)'\0');

    d.SetKeyWithIV(key, key.size(), iv);

    CryptoPP::StringSource s(cipher, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered))); // StringSource
}
