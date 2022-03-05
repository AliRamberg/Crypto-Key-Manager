#include "Crypto.h"

Crypto::Crypto()
{
    CryptoPP::AutoSeededRandomPool rng;
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
    CryptoPP::AutoSeededRandomPool rng;

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
    // CryptoPP::RSAFunction publicKey(private_key);
    // std::string key;
    // CryptoPP::StringSink ss(key);
    // publicKey.Save(ss);
    // return key;
    std::string key;
    CryptoPP::StringSink ss(key);
    public_key.Save(ss);
    return key;
}

void Crypto::encryptData(std::string &plain_string, CryptoPP::SecByteBlock *cipher_text) const
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(public_key);

    CryptoPP::SecByteBlock plaintxt(plain_string.size());
    std::memcpy(plaintxt, plain_string.data(), plain_string.size());

    // Validate encryptor
    assert(0 != encryptor.FixedMaxPlaintextLength());
    assert(plaintxt.size() <= encryptor.FixedMaxPlaintextLength());

    // Create cipher text space
    size_t ecl = encryptor.CiphertextLength(plaintxt.size());
    assert(0 != ecl);
    CryptoPP::SecByteBlock cipher(ecl);

    encryptor.Encrypt(rng, plaintxt, plaintxt.size(), cipher);
    *cipher_text = cipher;
}

void Crypto::decryptData(CryptoPP::SecByteBlock &cipher, std::string &recovered) const
{
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(private_key);

    // Validate decryptor
    assert(0 != decryptor.FixedCiphertextLength());
    assert(cipher.size() <= decryptor.FixedCiphertextLength());

    // Create recovered text space
    size_t dpl = decryptor.MaxPlaintextLength(cipher.size());
    assert(0 != dpl);
    CryptoPP::SecByteBlock recovered_block(dpl);

    CryptoPP::DecodingResult result = decryptor.Decrypt(rng, cipher, cipher.size(), recovered_block);

    // More sanity checks
    assert(result.isValidCoding);
    assert(result.messageLength <= decryptor.MaxPlaintextLength(cipher.size()));

    // At this point, we can set the size of the recovered
    //  data. Until decryption occurs (successfully), we
    //  only know its maximum size
    recovered_block.resize(result.messageLength);
    std::string recovered_str(recovered_block.begin(), recovered_block.end());

    // *recovered_text = recovered;
    recovered = recovered_str;
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
