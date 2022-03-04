#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include <iostream>
#include <tuple>
#include <boost/algorithm/hex.hpp>
#include <boost/asio.hpp>
#include "Crypto.h"
#define CLIENT_ID_MAX_LENGTH 128

/* int main()
{
#pragma pack(push, 1)
    struct
    {
        int i;
        char a, b;
        std::array<char, CLIENT_ID_MAX_LENGTH> client_id;

    } arr, out;
#pragma pack(pop)

    arr.a = 'a';
    arr.i = 128;
    arr.b = 'b';

    arr.client_id.

    std::cout << sizeof(arr) << std::endl;
    auto mutable_buffer = boost::asio::buffer((void *)&arr, sizeof(arr));

    // std::copy(mutable_buffer.begin, )
    std::string str((char *)mutable_buffer.data(), mutable_buffer.size());

    std::memcpy(&out, mutable_buffer.data(), mutable_buffer.size());

    std::cout << out.a << " " << out.b << " " << out.i << std::endl;

    // std::cout << str << std::endl;
    // std::cout << (char *)mutable_buffer.data() << std::endl;
}
 */

// class tester
// {
// private:
//     struct _test
//     {
//         char *data;
//     };

// public:
//     allocate(int , )
//     tester(/* args */);
//     ~tester();
// };

// tester::tester(/* args */)
// {
// }

// tester::~tester()
// {
// }

// int main(int argc, char const *argv[])
// {
//     int size = 10;
//     char *ptr;
//     allocate(size, &ptr);
//     std::memset(ptr, 'A', size);
//     std::cout << ptr << std::endl;
//     deallocate(ptr);
//     return 0;
// }

// int main(int argc, char const *argv[])
// {
//     boost::asio::io_context io_context;
//     boost::asio::posix::stream_descriptor input(io_context, STDIN_FILENO);
//     struct __res_t
//     {
//         std::array<char, 5> client_id;
//         std::array<char, 3> public_key;
//     } res_t;
//     boost::asio::read(input, boost::asio::buffer(reinterpret_cast<void *>(&res_t), sizeof(res_t)));

//     std::cout << sizeof(res_t) << std::endl;
//     std::cout << res_t.client_id.data() << std::endl;
//     std::cout << res_t.public_key.data() << std::endl;

//     return 0;
// }

// int main(int argc, char const *argv[])
// {
//     std::array<char, 5> arr = {'A', 'B', 'C', 'D'};
//     std::string s(arr.begin(), arr.end());
//     std::cout << s << std::endl;
//     std::cout << s.size() << std::endl;
//     std::cout << (s == "ABCD\0") << std::endl;
//     std::cout << std::endl;
//     return 0;
// }

std::tuple<int, int> func()
{
    return {2, 5};
}

// int main(int argc, char const *argv[])
// {
//     Crypto c;
//     std::string pubkey = c.encodePubKey();
//     std::string prvkey = c.encodePrvKey();
//     std::cout << "Public Key: " << pubkey.size() << std::endl
//               << pubkey << std::endl;

//     std::string pub_bytes = c.getPublicKey();
//     std::cout << "PUBLIC BYTES?: " << pub_bytes.size() << std::endl
//               << pub_bytes << std::endl;

//     std::cout << "Private Key: " << prvkey.size() << std::endl
//               << prvkey << std::endl;

//     std::string plain_text = "HI SHALOM OLAM!";
//     std::cout << "Plain Text: " << plain_text << std::endl;
//     CryptoPP::SecByteBlock encrypted;
//     c.encryptData(plain_text, &encrypted);

//     std::string encodedEncryptedText(encrypted.begin(), encrypted.end());

//     CryptoPP::SecByteBlock decrypted;
//     // auto ptr_decrypted = CryptoPP::BytePtr(encodedEncryptedText);
//     // CryptoPP::SecByteBlock cipher(ptr_decrypted, encodedEncryptedText.size());
//     c.decryptData(encrypted, &decrypted);

//     std::string encodedDecryptedText(decrypted.begin(), decrypted.end());
//     // auto hex = boost::algorithm::hex(encodedDecryptedText);
//     // std::cout << hex << std::endl;
//     std::cout << "Decrypted Data: " << encodedDecryptedText << std::endl;
// }

int main(int argc, char const *argv[])
{
    try
    {
        std::cout << "\n\n=== === === Generating AES Key === === ===" << std::endl;
        CryptoPP::SecByteBlock key, iv;
        Crypto::generateAESKey(&key, &iv);

        std::string plain = "SHALOM OLAM!";
        std::cout << "Plain String: " << plain << std::endl;

        std::cout << "\n\n=== === === Encrypting Data === === ===" << std::endl;
        std::string cipher;
        Crypto::encryptAES(plain, key, iv, cipher);
        std::cout << "Encrypted String: " << cipher << std::endl;

        std::cout << "\n\n=== === === Decrypting Data === === ===" << std::endl;
        std::string recovered;
        Crypto::decryptAES(cipher, key, iv, recovered);
        std::cout << "Recovered String: " << recovered << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}
