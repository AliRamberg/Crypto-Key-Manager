#ifndef _CLIENT_H
#define _CLIENT_H

#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>

#include "Definitions.h"
#include "Crypto.h"
#include "Users.h"

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/algorithm/hex.hpp>

using boost::asio::ip::tcp;

class Client
{
private:
    const size_t UUID_HEX_LEN = 32;
    const size_t PRIVATE_HEX_LEN = 844;
    void connect(const tcp::resolver::results_type &);
    Crypto *cipher_suite;
    UsersList *users;
    bool read_creds();
    void cleanup();

    std::string username;
    std::array<char, CLIENT_UUID_LENGTH> client_id;
    std::string encoded_private_key;

public:
    Client();
    ~Client();
    // ~Client();
    std::vector<std::string> read_server_info();
    std::array<char, CLIENT_UUID_LENGTH> getID() const;
    UsersList *getUsers();
    Crypto *getCipherSuite();
    int main_menu();
};

#endif