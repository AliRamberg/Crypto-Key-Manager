#ifndef _CLIENT_H
#define _CLIENT_H

#ifdef __APPLE__
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/algorithm/hex.hpp>

#include "Crypto.h"
#include "Users.h"

using boost::asio::ip::tcp;

class Client
{
private:
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
    UsersList *getUsers();
    Crypto *getCipherSuite();
    int main_menu();
};

#endif