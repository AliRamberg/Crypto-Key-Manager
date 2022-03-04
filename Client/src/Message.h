#ifndef _MESSAGE_H
#define _MESSAGE_H

#ifdef __APPLE__
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <cstdint>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <boost/asio.hpp>

#include <boost/algorithm/hex.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>

#include "Definitions.h"
#include "Crypto.h"
#include "Client.h"
#include "MessageEnum.h"

#define MESSAGE_BUFFER_SIZE 1024

using namespace boost::asio::ip;

#pragma pack(push, 1)
struct _req_h
{
    // char client_id[CLIENT_UUID_LENGTH];
    std::array<char, CLIENT_UUID_LENGTH> client_id;
    std::uint8_t version;
    std::uint16_t code_type;
    std::uint32_t payload_length;
};

struct RequestMessage
{
    struct _req_h header;
    char *body;
};

struct _res_h
{
    std::uint8_t version;
    std::uint16_t code;
    std::uint32_t payload_size;
};
struct ResponseMessage
{
    struct _res_h header;
    // char *body;
};
#pragma pack(pop)

class Message
{
private:
    tcp::socket &s;
    std::string username;
    struct RequestMessage req;
    struct ResponseMessage res;

    UsersList *users;
    Crypto *crypt;

    // boost::asio::const_buffer data_header() const;

    bool read_creds(/* std::filesystem::path & */);

    // Requests
    bool request_register(/* bool */);
    bool request_list();
    bool request_public_key();
    bool request_messages();
    bool request_send_message();
    bool process_code_151();
    bool process_code_152();

    // Responses
    void response_register();
    void response_list();
    void response_public_key();
    void response_messages();

    std::array<char, PUBLIC_KEY_SIZE> public_key;

public:
    Message(tcp::socket &, UsersList *users, Crypto *crypt);
    ~Message();

    bool process_msg(const int);
    void send_message();
    void receive_message();
    boost::asio::mutable_buffer data();
};

#endif