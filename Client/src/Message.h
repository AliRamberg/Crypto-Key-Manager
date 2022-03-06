#ifndef _MESSAGE_H
#define _MESSAGE_H

#include <cstdint>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>

#include "Definitions.h"
#include "Crypto.h"
#include "Client.h"
#include "MessageEnum.h"

#include <boost/asio.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/endian/conversion.hpp>
//

#define MESSAGE_BUFFER_SIZE 1024

using namespace boost::asio::ip;

#pragma pack(push, 1)
struct __req_h
{
    // char client_id[CLIENT_UUID_LENGTH];
    std::array<char, CLIENT_UUID_LENGTH> client_id;
    std::uint8_t version;
    std::uint16_t code_type;
    std::uint32_t payload_length;
};

struct Request
{
    struct __req_h header;
    char *body;
};

struct __res_h
{
    std::uint8_t version;
    std::uint16_t code;
    std::uint32_t payload_size;
};
struct Response
{
    struct __res_h header;
    // char *body;
};

struct msg
{
    std::array<char, CLIENT_UUID_LENGTH> recipient;
    MessageType_E message_type;
    std::uint32_t message_size;
};
#pragma pack(pop)

class Message
{
private:
    tcp::socket &s;
    std::string username;
    struct msg msg;
    struct Request req;
    struct Response res;

    UsersList *users;
    Crypto *crypt;

    std::array<char, CLIENT_UUID_LENGTH> client_input();
    std::array<char, PUBLIC_KEY_SIZE> public_key;

    // Requests
    bool request_register(/* bool */);
    bool request_list();
    bool request_public_key();
    bool request_messages();
    bool request_send_text();
    bool request_send_symkey();
    bool request_recv_symkey();

    // Responses
    void response_register();
    void response_list();
    void response_public_key();
    void response_messages();
    void response_msg_sent();

public:
    Message(tcp::socket &, std::array<char, CLIENT_UUID_LENGTH> id, UsersList *users, Crypto *crypt);
    ~Message();

    bool process_msg(const int);
    void send_message();
    void receive_message();
};

#endif