#ifndef _MESSAGEENUM_H
#define _MESSAGEENUM_H

#include <iostream>
#include <stdint.h>

enum Request_E : std::uint16_t
{
    REG_REQUEST = 1100,
    LIST_USERS = 1101,
    REQ_PUB = 1102,
    SND_MSG = 1103,
    GET_MSG = 1104
};

enum MessageType_E : std::uint8_t
{
    REQ_SYM = 1,
    SND_SYM = 2,
    SND_TXT = 3
};

enum class Response_E : std::uint16_t
{
    REG_SUCCESS = 2100,
    SEND_USERS = 2101,
    PUB_KEY = 2102,
    MESSAGE_SENT = 2103,
    USER_MESSAGES = 2104,
    RES_ERROR = 9000
};

#endif