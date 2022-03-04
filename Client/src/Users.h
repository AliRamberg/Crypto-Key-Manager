#ifndef _USERS_H
#define _USERS_H

#include <iostream>
#include <array>
#include <vector>

#include "Crypto.h"
#include "Definitions.h"

class User
{
private:
    std::string username;
    std::array<char, CLIENT_UUID_LENGTH> uid;
    std::array<char, PUBLIC_KEY_SIZE> pubkey;
    std::array<char, SYMMETRIC_KEY_SIZE> symkey;

public:
    User(std::array<char, USERNAME_MAX_LENGTH> &name, std::array<char, CLIENT_UUID_LENGTH> &uid);
    std::string getName();
    std::array<char, CLIENT_UUID_LENGTH> getUid() const;
    std::array<char, PUBLIC_KEY_SIZE> getKey();
    void setPubKey(std::array<char, PUBLIC_KEY_SIZE> &key);
    void setSymKey(std::array<char, SYMMETRIC_KEY_SIZE> &key);
};

class UsersList
{
private:
    std::vector<User> list;
    const User *getUserByName(std::string &name);
    User *getUserById(std::array<char, CLIENT_UUID_LENGTH> &id);

public:
    void append(User &u);
    std::array<char, CLIENT_UUID_LENGTH> getUid(std::string &name);
    void setPubKey(std::array<char, CLIENT_UUID_LENGTH> &id, std::array<char, PUBLIC_KEY_SIZE> key);
    void setSymKey(std::array<char, CLIENT_UUID_LENGTH> &id, std::array<char, SYMMETRIC_KEY_SIZE> key);
};

#endif
