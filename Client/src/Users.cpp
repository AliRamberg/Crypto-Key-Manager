#include "Users.h"

User::User(std::array<char, USERNAME_MAX_LENGTH> &name, std::array<char, CLIENT_UUID_LENGTH> &uid) : uid(uid)
{
    username = std::string(name.data());
    pubkey.fill('\0');
    symkey.fill('\0');
}
std::string User::getName() const { return username; }
std::array<char, CLIENT_UUID_LENGTH> User::getUid() const { return uid; }

std::array<char, PUBLIC_KEY_SIZE> User::getKey() { return pubkey; }
void User::setPubKey(std::array<char, PUBLIC_KEY_SIZE> &key)
{
    pubkey = key;
}

void User::setSymKey(std::string &key)
{
    std::copy(key.begin(), key.end(), symkey.data());
}

std::array<char, PUBLIC_KEY_SIZE> User::getPubKey() const
{
    return pubkey;
}

std::array<char, SYMMETRIC_KEY_SIZE> User::getSymKey() const
{
    return symkey;
}

void UsersList::append(User &u)
{
    auto found = std::find_if(list.begin(), list.end(), [&](User &user)
                              { return user.getUid() == u.getUid(); });
    if (found != list.end())
    {
        std::cerr << "user already in list, skipping..." << std::endl;
    }
    else
    {
        list.push_back(u);
    }
}

const User *UsersList::getUserByName(std::string &name) const
{
    auto found = std::find_if(list.begin(), list.end(), [&name](const User &u)
                              { return u.getName() == name; });
    if (found != list.end())
    {
        return (const User *)&(*found);
    }
    return nullptr;
}
User *UsersList::getUserById(std::array<char, CLIENT_UUID_LENGTH> &id) const
{
    auto found = std::find_if(list.begin(), list.end(), [&id](const User &u)
                              { return u.getUid() == id; });
    if (found != list.end())
    {
        return (User *)&(*found);
    }

    return nullptr;
}

std::array<char, CLIENT_UUID_LENGTH> UsersList::getUid(std::string &name)
{
    const User *user = getUserByName(name);
    if (user)
    {
        return user->getUid();
    }
    return {};
}
std::string UsersList::getUsername(std::array<char, CLIENT_UUID_LENGTH> &uid)
{
    const User *user = getUserById(uid);
    if (user)
    {
        return user->getName();
    }
    return {};
}

void UsersList::setPubKey(std::array<char, CLIENT_UUID_LENGTH> &id, std::array<char, PUBLIC_KEY_SIZE> key)
{
    User *user = getUserById(id);
    std::cout << "Update User[" << user->getName() << "] public key\n";
    user->setPubKey(key);
}

void UsersList::setSymKey(std::array<char, CLIENT_UUID_LENGTH> &id, std::string &key)
{

    User *user = getUserById(id);
    if (!user)
    {
        throw std::runtime_error("User was not found, try to refresh user list");
    }
    std::cout << "Update User[" << user->getName() << "] symmetric key\n";
    user->setSymKey(key);
}

std::array<char, SYMMETRIC_KEY_SIZE> UsersList::getSymKey(std::string &username) const
{
    const User *user = getUserByName(username);
    if (user)
    {
        std::cout << "USER FOUND" << std::endl;
        return user->getSymKey();
    }
    std::cout << "USER NOT FOUND" << std::endl;
    return {};
}

std::array<char, SYMMETRIC_KEY_SIZE> UsersList::getSymKey(std::array<char, CLIENT_UUID_LENGTH> &uid) const
{
    const User *user = getUserById(uid);
    if (user)
    {
        return user->getSymKey();
    }
    return {};
}

std::array<char, PUBLIC_KEY_SIZE> UsersList::getPubKey(std::string &username) const
{
    const User *user = getUserByName(username);
    if (user)
    {
        return user->getPubKey();
    }
    return {};
}

std::array<char, PUBLIC_KEY_SIZE> UsersList::getPubKey(std::array<char, CLIENT_UUID_LENGTH> &uid) const
{
    const User *user = getUserById(uid);
    if (user)
    {
        return user->getPubKey();
    }
    return {};
}
