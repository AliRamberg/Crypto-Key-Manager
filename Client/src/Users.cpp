#include "Users.h"

User::User(std::array<char, USERNAME_MAX_LENGTH> &name, std::array<char, CLIENT_UUID_LENGTH> &uid) : uid(uid)
{
    username = std::string(name.data());
    pubkey.fill('\0');
    symkey.fill('\0');
}
std::string User::getName() { return username; }
std::array<char, CLIENT_UUID_LENGTH> User::getUid() const { return uid; }
std::array<char, PUBLIC_KEY_SIZE> User::getKey() { return pubkey; }
void User::setPubKey(std::array<char, PUBLIC_KEY_SIZE> &key)
{
    pubkey = key;
}

void User::setSymKey(std::array<char, SYMMETRIC_KEY_SIZE> &key)
{
    symkey = key;
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

const User *UsersList::getUserByName(std::string &name)
{
    auto found = std::find_if(list.begin(), list.end(), [&name](User &u)
                              { return u.getName() == name; });
    if (found != list.end())
    {
        return &(*found);
    }
    std::cerr << "failed to locate user" << '\n';
    return nullptr;
}
User *UsersList::getUserById(std::array<char, CLIENT_UUID_LENGTH> &id)
{
    auto found = std::find_if(list.begin(), list.end(), [&id](User &u)
                              { return u.getUid() == id; });
    if (found != list.end())
    {
        return &(*found);
    }
    std::cerr << "failed to locate user" << '\n';
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

void UsersList::setPubKey(std::array<char, CLIENT_UUID_LENGTH> &id, std::array<char, PUBLIC_KEY_SIZE> key)
{
    User *user = getUserById(id);
    std::cout << "Update User[" << user->getName() << "] public key";
    user->setPubKey(key);
}

void UsersList::setSymKey(std::array<char, CLIENT_UUID_LENGTH> &id, std::array<char, SYMMETRIC_KEY_SIZE> key)
{
    User *user = getUserById(id);
    std::cout << "Update User[" << user->getName() << "] symmetric key";
    user->setSymKey(key);
}
