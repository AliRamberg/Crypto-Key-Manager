#include "Message.h"

Message::Message(tcp::socket &s, UsersList *users, Crypto *crypt) : s(s), users(users), crypt(crypt) {}

Message::~Message()
{
    // Do not delete `users` and `crypt` as these are kept in the Client class
}

// bool Message::read_creds()
// {
//     auto path = std::filesystem::path(CREDS_FILE);
//     const unsigned UUID_HEX = 32;
//     if (!std::filesystem::exists(path))
//         return false;
//     std::ifstream file(path, std::ios::beg);
//     std::string line;

//     // Username
//     std::getline(file, line);
//     if (line.size() < 1)
//     {
//         std::remove(CREDS_FILE);
//         return false;
//     }
//     username = line;
//     std::cout << "read username: " << username << '\n';

//     // ClientID
//     std::getline(file, line);
//     if (!std::all_of(line.begin(), line.end(), ::isxdigit) && line.size() < UUID_HEX)
//     {
//         std::remove(CREDS_FILE);
//         return false;
//     }
//     auto unhex = boost::algorithm::unhex(line);
//     std::copy(unhex.begin(), unhex.end(), req.header.client_id.data());
//     std::cout << "read client_id: " << unhex << '\n';

//     return true;
// }

bool Message::process_msg(const int input_code)
{
    switch (input_code)
    {
    case 110:
        return request_register();
    case 120:
        return request_list();
    case 130:
        return request_public_key();
    case 140:
        return request_messages();
    case 150:
        return request_send_text();
    case 151:
        return request_send_symkey();
    case 152:
        return request_recv_symkey();

    default:
        std::cerr << "Invalid option!" << std::endl;
        break;
    }

    return false;
}

void Message::send_message()
{
    // Send header first, fixed size
    // auto header = boost::asio::buffer(&req.header, sizeof(req.header));

    // TODO: log everything and add log("sending message to client {addr}:{port}, maybe?")
    std::cout << "Sending Header (" << sizeof(req.header) << ") bytes" << std::endl;
    boost::asio::write(s, boost::asio::buffer(&req.header, sizeof(req.header)));

    // send as much payload there is
    std::cout << "Sending Body (" << req.header.payload_length << ") bytes" << std::endl;
    boost::asio::write(s, boost::asio::buffer(req.body, req.header.payload_length));

    // Free memory once the data is sent
    delete[] req.body;
}

void Message::receive_message()
{
    std::memset(&res.header, 0, sizeof(res.header));
    std::cout << "Reading Header (" << sizeof(res.header) << ") bytes" << std::endl;
    boost::asio::read(s, boost::asio::buffer(reinterpret_cast<void *>(&res.header), sizeof(res.header)));
    switch (reinterpret_cast<Response_E &>(res.header.code))
    {
    case Response_E::REG_SUCCESS:
        response_register();
        break;
    case Response_E::SEND_USERS:
        response_list();
        break;
    case Response_E::PUB_KEY:
        response_public_key();
        break;
    case Response_E::USER_MESSAGES:
        response_messages();
        break;
    case Response_E::MESSAGE_SENT:
        response_msg_sent();
        break;

    case Response_E::RES_ERROR:
    default:
        std::cerr << "Error: server responded with error" << std::endl;
        break;
    }
}

// request 110
bool Message::request_register()
{

    /////// File
    if (std::filesystem::exists(CREDS_FILE))
    {
        std::cerr << "credentials file already exists" << std::endl;
        return false;
    }

    username.reserve(USERNAME_MAX_LENGTH);
    username.clear();

    /////// User Interaction
    std::cout << "Enter username: ";
    std::cin >> username;
    if (username.length() >= USERNAME_MAX_LENGTH)
    {
        throw std::length_error("error: the specified username is too long, it must be less than 255 characters");
    }

    /////// request initialize
    std::array<char, USERNAME_MAX_LENGTH> username_array;
    username_array.fill('\0');
    std::copy(username.begin(), username.end(), username_array.data());

    auto public_string = crypt->getPublicKey();
    std::copy(public_string.begin(), public_string.end(), public_key.data());

    // Header
    req.header.client_id.fill('\0');
    req.header.version = VERSION;
    req.header.code_type = Request_E::REG_REQUEST;
    req.header.payload_length = username_array.size() + public_key.size(); // 255 bytes username + 160 bytes public key

    // MessageData body
    req.body = new char[req.header.payload_length];
    std::memset(req.body, 0, req.header.payload_length);
    std::memcpy(req.body, username_array.data(), username_array.size());
    std::memcpy(req.body + username_array.size(), public_key.data(), public_key.size());

    return true;
}

// request 120
bool Message::request_list()
{
    req.header.code_type = Request_E::LIST_USERS;
    req.header.payload_length = 0;
    req.body = nullptr;

    return true;
}

// request 130
bool Message::request_public_key()
{
    req.header.code_type = Request_E::REQ_PUB;
    req.header.payload_length = CLIENT_UUID_LENGTH;

    std::string username;
    std::cout << "enter username: ";
    std::cin >> username;
    if (username.length() >= USERNAME_MAX_LENGTH)
    {
        throw std::length_error("error: the specified username is too long, it must be less than 255 characters");
    }

    auto id = users->getUid(username);
    // if (id.at(0))
    if (std::any_of(id.begin(), id.end(), [](char c)
                    { return c != '\0'; }))
    {
        req.body = new char[CLIENT_UUID_LENGTH];
        std::memset(req.body, 0, CLIENT_UUID_LENGTH);
        std::memcpy(req.body, id.data(), id.size());

        return true;
    }
    return false;
}

// operation 140
bool Message::request_messages()
{
    req.header.code_type = Request_E::GET_MSG;
    req.header.payload_length = 0;
    req.body = nullptr;

    return true;
}

// request 150
bool Message::request_send_text()
{

    req.header.code_type = Request_E::SND_MSG;
    std::string content;

    msg.recipient = client_input();
    msg.message_type = MessageType_E::SND_TXT;

    std::cout << "Enter message content: " << std::endl;
    std::cin >> content;

    // AES Cryptography
    auto symkey = users->getSymKey(username);

    if (std::all_of(symkey.begin(), symkey.end(), [](char c)
                    { return c == '\0'; }))
    {
        throw std::runtime_error("invalid symmetric key");
    }

    CryptoPP::SecByteBlock key((CryptoPP::byte *)symkey.data(), symkey.size());
    std::string cipher;
    Crypto::encryptAES(content, key, cipher);

    msg.message_size = cipher.size();
    req.header.payload_length = MESSAGE_HEADER_SIZE + cipher.size();

    // Body
    req.body = new char[req.header.payload_length];
    std::memcpy(req.body, &msg, sizeof(msg));
    std::memcpy(req.body + sizeof(msg), cipher.c_str(), cipher.size());

    return true;
}

// request 151
bool Message::request_send_symkey()
{
    req.header.code_type = Request_E::SND_MSG;
    req.header.payload_length = MESSAGE_HEADER_SIZE;

    msg.recipient = client_input();
    msg.message_type = MessageType_E::REQ_SYM;
    msg.message_size = 0;
    req.body = nullptr;

    return true;
}

bool Message::request_recv_symkey()
{
    req.header.code_type = Request_E::SND_MSG;

    auto client_id = client_input();
    auto pubkey = users->getPubKey(client_id);

    if (std::all_of(pubkey.begin(), pubkey.end(), [](char c)
                    { return c == '\0'; }))
    {
        throw std::runtime_error("invalid public key");
    }
    CryptoPP::SecByteBlock key;
    Crypto::generateAESKey(&key);

    // RSA Encryption
    CryptoPP::SecByteBlock cipher;
    std::string str_symkey((char *)key.BytePtr(), key.size());
    crypt->encryptData(str_symkey, &cipher);

    msg.message_type = MessageType_E::SND_SYM;
    msg.recipient = client_id;
    msg.message_size = cipher.size();
    req.header.payload_length = MESSAGE_HEADER_SIZE + cipher.size();

    // Body
    req.body = new char[req.header.payload_length];
    std::memcpy(req.body, &msg, sizeof(msg));
    std::memcpy(req.body + sizeof(msg), cipher.BytePtr(), cipher.size());

    return true;
}

// response 110
void Message::response_register()
{
    struct __res_t
    {
        std::array<char, CLIENT_UUID_LENGTH> client_id;
    } res_t;
    std::cout << "Reading Body: " << sizeof(res_t) << " bytes" << std::endl;
    boost::asio::read(s, boost::asio::buffer(reinterpret_cast<void *>(&res_t), sizeof(res_t)));
    req.header.client_id = res_t.client_id;
    std::filesystem::path path = CREDS_FILE;
    std::ofstream out(path, std::ios::out | std::ios::app);

    // fill username, uuid_data, private_key
    std::string id(res_t.client_id.begin(), res_t.client_id.end());
    auto hex = boost::algorithm::hex(id);

    out << username << '\n'
        << hex << '\n'
        << crypt->encodePrvKey();
    out.close();
}

// response 120
void Message::response_list()
{
    struct __res_t
    {
        std::array<char, CLIENT_UUID_LENGTH> client_id;
        std::array<char, USERNAME_MAX_LENGTH> username;
    } res_t;
    int users_num = res.header.payload_size / (CLIENT_UUID_LENGTH + USERNAME_MAX_LENGTH);
    for (int i = 0; i < users_num; i++)
    {
        boost::asio::read(s, boost::asio::buffer(reinterpret_cast<void *>(&res_t), sizeof(res_t)));
        std::cout << "Reading Body: User[" << res_t.username.data() << "], " << sizeof(res_t) << " bytes" << std::endl;
        // auto new_user = User(std::string(res_t.username.data()), res_t.client_id);
        auto user = std::string(res_t.username.data());
        auto new_user = User(res_t.username, res_t.client_id);
        users->append(new_user);
    }
}

// response 130
void Message::response_public_key()
{
    struct __res_t
    {
        std::array<char, CLIENT_UUID_LENGTH> client_id;
        std::array<char, PUBLIC_KEY_SIZE> pubkey;
    } res_t;
    std::cout << "Reading Body: " << sizeof(res_t) << " bytes" << std::endl;
    boost::asio::read(s, boost::asio::buffer(reinterpret_cast<void *>(&res_t), sizeof(res_t)));
    users->setPubKey(res_t.client_id, res_t.pubkey);
}

// response 140
void Message::response_messages()
{
    if (!res.header.payload_size)
    {
        std::cout << "No messages!" << std::endl;
        return;
    }

    struct __res_t
    {
        std::array<char, CLIENT_UUID_LENGTH> sender_id;
        std::uint32_t message_id;
        MessageType_E message_type;
        std::uint32_t message_size;
    } res_t;
    boost::asio::read(s, boost::asio::buffer(reinterpret_cast<void *>(&res_t), sizeof(res_t)));

    size_t msgs_bytes_left = res.header.payload_size;
    size_t bytes_read = 0;
    std::cout << "New messages: " << msgs_bytes_left << " bytes" << std::endl;
    while (bytes_read < msgs_bytes_left)
    {
        std::cout << "From: " << res_t.sender_id.data() << '\n'
                  << "Content: ";
        switch (res_t.message_size)
        {
        case MessageType_E::REQ_SYM:
            std::cout << "Request for symmetric key\n";
            break;
        case MessageType_E::SND_SYM:
            std::cout << "Symmetric key received\n";
            // TODO: Decrypt RSA with private key
            std::array<char, SYMMETRIC_KEY_SIZE> sym_buf;
            boost::asio::read(s, boost::asio::buffer(sym_buf, SYMMETRIC_KEY_SIZE));
            users->setSymKey(res_t.sender_id, sym_buf);
            break;
        case MessageType_E::SND_TXT:
        {
            // Full Encrypted message
            std::vector<char> full_message;

            std::array<char, MESSAGE_BUFFER_SIZE> buffer;
            unsigned cur_msg_bytes_read = 0;
            while (cur_msg_bytes_read < res_t.message_size)
            {
                bytes_read += boost::asio::read(s, boost::asio::buffer(buffer, buffer.size()));
                full_message.insert(full_message.end(), buffer.begin(), buffer.end());
            }
            // TODO: Decrypt AES with `sender_id` sym key
            auto symkey = users->getSymKey(res_t.sender_id);
            if (!std::all_of(symkey.begin(), symkey.end(), [](char c)
                             { return c == '\0'; }))
            {
                std::cout << "can't decrypt message\n";
                break;
            }
            std::string recovered;
            std::string encrypted(full_message.data());
            CryptoPP::SecByteBlock key((CryptoPP::byte *)symkey.data(), symkey.size());
            Crypto::decryptAES(encrypted, key, recovered);

            std::cout << recovered;
            break;
        }
        default:
            std::cerr << "Failed to parse message header" << std::endl;
            return;
        }
        std::cout << ".\n.\n-----<EOM>-----\n"
                  << std::endl;
    }
}

// response 150 | 151 | 152
void Message::response_msg_sent()
{
    struct __res_t
    {
        std::array<char, CLIENT_UUID_LENGTH> recipient_id;
        MessageType_E message_type;
    } res_t;
    std::cout << "Reading Body: " << sizeof(res_t) << " bytes" << std::endl;
    boost::asio::read(s, boost::asio::buffer(reinterpret_cast<void *>(&res_t), sizeof(res_t)));
}

std::array<char, CLIENT_UUID_LENGTH> Message::client_input()
{
    std::string username;
    std::cout << "Enter username of recipient: ";
    std::cin >> username;
    if (username.length() >= USERNAME_MAX_LENGTH)
    {
        throw std::length_error("error: the specified username is too long, it must be less than 255 characters");
    }

    auto user_id = users->getUid(username);
    if (std::all_of(user_id.begin(), user_id.end(), [](char c)
                    { return c == '\0'; }))
    {
        throw std::runtime_error(std::string("Username \"" + username + "\" was not found\n"));
    }
    return user_id;
}
