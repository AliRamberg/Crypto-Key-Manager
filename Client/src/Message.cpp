#include "Message.h"

Message::Message(tcp::socket &s, std::array<char, CLIENT_UUID_LENGTH> uid, UsersList *users, Crypto *crypt) : s(s), users(users), crypt(crypt)
{
    if (!std::all_of(uid.begin(), uid.end(), [](const char c)
                     { return c == '\0'; }))
    {
        req.header.client_id = uid;
    }
}

Message::~Message()
{
    // Do not delete `users` and `crypt` as these are kept in the Client class
}

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

    // TODO: log everything and add log("sending message to client {addr}:{port}, maybe?")
    std::cout << "Sending Header " << sizeof(req.header) << " bytes" << std::endl;
    boost::asio::write(s, boost::asio::buffer(&req.header, sizeof(req.header)));

    // send as much payload there is
    std::cout << "Sending Body " << req.header.payload_length << " bytes" << std::endl;
    boost::asio::write(s, boost::asio::buffer(req.body, req.header.payload_length));

    // Free memory once the data is sent
    delete[] req.body;
}

void Message::receive_message()
{
    std::memset(&res.header, 0, sizeof(res.header));
    std::cout << "Reading Header " << sizeof(res.header) << " bytes" << std::endl;
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

    auto [username, uid] = client_input();
    msg.recipient = uid;
    msg.message_type = MessageType_E::SND_TXT;

    std::cout << "Enter message content: " << std::endl;
    std::getline(std::cin >> std::ws, content);

    // AES Cryptography
    auto symkey = users->getSymKey(username);

    if (std::all_of(symkey.begin(), symkey.end(), [](char c)
                    { return c == '\0'; }))
    {
        throw std::runtime_error("invalid symmetric key");
    }

    // CryptoPP::SecByteBlock key((CryptoPP::byte *)symkey.data(), symkey.size());
    std::string cipher;
    Crypto::encryptAES(content, symkey, cipher);

    msg.message_size = cipher.size();
    req.header.payload_length = MESSAGE_REQ_HEADER_SIZE + cipher.size();

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
    req.header.payload_length = MESSAGE_REQ_HEADER_SIZE;

    auto [username, uid] = client_input();
    msg.recipient = uid;
    msg.message_type = MessageType_E::REQ_SYM;
    msg.message_size = 0;

    // Body
    req.body = new char[MESSAGE_REQ_HEADER_SIZE];
    std::memcpy(req.body, &msg, sizeof(msg));

    return true;
}

// request 152
bool Message::request_recv_symkey()
{
    req.header.code_type = Request_E::SND_MSG;

    auto [username, client_id] = client_input();
    auto pubkey = users->getPubKey(client_id);

    if (std::all_of(pubkey.begin(), pubkey.end(), [](char c)
                    { return c == '\0'; }))
    {
        throw std::runtime_error("Invalid public key, try to retreive user public key");
    }

    std::string key = Crypto::generateAESKey();

    users->setSymKey(client_id, key);

    // RSA Encryption
    std::string pubkey_str(pubkey.begin(), pubkey.end());
    auto cipher = crypt->encryptData(key, pubkey_str);

    msg.message_type = MessageType_E::SND_SYM;
    msg.recipient = client_id;
    msg.message_size = cipher.size();
    req.header.payload_length = MESSAGE_REQ_HEADER_SIZE + cipher.size();

    // Body
    req.body = new char[req.header.payload_length];
    std::memset(req.body, 0, req.header.payload_length);
    std::memcpy(req.body, &msg, sizeof(msg));
    // std::memcpy(req.body + sizeof(msg), cipher.BytePtr(), cipher.size());
    std::memcpy(req.body + sizeof(msg), cipher.data(), cipher.size());

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

#pragma pack(push, 1)
    struct __res_t
    {
        std::array<char, CLIENT_UUID_LENGTH> sender_id;
        std::uint32_t message_id;
        std::uint8_t message_type;
        std::uint32_t message_size;
    } res_t;
#pragma pack(pop)

    size_t msgs_bytes_left = res.header.payload_size;
    size_t bytes_read = 0;

    std::cout << "New messages: " << msgs_bytes_left << " bytes" << std::endl;
    while (bytes_read < msgs_bytes_left)
    {
        bytes_read += boost::asio::read(s, boost::asio::buffer(reinterpret_cast<void *>(&res_t), MESSAGE_RES_HEADER_SIZE));
        std::cout << "Bytes read: " << bytes_read << std::endl;
        // USER WAS NOT FOUND!
        auto username = users->getUsername(res_t.sender_id);
        if (username.empty())
        {
            username = "<username could not be found, try to refresh user list>";
        }
        std::cout << "From: " << username << '\n'
                  << "Content: ";
        switch (res_t.message_type)
        {
        case MessageType_E::REQ_SYM:
            std::cout << "Request for symmetric key\n";
            break;
        case MessageType_E::SND_SYM:
        {
            std::cout << "Symmetric key received\n";

            std::array<char, ENCRYPTED_BUFFER_SIZE> encrypted_sym;
            bytes_read += boost::asio::read(s, boost::asio::buffer(encrypted_sym, ENCRYPTED_BUFFER_SIZE));

            // RSA Decryption
            std::string cipher(encrypted_sym.begin(), encrypted_sym.end());
            std::string recoved_sym = crypt->decryptData(cipher);

            std::array<char, SYMMETRIC_KEY_SIZE> symkey;
            std::copy(recoved_sym.begin(), recoved_sym.end(), symkey.data());

            users->setSymKey(res_t.sender_id, recoved_sym);
            break;
        }
        case MessageType_E::SND_TXT:
        {
            // Full Encrypted message
            std::vector<char> full_message;

            std::array<char, 16> buffer;
            unsigned cur_msg_bytes_read = 0;

            while (cur_msg_bytes_read < res_t.message_size)
            {
                cur_msg_bytes_read += boost::asio::read(s, boost::asio::buffer(buffer, buffer.size()));
                full_message.insert(full_message.end(), buffer.begin(), buffer.end());
            }

            // AES Decryption
            auto symkey = users->getSymKey(res_t.sender_id);
            if (std::all_of(symkey.begin(), symkey.end(), [](char c)
                            { return c == '\0'; }))
            {
                std::cout << "can't decrypt message\n";
                break;
            }
            std::string recovered;
            std::string encrypted_full(full_message.begin(), full_message.end());
            std::string encrypted(encrypted_full);
            Crypto::decryptAES(encrypted, symkey, recovered);

            std::cout << recovered;
            bytes_read += res_t.message_size;
            break;
        }
        default:
            std::cerr << "Failed to parse message header" << std::endl;
            return;
        }
        std::cout << "\n-----<EOM>-----\n"
                  << std::endl;
    }
}

// response 150 | 151 | 152
void Message::response_msg_sent()
{
    struct __res_t
    {
        std::array<char, CLIENT_UUID_LENGTH> recipient_id;
        std::uint32_t message_id;
    } res_t;
    // std::cout << "Reading Body: " << sizeof(res_t) << " bytes" << std::endl;
    boost::asio::read(s, boost::asio::buffer(reinterpret_cast<void *>(&res_t), sizeof(res_t)));
}

std::tuple<std::string, std::array<char, CLIENT_UUID_LENGTH>> Message::client_input()
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
        throw std::runtime_error("Username was not found");
    }
    return {username, user_id};
}
