#include "Message.h"

Message::Message(tcp::socket &s, UsersList *users, Crypto *crypt) : s(s), users(users), crypt(crypt)
{
}

Message::~Message()
{
}

bool Message::read_creds()
{
    auto path = std::filesystem::path(CREDS_FILE);
    if (!std::filesystem::exists(path))
        return false;
    std::ifstream file(path, std::ios::beg);
    std::string line;

    // Username
    std::getline(file, line);
    if (line.size() < 1)
    {
        return false;
    }
    username = line;
    std::cout << "read username: " << username << '\n';

    // ClientID
    std::getline(file, line);
    if (!std::all_of(line.begin(), line.end(), ::isxdigit))
    {
        return false;
    }
    auto unhex = boost::algorithm::unhex(line);
    std::copy(unhex.begin(), unhex.end(), req.header.client_id.data());
    std::cout << "read client_id: " << unhex << '\n';

    return true;
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
        return request_send_message();
    case 151:
        break;
    case 152:
        break;

    default:
        break;
    }

    std::cerr << "failed to initialize request" << std::endl;
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

    case Response_E::RES_ERROR:
    default:
        std::cerr << "Error: server responded with error" << std::endl;
        break;
    }
}

// operation 110
bool Message::request_register(/* bool found_creds */)
{
    /////// File

    std::filesystem::path path(CREDS_FILE);
    if (std::filesystem::exists(path) /* && found_creds */)
    {
        std::cerr << path << " already exists" << std::endl;
        return false;
    }
    // std::ofstream out(path, std::ios::out | std::ios::trunc);

    // std::string username;
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

// operation 120
bool Message::request_list()
{
    req.header.code_type = Request_E::LIST_USERS;
    req.header.payload_length = 0;
    req.body = nullptr;

    return true;
}

// operation 130
bool Message::request_public_key()
{
    req.header.code_type = Request_E::REQ_PUB;
    req.header.payload_length = CLIENT_UUID_LENGTH;

    std::string username;
    std::cout << "enter username: ";
    std::cin >> username;

    auto id = users->getUid(username);
    if (id.at(0))
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

bool Message::request_send_message()
{
    req.header.code_type = Request_E::SND_MSG;
    // req.header.pa yload_length = CLIENT_UUID_LENGTH + sizeof(std::uint8_t) + 4 + MESSAGE_LENGTH
    return false;
}

// operation 110
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

// operation 120
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

// operation 130
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

void Message::response_messages()
{
    if (!res.header.payload_size)
    {
        std::cout << "No messages!" << std::endl;
        return;
    }

    struct __res_t
    {
        std::array<char, CLIENT_UUID_LENGTH> client_id;
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
        std::cout << "From: " << res_t.client_id.data() << '\n'
                  << "Content: ";
        switch (res_t.message_size)
        {
        case MessageType_E::REQ_SYM:
            std::cout << "Request for symmetric key\n";
            break;
        case MessageType_E::SND_SYM:
            std::cout << "Symmetric key received\n";
            std::array<char, SYMMETRIC_KEY_SIZE> sym_buf;
            boost::asio::read(s, boost::asio::buffer(sym_buf, SYMMETRIC_KEY_SIZE));
            users->setSymKey(res_t.client_id, sym_buf);
            break;
        case MessageType_E::SND_TXT:
        {
            std::array<char, MESSAGE_BUFFER_SIZE> buffer;
            unsigned cur_msg_bytes_read = 0;
            while (cur_msg_bytes_read < res_t.message_size)
            {
                bytes_read += boost::asio::read(s, boost::asio::buffer(buffer, buffer.size()));
                std::cout << buffer.data();
            }
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
