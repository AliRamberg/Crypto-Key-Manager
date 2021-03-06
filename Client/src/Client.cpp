#include "Client.h"

Client::Client()
{
    users = new UsersList();
    if (!std::filesystem::exists(CREDS_FILE))
    {
        cipher_suite = new Crypto();
        client_id.fill('\0');
    }
    else if (!read_creds())
    {
        throw std::runtime_error("invalid credentials file");
    }
    else
    {
        // valid creds file
        cipher_suite = new Crypto(encoded_private_key);
    }
}

bool Client::read_creds()
{
    // auto path = std::filesystem::path(CREDS_FILE);

    std::ifstream file(CREDS_FILE, std::ios::beg);
    std::string line;

    // Username
    std::getline(file, line);
    if (line.size() < 1)
    {
        return false;
    }
    username = line;
    // std::cout << "parse username: " << username << '\n';

    // ClientID
    std::getline(file, line);
    if (!std::all_of(line.begin(), line.end(), ::isxdigit) || line.size() != Client::UUID_HEX_LEN)
    {
        return false;
    }
    auto unhex = boost::algorithm::unhex(line);
    std::copy(unhex.begin(), unhex.end(), client_id.data());
    // std::cout << "parse client_id: " << unhex << '\n';
    std::copy(unhex.begin(), unhex.end(), client_id.data());

    // Private Key
    std::getline(file, line);

    encoded_private_key = line;
    // std::cout << "parse private_key: " << encoded_private_key << '\n';

    return true;
}

Client::~Client()
{
    delete users;
    delete cipher_suite;
}

int Client::main_menu()
{
    std::cout
        << "\n\nMessageU client at your service.\n\n"
        << "110) Register\n"
        << "120) Request for clients list\n"
        << "130) Request for public key\n"
        << "140) Request for waiting messages\n"
        << "150) Send a text message\n"
        << "151) Send a request for symmetric key\n"
        << "152) Send your symmetric key\n"
        << "0) Exit Client\n"
        << "? ";
    std::string input;
    std::cin >> input;

    if (std::all_of(input.begin(), input.end(), [](char c)
                    { return isdigit(c) == 0; }))
    {
        return -1;
    }

    int input_code = std::atoi(input.c_str());

    if (!input_code)
    {
        std::cout << "Closing client" << std::endl;
        return 0;
    }
    return input_code;
}

std::vector<std::string> Client::read_server_info()
{
    std::string host, port;

    std::string filename = "server.info"; // TODO: Change to std::filesystem?
    std::ifstream in(filename, std::ios::in);
    if (!in.is_open())
    {
        throw std::runtime_error(std::string("failed to open " + filename));
        // std::cout << "failed to open " << filename << '\n';
        // return {};
    }

    std::vector<std::string> args;
    std::string arg;
    std::string server_endpoint;
    in >> server_endpoint;

    std::stringstream ss(server_endpoint);

    std::string s;
    while (std::getline(ss, s, ':'))
    {
        args.push_back(s);
    }

    // TODO: ew, mabye std::pair cause it is destructible?
    // host = args.at(0);
    // port = args.at(1);
    in.close();
    return args;
}

UsersList *Client::getUsers()
{
    return users;
}

Crypto *Client::getCipherSuite()
{
    return cipher_suite;
}

std::array<char, CLIENT_UUID_LENGTH> Client::getID() const
{
    return client_id;
}

/* void Client::connect(const std::string &host, const std::string &port)
{
boost::asio::io_context io_context;
tcp::resolver resolver(io_context);
tcp::socket s(io_context);
boost::asio::connect(s, resolver.resolve(host, port));
}
*/
/*
Client::Client(boost::asio::io_context &io_context, const tcp::resolver::results_type &endpoint) : _io_context(io_context), _socket(io_context)
{
    connect(endpoint);
}

Client::~Client()
{
}

void Client::connect(const tcp::resolver::results_type &endpoint)
{
    boost::asio::connect(_socket, endpoint);
}

int Client::main_menu()
{
    std::cout
        << "MessageU client at your service.\n\n"
        << "110) Register\n"
        << "120) Request for clients list\n"
        << "130) Request for public key\n"
        << "140) Request for waiting messages\n"
        << "150) Send a text message\n"
        << "151) Send a request for symmetric key\n"
        << "152) Send your symmetric key\n"
        << "0) Exit Client\n"
        << ">>> ";

    int input_code;
    std::cin >> input_code;

    if (!input_code)
    {
        cleanup();
        return 0;
    }
    return input_code;
}

void Client::cleanup()
{
    std::cout << "Closing socket connection..." << std::endl;
    _socket.close();
}

void Client::read_response()
{
}

void Client::write_request(boost::asio::mutable_buffer &buf)
{
    // send msg
}

void Client::close()
{
    if (_socket.is_open())
    {
        _socket.close();
    }
} */