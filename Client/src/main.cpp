#include "Client.h"
#include "Message.h"

int main(void)
{

    Client c;
    auto server_endpoints = c.read_server_info();
    std::string host = server_endpoints.front();
    std::string port = server_endpoints.back();

    while (true)
    {
        int input_code = c.main_menu();
        if (!input_code)
        {
            return EXIT_SUCCESS;
        }

        try
        {
            /* establish socket connection */
            boost::asio::io_context io_context;
            tcp::resolver resolver(io_context);
            tcp::socket s(io_context);
            boost::asio::connect(s, resolver.resolve(host, port));
            std::cout << "Connecting to " << host << ":" << port << " ..." << std::endl;

            // TODO: Convert all the codes ints to Enums

            Message msg(s, c.getID(), c.getUsers(), c.getCipherSuite());

            if (msg.process_msg(input_code))
            {
                msg.send_message();
                msg.receive_message();
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << std::endl;
        }
    }
    return 0;
}
