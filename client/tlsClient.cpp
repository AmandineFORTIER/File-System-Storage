#include <botan-2/botan/tls_client.h>
#include <botan-2/botan/tls_callbacks.h>
#include <botan-2/botan/tls_session_manager.h>
#include <botan-2/botan/tls_policy.h>
#include <botan-2/botan/auto_rng.h>
#include <botan-2/botan/certstor.h>
#include <botan-2/botan/certstor_system.h>


#include "../Message.h"

#include <sstream>
#include <sys/socket.h> // For socket functions
#include <netinet/in.h> // For sockaddr_in
#include <cstdlib> // For exit() and EXIT_FAILURE
#include <unistd.h> // For read
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <cstring>
#include <termios.h>

#include <string>
#include <queue>

/**
 * @brief Callbacks invoked by TLS::Channel.
 *
 * Botan::TLS::Callbacks is an abstract class.
 * For improved readability, only the functions that are mandatory
 * to implement are listed here. See src/lib/tls/tls_callbacks.h.
 */
class Callbacks : public Botan::TLS::Callbacks
{
   public:
        Callbacks(int socket):socket(socket)
        {
            
        }
      void tls_emit_data(const uint8_t data[], size_t size) override
        {   
            if (!this->channel || !this->channel->is_active())
            {
                // Handshake in progress
                this->write_socket(data, size);
            }
            else
            {
                // Just collect the data and deal with it later in write_socket()
                this->pending_send.emplace(data, data + size);
            }
         
        }
        
      void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
         {
         // process full TLS record received by tls server, e.g.,
         // by passing it to the application
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         // handle a tls alert received from the tls server
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         // the session with the tls server was established
         // return false to prevent the session from being cached, true to
         // cache the session in the configured session manager
         return false;
         }
    private:
        std::unique_ptr<Botan::TLS::Channel> channel;
        int socket;
        std::queue<std::vector<uint8_t>> pending_send;
        ssize_t write_socket(const uint8_t* buffer, size_t size)
        {
            ssize_t bytes_written = send(this->socket, buffer, size, MSG_NOSIGNAL);
                
            if (bytes_written < 0)
            {
                std::cout << "tls_socket::write_socket: Error: " << std::strerror(errno) << std::endl;
            }

            return bytes_written;
        }
};

/**
 * @brief Credentials storage for the tls client.
 *
 * It returns a list of trusted CA certificates from a local directory.
 * TLS client authentication is disabled. See src/lib/tls/credentials_manager.h.
 */
class Client_Credentials : public Botan::Credentials_Manager
   {
   public:
      Client_Credentials()
        {
         // Here we base trust on the system managed trusted CA list
            try
            {
                const std::vector<std::string> paths =
                    {
                        "/etc/ssl/certs",
                        "/usr/share/ca-certificates",
                        "./certs"
                    };
                
                for (auto const& path : paths)
                {
                    auto cs = std::make_shared<Botan::Certificate_Store_In_Memory>(path);
                    this->m_stores.push_back(cs);
                }
            }
            catch (std::exception&)
            {
            }
        }

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
         const std::string& type,
         const std::string& context) override
         {
            std::vector<Botan::Certificate_Store*> v;
            
            // don't ask for client certs
            if (type == "tls-server")
            {
                return v;
            }
            
            for (auto const& cs : this->m_stores)
            {
                v.push_back(cs.get());
            }
            
            return v;
    }

   private:
        Botan::AutoSeeded_RNG rng;
        std::vector<std::shared_ptr<Botan::Certificate_Store>> m_stores;
};








std::string ask_username()
{
    std::string username;
    std::cout<<"Username: ";
    std::cin >> username;
    return username;
}

void ask_password(char password[72])
{
    std::cout<<"Password : ";

    /* ignore signals */
	//signal(SIGINT, SIG_IGN);
	//signal(SIGTERM, SIG_IGN);
    
	/* no echo */
	struct termios term;
	tcgetattr(1, &term);
	term.c_lflag &= ~ECHO;
	tcsetattr(1, TCSANOW, &term);


    //char pass[72];
    std::cin>>password;
    std::cin.clear();

    
	/* reset the term */
	term.c_lflag |= ECHO;
	tcsetattr(1, TCSANOW, &term);

    std::cin.clear();
    std::cout.clear();
    std::cout<<std::endl;

}


int connect_to_server()
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        std::cout << "Failed to create socket. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    sockaddr_in sockaddr; 
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(9999); // htons is necessary to convert a number to
    sockaddr.sin_addr.s_addr = INADDR_ANY;
                                    // network byte order

    if (connect(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0)
    {
        std::cout << "Failed to connect to port 9999. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

char read_from_connection(int sockfd)
{
    // Read from the connection
    char buffer[1024];
    read(sockfd, buffer, 1024);
    return buffer[0];
}





void send_user_connection(userMsg usr, int sockfd)
{
    std::stringstream ss;
    ss << usr;    //serialize
    write (sockfd, ss.str().c_str(), sizeof(usr)); 
    ss.clear();
}


void send_user_command(cmdMsg cmd, int sockfd)
{
    std::stringstream ss;
    ss << cmd;    //serialize
    write (sockfd, ss.str().c_str(), sizeof(cmd)); 
    ss.clear();
}


int main()
{
    bool BASIC_CLIENT_SERVER = true;
   
    
    sockaddr_in sockaddr; 
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(9999); // htons is necessary to convert a number to
    sockaddr.sin_addr.s_addr = INADDR_ANY;
                                    // network byte order
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        std::cout << "Failed to create socket. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0)
    {
        std::cout << "Failed to connect to port 9999. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }
    if(BASIC_CLIENT_SERVER)
    {
        // read data received from the tls server, e.g., using BSD sockets or boost asio
        // ...

        // send data to the tls server using client.send_data()

        int sockfd=connect_to_server();;
        std::string username;
        char pass[72];
        bool not_connected = false;
        std::string s;
        bool cmd_well_finished = false;
        do{
            std::cout <<" === Welcome to a file storage system ===\n"<<
                        "  To create an account write '""create""'\n"<<
                        "  To connect yourself write '""connect""'\n"<<
                        "  To quit write '""quit""'"<<std::endl;
            

            while (std::cin >> s)
            {
                if (std::strcmp(s.c_str(),"quit")==0)
                {
                    userMsg usr(s, username, pass);
                    send_user_connection(usr, sockfd);
                    close(sockfd);
                    exit(EXIT_SUCCESS);
                    break;
                }else if (std::strcmp(s.c_str(),"create")==0 || std::strcmp(s.c_str(),"connect")==0)
                {
                    break;
                }
                std::cin.clear();
            }
            
            username = ask_username();
            ask_password(pass);
            userMsg usr(s, username,pass);
            username.clear();

            send_user_connection(usr, sockfd);
            


            // if (not_connected = ((read_from_connection(sockfd) == '0')||(strcmp(s.c_str(),"create")==0)))
            // {
            //     std::cout<<"You're not connected."<<std::endl;
            // }

            cmd_well_finished = read_from_connection(sockfd) == '1';
            not_connected = std::strcmp(usr.get_cmd_request().c_str(),"create")==0;

            if (!cmd_well_finished)
            {
                if(std::strcmp(usr.get_cmd_request().c_str(),"create")==0)
                {
                    std::cout<<"Problem to create a user. Try again."<<std::endl;
                }else if(std::strcmp(usr.get_cmd_request().c_str(),"connect")==0)
                {
                    std::cout<<"Bad username or password. Try another username."<<std::endl;
                }else
                {
                    std::cout<<"Undefined error"<<std::endl;
                }
            }       

        }while(not_connected || !cmd_well_finished);


        std::cout <<" === Here are your commands as a connected user ===\n"<<
                "  To delete a file (or repo) write '""del""'\n"<<
                "  To download a file (or repo) write '""dl""'\n"<<
                "  To upload a file (or repo) write '""upload""'\n"<<
                "  To create a repo write '""create""'\n"<<
                "  To list all files/repo write '""ls""'\n"<<
                "  To quit write '""quit""'"<<std::endl;
        while (std::cin >> s)
        {
            if (s == "quit")
            {
                userMsg usr(s, username, pass);
                send_user_connection(usr, sockfd);
                close(sockfd);
                exit(EXIT_SUCCESS);
            }else{

                //Store file
                //Dl files
                //delete files
                //list files
                //files =  repo or files


                //un ls de tout les dossier ou le user est proprio ou a les droit ecriture ==> jsp quoi pour le droit de lecture

                // std::string path = "./files/";
                std::string path;

                if(std::strcmp(s.c_str(),"del")==0)
                {
                    std::cout<<"You're in the delete section"<<std::endl;
                    std::cout<<"Enter the directory name. e.g. path/myDirectory : ";
                    std::cin >> path;
                    cmdMsg msg(s,path);
                    send_user_command(msg,sockfd);
                // envoyer un msg sans user vu qu'il est co. Dans l'idee j'aimerais creer un vrai user et avec un setuid faire comme si c'etais lui qui fais les actions. 
                //le server utilisera execl PAS p

                }else if (std::strcmp(s.c_str(),"dl")==0)
                {
                    std::cout<<"You're in the download section"<<std::endl;
                    std::cout<<"Enter the directory name. e.g. path/myDirectory : ";
                    std::cin >> path;
                    cmdMsg msg(s,path);


                }else if (std::strcmp(s.c_str(),"upload")==0)
                {
                    std::cout<<"You're in the upload section"<<std::endl;

                    // std::filesystem::copy("./files/a", "./files/test", std::filesystem::copy_options::recursive);

                }else if (std::strcmp(s.c_str(),"create")==0)
                {
                    std::cout<<"You're in the create section"<<std::endl;
                    std::cout<<"Enter the directory name. e.g. path/myDirectory : ";
                    
                    std::cin >> path;
                    cmdMsg msg(s,path);



                    // std::cin >> param;

                    // std::string merge = path+param;

                    // const char* tmp[]={merge.c_str()};
                    // std::cout<<"path : "<<tmp<<std::endl;

                    // if(!mkdir(*tmp,S_IRWXU))
                    // {
                    //     std::cout<<"repo created"<<std::endl;
                    // }else
                    // {
                    //     std::cout<<"Error creation repo"<<std::endl;
                    // }
                    

                }
                std::cout<<read_from_connection(sockfd)<<std::endl;
        }


    }

        //close(sockfd);
    }else
    {
        // prepare all the parameters
        Callbacks callbacks(sockfd);
        Botan::TLS::Session_Manager_In_Memory session_mgr(Botan::system_rng());
        Client_Credentials creds;
        Botan::TLS::Strict_Policy policy;

        // open the tls connection
        Botan::TLS::Client client(callbacks,
                                    session_mgr,
                                    creds,
                                    policy,
                                    Botan::system_rng(),
                                    Botan::TLS::Server_Information("", 9999),
                                    Botan::TLS::Protocol_Version::TLS_V12);
    }
}