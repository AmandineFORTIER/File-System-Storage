#include <botan-2/botan/tls_client.h>
#include <botan-2/botan/tls_callbacks.h>
#include <botan-2/botan/tls_session_manager.h>
#include <botan-2/botan/tls_policy.h>
#include <botan-2/botan/auto_rng.h>
#include <botan-2/botan/certstor.h>
#include <botan-2/botan/certstor_system.h>
#include "../Message.hpp"
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
#include <fstream>      // std::ifstream
#include <zip.h>

// /**
//  * @brief Callbacks invoked by TLS::Channel.
//  *
//  * Botan::TLS::Callbacks is an abstract class.
//  * For improved readability, only the functions that are mandatory
//  * to implement are listed here. See src/lib/tls/tls_callbacks.h.
//  */
// class Callbacks : public Botan::TLS::Callbacks
// {
//    public:
//         Callbacks(int socket):socket(socket)
//         {
            
//         }
//       void tls_emit_data(const uint8_t data[], size_t size) override
//         {   
//             if (!this->channel || !this->channel->is_active())
//             {
//                 // Handshake in progress
//                 this->write_socket(data, size);
//             }
//             else
//             {
//                 // Just collect the data and deal with it later in write_socket()
//                 this->pending_send.emplace(data, data + size);
//             }
         
//         }
        
//       void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
//          {
//          // process full TLS record received by tls server, e.g.,
//          // by passing it to the application
//          }

//       void tls_alert(Botan::TLS::Alert alert) override
//          {
//          // handle a tls alert received from the tls server
//          }

//       bool tls_session_established(const Botan::TLS::Session& session) override
//          {
//          // the session with the tls server was established
//          // return false to prevent the session from being cached, true to
//          // cache the session in the configured session manager
//          return false;
//          }
//     private:
//         std::unique_ptr<Botan::TLS::Channel> channel;
//         int socket;
//         std::queue<std::vector<uint8_t>> pending_send;
//         ssize_t write_socket(const uint8_t* buffer, size_t size)
//         {
//             ssize_t bytes_written = send(this->socket, buffer, size, MSG_NOSIGNAL);
                
//             if (bytes_written < 0)
//             {
//                 std::cout << "tls_socket::write_socket: Error: " << std::strerror(errno) << std::endl;
//             }

//             return bytes_written;
//         }
// };

// /**
//  * @brief Credentials storage for the tls client.
//  *
//  * It returns a list of trusted CA certificates from a local directory.
//  * TLS client authentication is disabled. See src/lib/tls/credentials_manager.h.
//  */
// class Client_Credentials : public Botan::Credentials_Manager
//    {
//    public:
//       Client_Credentials()
//         {
//          // Here we base trust on the system managed trusted CA list
//             try
//             {
//                 const std::vector<std::string> paths =
//                     {
//                         "/etc/ssl/certs",
//                         "/usr/share/ca-certificates",
//                         "./certs"
//                     };
                
//                 for (auto const& path : paths)
//                 {
//                     auto cs = std::make_shared<Botan::Certificate_Store_In_Memory>(path);
//                     this->m_stores.push_back(cs);
//                 }
//             }
//             catch (std::exception&)
//             {
//             }
//         }

//       std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
//          const std::string& type,
//          const std::string& context) override
//          {
//             std::vector<Botan::Certificate_Store*> v;
            
//             // don't ask for client certs
//             if (type == "tls-server")
//             {
//                 return v;
//             }
            
//             for (auto const& cs : this->m_stores)
//             {
//                 v.push_back(cs.get());
//             }
            
//             return v;
//     }

//    private:
//         Botan::AutoSeeded_RNG rng;
//         std::vector<std::shared_ptr<Botan::Certificate_Store>> m_stores;
// };

std::string ask_username()
{
    std::string username;
    std::cout<<"Username: ";
    std::cin >> username;
    return username;
}
void checkPath(std::string &path)
{
    while(std::cin >> path)
    {
        if (path.at(0) == '.' || path.at(0) == '/' || path.find("..") != std::string::npos)
        {
            std::cout<<"Bad path. You cannot use / as a first indicator and you connot use . and .. and in your path."<<std::endl;;
        }else
        {
            break;
        }
    }
}

std::string itoa(int a)
{
    std::string ss="";   //create empty string
    while(a)
    {
        int x=a%10;
        a/=10;
        char i='0';
        i=i+x;
        ss=i+ss;      //append new character at the front of the string!
    }
    return ss;
}
void ask_password(char password[72])
{
    std::cout<<"Password : ";
    
	/* no echo */
	struct termios term;
	tcgetattr(1, &term);
	term.c_lflag &= ~ECHO;
	tcsetattr(1, TCSANOW, &term);

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

bool read_from_connection(int sockfd)
{
    char buffer[1024];
    memset(buffer,0,sizeof(buffer));
    read(sockfd, buffer, 1024);
    return buffer[0] == '1';
}

template <typename T>
void serialize_message(T& msg, int sockfd)
{
    std::stringstream ss;
    ss << msg;    //serialize
    write (sockfd, ss.str().c_str(), sizeof(msg)); 
    ss.clear();
}


int main()
{
    bool BASIC_CLIENT_SERVER = true;
   
    // fsync(sockfd);
    if(BASIC_CLIENT_SERVER)
    {
        int sockfd=connect_to_server();;
        std::string username;

        char pass[72];
        bool connected = false;
        std::string s;
        bool cmd_well_finished = false;
        bool authentified = false;

        do{
            cmd_well_finished = false;
            authentified = false;
            connected = false;
            std::cout <<" === Welcome to a file storage system ===\n"<<
                        "  To create an account write '""create""'\n"<<
                        "  To connect yourself write '""connect""'\n"<<
                        "  To quit write '""quit""'"<<std::endl;
            
            while (std::cin >> s)
            {
                if (std::strcmp(s.c_str(),"quit")==0)
                {
                    Message::userMsg usr(s, username, pass);
                    serialize_message<Message::userMsg>(usr,sockfd);
                    close(sockfd);
                    exit(EXIT_SUCCESS);
                }else if (std::strcmp(s.c_str(),"create")==0 || std::strcmp(s.c_str(),"connect")==0)
                {
                    break;
                }
                std::cin.clear();
            }
            
            username = ask_username();
            ask_password(pass);
            Message::userMsg usr(s, username,pass);
            serialize_message<Message::userMsg>(usr,sockfd);
            cmd_well_finished = read_from_connection(sockfd);

            connected = (std::strcmp(usr.get_cmd_request().c_str(),"connect")==0);

            if (connected && cmd_well_finished)
            {
                Message::cmdMsg msg("isAuth");
                serialize_message<Message::cmdMsg>(msg,sockfd);
                authentified = read_from_connection(sockfd);
            }
            
            if (!cmd_well_finished)
            {
                if(std::strcmp(usr.get_cmd_request().c_str(),"create")==0)
                {
                    std::cout<<"!! Problem to create a user. Try again. !!"<<std::endl;
                }else if(std::strcmp(usr.get_cmd_request().c_str(),"connect")==0)
                {
                    std::cout<<"!! Bad username or password. Try another username. !!"<<std::endl;
                }else
                {
                    std::cout<<"Undefined error"<<std::endl;
                }
            }else if (!authentified)
            {
                std::cout<<"!! Your account is not yet activate. Contact the administrator if you have any problem. !!"<<std::endl;
            }

        }while(!connected || !cmd_well_finished || !authentified);
        
        do{
            Message::cmdMsg msg("isAdmin");
            serialize_message<Message::cmdMsg>(msg,sockfd);
            bool is_admin = read_from_connection(sockfd);

            if (is_admin)
            {
                std::cout <<" === Here are your commands as a connected admin ===\n"<<
                    "  To delete a file (or repo) write '""del""'\n"<<
                    "  To download a file (or repo) write '""dl""'\n"<<
                    "  To upload a file (or repo) write '""upload""'\n"<<
                    "  To create a repo write '""create""'\n"<<
                    "  To list all files/repo write '""ls""'\n"<<
                    "  To activate a user account write '""activate""'\n"<<
                    "  To deactivate a user account write '""deactivate""'\n"<<
                    "  To give admin grade write '""admin""'\n"<<
                    "  To quit write '""quit""'"<<std::endl;
            }else
            {
                std::cout <<" === Here are your commands as a connected user ===\n"<<
                        "  To delete a file (or repo) write '""del""'\n"<<
                        "  To download a file (or repo) write '""dl""'\n"<<
                        "  To upload a file (or repo) write '""upload""'\n"<<
                        "  To create a repo write '""create""'\n"<<
                        "  To list all files/repo write '""ls""'\n"<<
                        "  To quit write '""quit""'"<<std::endl;
            }

            while (std::cin >> s)
            {
                if (strcmp(s.c_str(),"quit")==0)
                {
                    Message::cmdMsg usr(s);
                    serialize_message<Message::cmdMsg>(usr,sockfd);
                    close(sockfd);
                    exit(EXIT_SUCCESS);
                }else
                {
                    break;
                }
                
            }
            char buffer[1024];
            
            std::string path;
            if(std::strcmp(s.c_str(),"del")==0||std::strcmp(s.c_str(),"create")==0)
            {
                std::cout<<"Enter the directory name. e.g. path/myDirectory : ";
                checkPath(path);
                Message::cmdMsg msg(s,path);
                serialize_message<Message::cmdMsg>(msg,sockfd);

            // envoyer un msg sans user vu qu'il est co. Dans l'idee j'aimerais creer un vrai user et avec un setuid faire comme si c'etais lui qui fais les actions. 
            //le server utilisera execl PAS p

            }else if (std::strcmp(s.c_str(),"dl")==0)
            {
                std::cout<<"Enter the path of the file/repo you want to download. e.g. path/myDirectory : ";
                checkPath(path);
                Message::cmdMsg msg(s,path);
                serialize_message<Message::cmdMsg>(msg,sockfd);
                
                std::string fileName = "./files/"+path;
                FILE * readFile =  fopen(fileName.data(),"wb");
                char recvbuf[1024];
                memset(recvbuf,0,sizeof(recvbuf));
                int FileSize = 0;
                int error = recv(sockfd,recvbuf,1024,0);
                if (error == 0)
                {
                    std::cout<<"Error in receving FileSize "<<std::endl;
                    fclose(readFile);
                    close(sockfd);
                }
                
                FileSize = atoi(recvbuf);
                std::cout<<"Number of Bytes :"<<FileSize<<std::endl;
                
                char buffer[1024];
                int bytesReceived = 0;
                while(FileSize > 0)
                {
                    bytesReceived = 0;
                    memset(buffer,0,sizeof(buffer));
                    if(FileSize>1024)
                    {
                        bytesReceived = recv(sockfd, buffer, 1024, 0 );
                        fwrite(buffer, 1024, 1, readFile);
                    }
                    else
                    {
                        bytesReceived =recv( sockfd, buffer, FileSize, 0 );
                        buffer[FileSize]='\0';
                        fwrite(buffer, FileSize, 1, readFile);
                        send(sockfd,"END",strlen("END"),0);
                    }
                    FileSize -= 1024;
                }
                fclose(readFile);

            }else if (std::strcmp(s.c_str(),"upload")==0)
            {
                std::string pathDst;
                std::cout<<"Enter the path of the file/repo you want to upload. e.g. path/myDirectory : ";
                std::cin >> path;
                std::cout<<"Enter the path owhere you want to add your file/repo. e.g. path/myDirectory : ";
                checkPath(pathDst);
                Message::cmdMsg msg(s,path, pathDst);
                serialize_message<Message::cmdMsg>(msg,sockfd);
                
                std::string filepath = path;
                std::ifstream myFile(filepath, std::ios::in|std::ios::binary|std::ios::ate);
                int size = (int)myFile.tellg();
                myFile.close();
                FILE * readFile =  fopen(filepath.data(),"rb");
                if (readFile == NULL)
                {
                    std::cout<<"Unable to open File";
                    fclose(readFile);
                    close(sockfd);
                }
                std::cout<<"\nNumber of Bytes :"<<size<<std::endl;

                std::string FileSize = itoa(size).c_str();
                int fileSizeLength = FileSize.length();
                FileSize[fileSizeLength] = '\0';
                send(sockfd,FileSize.c_str(),fileSizeLength,0);
                double origin_size = size;
                char buffer[1024];
                int pourc;
                int bytesReceived = 0;
                int test = 0;
                int last_pourc = 0;
                while(size > 0)
                {
                    bytesReceived = 0;
                    memset(buffer,0,sizeof(buffer));
                        if(size>1024)
                        {
                            fread(buffer, 1024, 1, readFile);
                            bytesReceived = send( sockfd, buffer, 1024, 0 );
                        }
                        else
                        {
                            fread(buffer, size, 1, readFile);
                            buffer[size]='\0';
                            bytesReceived = send( sockfd, buffer, size, 0 );
                        }
                    test+=bytesReceived;
                     size -= 1024;
                     pourc = (test/origin_size)*100;
                     
                     if (pourc != last_pourc && pourc%10 == 0)
                     {
                        std::cout<<pourc<<std::endl;
                        last_pourc = pourc;
                     }                    
                }
                char recev[10];
                memset(recev,0,sizeof(recev));
                read(sockfd,recev,strlen("END"));
                if(strcmp(recev,"END")== 0)
                {
                    std::cout<<"END received"<<std::endl;
                }
                memset(recev,0,sizeof(recev));
                fclose(readFile);

            }else if (std::strcmp(s.c_str(),"ls")==0)
            {
                Message::cmdMsg msg(s);
                serialize_message<Message::cmdMsg>(msg,sockfd);

                std::cout<<"=============Files listing============="<<std::endl;;
                read(sockfd, buffer, 1024);
                std::cout<<buffer<<std::endl;
                memset(buffer,0,sizeof(buffer));
                std::cout<<"======================================="<<std::endl;;
            }

            if (is_admin)
            {
                if(std::strcmp(s.c_str(),"admin")==0||std::strcmp(s.c_str(),"activate")==0||std::strcmp(s.c_str(),"deactivate")==0)
                {
                    std::cout<<"======================User list======================"<<std::endl;
                    Message::cmdMsg msgList("list_user");
                    serialize_message<Message::cmdMsg>(msgList,sockfd);

                    read(sockfd, buffer, 1024);
                    std::cout<<buffer<<std::endl;
                    memset(buffer,0,sizeof(buffer));
                    std::cout<<"====================================================="<<std::endl;

                    std::cout<<"Enter the concerned user. e.g. abs : ";
                    std::cin >> path;
                    Message::cmdMsg msg(s,path);
                    serialize_message<Message::cmdMsg>(msg,sockfd);
                }
            } 
        }while(1);
        //close(sockfd);
    }else
    {
        // // prepare all the parameters
        // Callbacks callbacks(sockfd);
        // Botan::TLS::Session_Manager_In_Memory session_mgr(Botan::system_rng());
        // Client_Credentials creds;
        // Botan::TLS::Strict_Policy policy;

        // // open the tls connection
        // Botan::TLS::Client client(callbacks,
        //                             session_mgr,
        //                             creds,
        //                             policy,
        //                             Botan::system_rng(),
        //                             Botan::TLS::Server_Information("", 9999),
        //                             Botan::TLS::Protocol_Version::TLS_V12);
    }
}