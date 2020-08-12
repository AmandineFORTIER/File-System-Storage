// #include <iostream> // For cout

#include <memory>

#include <sqlite3.h>

#include "../Message.h"
#include <sstream>

#include <arpa/inet.h>
#include <sys/socket.h> // For socket functions
#include <netinet/in.h> // For sockaddr_in
#include <cstdlib> // For exit() and EXIT_FAILURE
#include <iostream> // For cout
#include <unistd.h> // For read
#include <errno.h>
#include <cstring>
#include <thread>

#include <unistd.h>

#include <sys/wait.h>
#include <filesystem>

#include <botan-2/botan/bcrypt.h>
#include <botan-2/botan/botan.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#include <cstdlib>
#include <iostream>

bool BASIC_CLIENT_SERVER = true;


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
//       void tls_emit_data(const uint8_t data[], size_t size) override
//          {
//          // send data to tls client, e.g., using BSD sockets or boost asio
//          }

//       void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
//          {
//          // process full TLS record received by tls client, e.g.,
//          // by passing it to the application
//          }

//       void tls_alert(Botan::TLS::Alert alert) override
//          {
//          // handle a tls alert received from the tls server
//          }

//       bool tls_session_established(const Botan::TLS::Session& session) override
//          {
//          // the session with the tls client was established
//          // return false to prevent the session from being cached, true to
//          // cache the session in the configured session manager
//          return false;
//          }
//     std::unique_ptr<Botan::TLS::Channel> channel;
// };

// /**
//  * @brief Credentials storage for the tls server.
//  *
//  * It returns a certificate and the associated private key to
//  * authenticate the tls server to the client.
//  * TLS client authentication is not requested.
//  * See src/lib/tls/credentials_manager.h.
//  */

// class Server_Credentials : public Botan::Credentials_Manager
// {
//    public:
//       Server_Credentials()// : m_key(Botan::PKCS8::load_key("botan.randombit.net.key"))
//          {
//          }
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
            
//             for (auto const& cs : this->certstores)
//             {
//                 v.push_back(cs.get());
//             }
            
//             return v;
//          }

//       std::vector<Botan::X509_Certificate> cert_chain(
//          const std::vector<std::string>& cert_key_types,
//          const std::string& type,
//          const std::string& context) override
//          {
//             BOTAN_UNUSED(type);
            
//             for (auto const& i : this->creds)
//             {
//                 if (std::find(cert_key_types.begin(), cert_key_types.end(), i.key->algo_name()) == cert_key_types.end())
//                 {
//                     continue;
//                 }
                
//                 if (context != "" && !i.certs[0].matches_dns_name(context))
//                 {
//                     continue;
//                 }
                
//                 return i.certs;
//             }
            
//             return std::vector<Botan::X509_Certificate>();
//          }

//       Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
//          const std::string& type,
//          const std::string& context) override
//          {
//             for (auto const& i : this->creds)
//             {
//                 if (cert == i.certs[0])
//                 {
//                     return i.key.get();
//                 }
//             }
            
//             return nullptr;
//          }

//       private:
//         Botan::AutoSeeded_RNG rng;
//         std::vector<std::shared_ptr<Botan::Certificate_Store>> certstores;
//         struct certificate_info
//         {
//             std::vector<Botan::X509_Certificate> certs;
//             std::shared_ptr<Botan::Private_Key> key;
//         };
//         std::vector<certificate_info> creds;
// };

// Botan::X509_Certificate create_certificate()
// {
//    uint32_t expire_time = 60*60*24*90; //days of validity in seconds ==> 90 days
//    Botan::X509_Cert_Options opt("server/Belgium",expire_time);

//    Botan::AutoSeeded_RNG rng;
//    Botan::RSA_PrivateKey pKey(rng,4096);
//    Botan::X509_Certificate cert = Botan::X509::create_self_signed_cert(opt,pKey,"SHA-256",rng);

//    return cert;
// }



void threadClient(sockaddr_in sockaddr,int connection)
{
    /*
    // Send a message to the connection
    std::string response = "Good talking to you\n";
    write(connection, response.c_str(), response.size());

    // Read from the connection
    char buffer[100];
    while (read(connection, buffer, 100)>0)
    {
        std::cout << "The message was: " << buffer;
    }
    */
    bool quit = false;
    char t[72]{};
    std::string cmd;
    std::string user;
    userMsg usr(cmd,user,t);
    std::stringstream ss;
    char buffer[sizeof(usr)];
    std::string temp;
    bool connected = false;
    do
    {
        cmd.clear();
        user.clear();
        ss.clear();
        memset(buffer, 0, sizeof(usr));
        temp.clear();
        read(connection, buffer, sizeof(usr));  //receive
        temp.assign(buffer); 
        ss << temp;
        ss >> usr;   //unserialize

        memset(buffer, 0, sizeof(usr));
        ss.clear();


        // std::cout<<usr.get_cmd_request()<<std::endl;
        // std::cout<<usr.get_username()<<std::endl;
        // std::cout<<usr.get_password()<<std::endl;

        

        bool well_terminated = false;
        if ((strcmp(usr.get_cmd_request().c_str(),"quit")==0))
        {
            break;
        }
        
        
        if (strcmp(usr.get_cmd_request().c_str(),"create")==0)
        {
            Botan::AutoSeeded_RNG rng;
            auto hash = Botan::generate_bcrypt(usr.get_password(), rng, 12);            
            
            sqlite3 *db;
            sqlite3_stmt* stmt;
            char *zErrMsg = 0;
            int rc = sqlite3_open("../database/users.db",&db);
            if (rc != SQLITE_OK) 
            {
                fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }

            char sql[] = "INSERT INTO user(username, password, grade, isAuthenticated) VALUES (?, ?, ?, ?)";
            rc = sqlite3_prepare_v2(db,sql,-1, &stmt,0);
            if (rc != SQLITE_OK) 
            {
                fprintf(stderr, "Can't prepare select statment %s (%i): %s\n", sql, rc, sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
            std::string grade = "User";
            rc = sqlite3_bind_blob(stmt, 1, usr.get_username().c_str() ,usr.get_username().length(),NULL);
            if(rc != SQLITE_OK) 
            {
                fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }

            rc = sqlite3_bind_blob(stmt, 2, hash.c_str() ,hash.length(),NULL);
            if(rc != SQLITE_OK) 
            {
                fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }

            rc = sqlite3_bind_text(stmt, 3, grade.c_str() ,sizeof(grade),NULL);
            if(rc != SQLITE_OK) 
            {
                fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
            int isAuthenticated = 0;
            rc = sqlite3_bind_int(stmt, 4, isAuthenticated);
            if(rc != SQLITE_OK) 
            {
                fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
            
            rc = sqlite3_step(stmt);
            if(rc != SQLITE_DONE) 
            {
                fprintf(stderr, "insert statement didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
            } else {
                printf("INSERT completed\n\n");
                well_terminated=true;
            }

            rc = sqlite3_clear_bindings(stmt);
            if(rc != SQLITE_OK) 
            {
                fprintf(stderr, "clear bindings didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
            }

            rc = sqlite3_reset(stmt);
            if(rc != SQLITE_OK) 
            {
                fprintf(stderr, "reset didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
            }

            rc = sqlite3_finalize(stmt);
            if(rc != SQLITE_OK) 
            {
                fprintf(stderr, "finalize didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
            }

            rc = sqlite3_close(db);
            if(rc != SQLITE_OK) 
            {
                fprintf(stderr, "close didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
            }

            //creation du user unix execl pas p
            // std::string group = (strcmp(grade.c_str(),"User")==0)?"FileStorageUser":"FileStorageAdmin";

            // if(fork()==0)
            // {
            //     if(fork()==0)
            //     {
            //         execl("/usr/sbin/groupadd","groupadd",group.c_str(),0);
            //         perror("groupadd error");
            //         exit(0);
            //     }else
            //     {
            //         exit(0);
            //     }
            //     std::cout<<"add"<<std::endl;

            //     if(fork()==0)
            //     {
            //         execl("/usr/sbin/useradd","useradd","-g",group,usr.get_username().c_str(),0);
            //         perror("useradd error");
            //         exit(0);
            //     }else
            //     {
            //         exit(0);
            //     }

            //     if(fork()==0)
            //     {
            //         execl("/usr/bin/passwd",group.c_str(),usr.get_username().c_str(),0);
            //         perror("passwd error");
            //         exit(0);
            //     }else
            //     {
            //         exit(0);
            //     }
            // }
            // wait(0);



            // Send a message to the connection.
            std::string reponse = well_terminated?"1":"0"; 
            write(connection, reponse.c_str(), reponse.length());

        }else if(strcmp(usr.get_cmd_request().c_str(),"connect")==0)
        {
            sqlite3 *db;
            sqlite3_stmt* stmt;
            char *zErrMsg = 0;
            int rc = sqlite3_open("../database/users.db",&db);
            if (rc != SQLITE_OK) 
            {
                fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }

            char sql[] = "SELECT username, password FROM user WHERE username = ?";
            rc = sqlite3_prepare_v2(db,sql,-1, &stmt,0);
            if (rc != SQLITE_OK) 
            {
                fprintf(stderr, "Can't prepare select statment %s (%i): %s\n", sql, rc, sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
            rc = sqlite3_bind_blob(stmt, 1, usr.get_username().c_str(),usr.get_username().length(),NULL);
            if(rc != SQLITE_OK) {
                fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }

            std::string username="";

            if ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) 
            {
                const unsigned char* name = sqlite3_column_text(stmt, 0);
                const std::string temp_name = reinterpret_cast<const char *>(name);
                username = temp_name;
                auto hash = sqlite3_column_text(stmt, 1);
                const std::string h = reinterpret_cast<const char*>(hash);
                well_terminated=Botan::check_bcrypt(usr.get_password(),h);
            }
            
            rc = sqlite3_clear_bindings(stmt);
            if(rc != SQLITE_OK) {
                fprintf(stderr, "clear bindings didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
            }

            rc = sqlite3_reset(stmt);
            if(rc != SQLITE_OK) {
                fprintf(stderr, "reset didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
            }

            rc = sqlite3_finalize(stmt);
            if(rc != SQLITE_OK) {
                fprintf(stderr, "finalize didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
            }

            rc = sqlite3_close(db);
            if(rc != SQLITE_OK) {
                fprintf(stderr, "close didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
            }

            // Send a message to the connection.
            std::string reponse = well_terminated?"1":"0"; 
            write(connection, reponse.c_str(), reponse.length());
            connected = well_terminated;
        }
        
    } while (!connected);

    if (connected)
    {
        std::string com="";
        cmdMsg connected_cmd(com);
        std::stringstream ss;
        char buffer[sizeof(connected_cmd)];
        std::string tempp;

        read(connection, buffer, sizeof(connected_cmd));  //receive
        tempp.assign(buffer); 
        ss << tempp;
        ss >> connected_cmd;   //unserialize

        memset(buffer, 0, sizeof(connected_cmd));
        ss.clear();


        std::cout<<connected_cmd.get_cmd_request().c_str()<<std::endl;
        
        if (strcmp(connected_cmd.get_cmd_request().c_str(),"quit")==0)
        {
            
        }else{

            //Store file
            //Dl files
            //delete files
            //files =  repo or files


            //un ls de tout les dossier ou le user est proprio ou a les droit ecriture ==> jsp quoi pour le droit de lecture

            std::string path = connected_cmd.get_pathSrc();
            std::string origin_path = "./files/";
            std::string tmp(origin_path+path);

            if(std::strcmp(connected_cmd.get_cmd_request().c_str(),"del")==0)
            {
                std::cout<<"You're in the delete section"<<std::endl;
                std::cout<<"Enter the directory name. e.g. path/myDirectory : ";

                std::filesystem::remove_all(tmp.c_str());
            }else if (std::strcmp(connected_cmd.get_cmd_request().c_str(),"create")==0)
            {
                std::filesystem::create_directories(tmp);
                std::filesystem::permissions(tmp, std::filesystem::perms::all, std::filesystem::perm_options::replace);
                
                // if(!mkdir(tmp.c_str(),0777))
                // {
                //     std::cout<<"repo created"<<std::endl;
                // }else
                // {
                //     std::cout<<"Error creation repo"<<std::endl;
                // }
            }else if (std::strcmp(connected_cmd.get_cmd_request().c_str(),"dl")==0)
            {
                /* code */
            }else if (std::strcmp(connected_cmd.get_cmd_request().c_str(),"upload")==0)
            {
                /* code */
            }else if (std::strcmp(connected_cmd.get_cmd_request().c_str(),"ls")==0)
            {
                std::string ls_output;
                for (const auto & entry : std::filesystem::recursive_directory_iterator(tmp))
                {
                    ls_output += entry.path().c_str();
                    ls_output +="\n";
                }
                // fdatasync(connection);
                write(connection, ls_output.c_str(), ls_output.length());

                
            }
            
        }
        




    }
    

    std::cout<<"Disconnected"<<std::endl;
    close(connection);

}

void command(int sockfd)
{
    std::string s;
    while (std::cin >> s)
    {
        if (s == "quit")
        {
            close(sockfd);
            exit(EXIT_FAILURE);
        }
    }
}


int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;    //https://stackoverflow.com/a/21099172  https://www.gta.ufrj.br/ensino/eel878/sockets/sockaddr_inman.html


    // Listen to port on any address
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);    // htons is necessary to convert a number to network byte number
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    


    s = socket(AF_INET, SOCK_STREAM, 0);//man socket(2)
    //AF_INET (IPv4 protocol) , AF_INET6 (IPv6 protocol)
    //SOCK_STREAM: TCP(reliable, connection oriented) SOCK_DGRAM: UDP(unreliable, connectionless)
    //Protocol value for Internet Protocol(IP), which is 0. This is the same number which appears on protocol field in the IP header of a packet.(man protocols for more details)

    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    // https://linux.die.net/man/3/setsockopt
        /* Enable the socket to reuse the address */
        /*
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockaddr, sizeof(sockaddr)) == -1) 
        {
            perror("setsockopt");
            return 1;
        }
        */

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 10) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }


    return s;
}

int main()
{
    int sockfd;
    if (BASIC_CLIENT_SERVER)
    {
        // Create a socket (IPv4, TCP)
        int sockfd = socket(AF_INET, SOCK_STREAM, 0); //man socket(2)
        //AF_INET (IPv4 protocol) , AF_INET6 (IPv6 protocol)
        //SOCK_STREAM: TCP(reliable, connection oriented) SOCK_DGRAM: UDP(unreliable, connectionless)
        //Protocol value for Internet Protocol(IP), which is 0. This is the same number which appears on protocol field in the IP header of a packet.(man protocols for more details)
        if (sockfd < 0)
        {
        std::cout << "Failed to create socket. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
        }

        std::thread com(command, sockfd);
        com.detach();

        // Listen to port 9999 on any address
        sockaddr_in sockaddr;                     //https://stackoverflow.com/a/21099172  https://www.gta.ufrj.br/ensino/eel878/sockets/sockaddr_inman.html
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port = htons(9999); // htons is necessary to convert a number to
        sockaddr.sin_addr.s_addr = INADDR_ANY;
                                        // network byte order

        // https://linux.die.net/man/3/setsockopt
        /* Enable the socket to reuse the address */
        /*
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockaddr, sizeof(sockaddr)) == -1) 
        {
            perror("setsockopt");
            return 1;
        }
        */
        if (bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0)
        {
            std::cout << "Failed to bind to port 9999. errno: " << errno << std::endl;
            exit(EXIT_FAILURE);
        }

        // Start listening. Hold at most 10 connections in the queue
        if (listen(sockfd, 10) < 0)
        {
            std::cout << "Failed to listen on socket. errno: " << errno << std::endl;
            exit(EXIT_FAILURE);
        }

        while (1)
        {
            // Grab a connection from the queue
            auto addrlen = sizeof(sockaddr);
            int connection = accept(sockfd, (struct sockaddr*)&sockaddr, (socklen_t*)&addrlen); //https://linux.die.net/man/3/accept
            if (connection < 0) 
            {
                close(connection);
                exit(EXIT_FAILURE);
            }
            // fsync(connection);


            std::thread test(threadClient,sockaddr,connection);
            test.detach();
        }
    
    }else
    {
        // //Botan::X509_Certificate cert =  create_certificate();
        // //std::cout<<cert.to_string()<<std::endl;

        // // prepare all the parameters
        // Callbacks callbacks;
        // Botan::AutoSeeded_RNG rng;
        // Botan::TLS::Session_Manager_In_Memory session_mgr(rng);

        // std::string hostname = "localhost";
        // uint16_t port = 9999;
        // Botan::TLS::Server_Information server_info(hostname, port);
        // Botan::TLS::Session sess;
        // session_mgr.load_from_server_info(server_info,sess);

        // Server_Credentials creds;
        // Botan::TLS::Strict_Policy policy;

        // sockfd =  create_socket(999);

        // // read data received from the tls client, e.g., using BSD sockets or boost asio
        // // and pass it to server.received_data().
        // // ...

        // // send data to the tls client using server.send_data()
        // // ...



        //     // accept tls connection from client
        // Botan::TLS::Server server(callbacks,
        //                         session_mgr,
        //                         creds,
        //                         policy,
        //                         rng);



        // fd_set writefds;
        // FD_ZERO(&writefds);
        // while(!server.is_closed())
        // {
        //     fd_set readfds;
        //     FD_ZERO(&readfds);
        //     FD_ZERO(&writefds);
        //     FD_SET(sockfd, &readfds);
        //     if (server.is_active())
        //     {
        //         FD_SET(STDIN_FILENO, &readfds);
        //     }

        //     FD_SET(sockfd, &writefds);


        //     select(sockfd + 1, &readfds, &writefds, nullptr, nullptr);

        //     if (server.is_closed())
        //     {
        //         // TODO: Do something better (e.g. throw or log)
        //         std::cout << "server_tls_socket::send_receive: Socket closed." << std::endl;
        //     }

        //     try
        //     {
        //        uint8_t buffer[4 * 1024] = {0};
        //         ssize_t bytes_read = read(sockfd, buffer, sizeof(buffer));

        //         if (bytes_read == -1)
        //         {
        //             // TODO: Do something better (e.g. throw or log)
        //             std::cout << "tls_socket::read_socket: Error: " << std::strerror(errno) << std::endl;
        //         }
        //         else if (bytes_read == 0)
        //         {
        //             // TODO: Do something better (e.g. throw or log)
        //             std::cout << "tls_socket::read_socket: Other end closed the connection" << std::endl;
        //             callbacks.channel.get()->close();
        //         }
        //         else if (bytes_read > 0)
        //         {
        //             callbacks.channel.get()->received_data(buffer, bytes_read);
        //         }
        //     }
        //     catch (std::exception& e)
        //     {
        //         // TODO: Do something better (e.g. throw or log)
        //         std::cout << "server_tls_socket::send_receive: Error: " << e.what() << std::endl;
        //     }

        // }    
    }

}