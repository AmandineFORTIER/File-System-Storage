#include <memory>
#include <sqlite3.h>
#include "../Message.hpp"
#include "../Utils.hpp"
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
#include <sys/sendfile.h>
#include <fcntl.h>
#include <fstream>      // std::ifstream
#include <stdlib.h>

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

bool BASIC_CLIENT_SERVER = true;
//def port number, nb max connection, ...

void finalize_query(sqlite3_stmt* stmt, sqlite3 *db)
{
    int rc = sqlite3_clear_bindings(stmt);
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
}

void client_command(sockaddr_in sockaddr,int connection)
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


    bool quit = false;
    bool connected = false;
    bool authentified = false;
    char pass[72]{};
    Message::userMsg usr("","",pass);
    do
    {
        Utils::unserialize_message<Message::userMsg>(usr,connection);
       
        bool well_terminated = false;
        if ((strcmp(usr.get_cmd_request().c_str(),"quit")==0))
        {
            break;
        }else if (strcmp(usr.get_cmd_request().c_str(),"create")==0)
        {
            Botan::AutoSeeded_RNG rng;
            auto hash = Botan::generate_bcrypt(usr.get_password(), rng, 12);            
            
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
                well_terminated=true;
            }

            finalize_query(stmt,db);
            std::string reponse = well_terminated?"1":"0"; 
            write(connection, reponse.c_str(), reponse.length());

        }else if(strcmp(usr.get_cmd_request().c_str(),"connect")==0)
        {
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
            
           finalize_query(stmt, db);
            std::string reponse = well_terminated?"1":"0"; 
            write(connection, reponse.c_str(), reponse.length());
            connected = well_terminated;
        }
        if (connected)
        {
            Message::cmdMsg connected_cmd(" ");
            Utils::unserialize_message<Message::cmdMsg>(connected_cmd,connection);

            if(strcmp(connected_cmd.get_cmd_request().c_str(),"isAuth")==0)
            {


                char sql[] = "SELECT isAuthenticated FROM user WHERE username = ?";
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

                    const char* isAuth="";
                    if ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) 
                    {
                        const unsigned char* auth = sqlite3_column_text(stmt, 0);
                        const std::string temp_auth = reinterpret_cast<const char *>(auth);
                        isAuth = temp_auth.c_str();
                    }
                    
                    finalize_query(stmt, db);
                    authentified = strcmp(isAuth,"1")==0;
                    write(connection, isAuth, sizeof(isAuth));
            }
        }
    } while (!connected || !authentified);

    if (connected)
    {
        Message::cmdMsg connected_cmd("");
        do
        {   
            Utils::unserialize_message<Message::cmdMsg>(connected_cmd,connection);

            std::string path = connected_cmd.get_param1();
            std::string origin_path = "./files/";
            std::string tmp(origin_path+path);

            if (strcmp(connected_cmd.get_cmd_request().c_str(),"quit")==0)
            {
                break;
            }else if(strcmp(connected_cmd.get_cmd_request().c_str(),"isAdmin")==0)
            {
                char sql[] = "SELECT grade FROM user WHERE username = ?";
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

                const char* isAdmin="";
                if ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) 
                {
                    const unsigned char* grade = sqlite3_column_text(stmt, 0);
                    const std::string temp_grade = reinterpret_cast<const char *>(grade);
                    isAdmin = (strcmp(temp_grade.c_str(),"Admin")==0)?"1":"0";
                }
                
                finalize_query(stmt, db);
                write(connection, isAdmin, sizeof(isAdmin));
            }else if(strcmp(connected_cmd.get_cmd_request().c_str(),"list_user")==0)
            {
                char sql[] = "SELECT username, grade, isAuthenticated FROM user";
                rc = sqlite3_prepare_v2(db,sql,-1, &stmt,0);
                if (rc != SQLITE_OK) 
                {
                    fprintf(stderr, "Can't prepare select statment %s (%i): %s\n", sql, rc, sqlite3_errmsg(db));
                    sqlite3_close(db);
                    exit(1);
                }
            
                std::string answer = "Username\tGrade \t is authenticated ?\n------------------------------------------------\n";
                while(sqlite3_step(stmt) == SQLITE_ROW) 
                {
                    int column = sqlite3_column_count(stmt);

                    for(int i = 0; i < column; i++)
                    {
                        answer += (std::string((const char *) sqlite3_column_text(stmt, i))) + "\t\t";
                    }
                    answer+="\n";
                }

               finalize_query(stmt, db);
                write(connection, answer.c_str(), answer.length());
            }else if(std::strcmp(connected_cmd.get_cmd_request().c_str(),"activate")==0||std::strcmp(connected_cmd.get_cmd_request().c_str(),"deactivate")==0)
            {
                int val = (std::strcmp(connected_cmd.get_cmd_request().c_str(),"activate")==0);
                char sql[] = "UPDATE user SET isAuthenticated = ? WHERE username = ?";
                rc = sqlite3_prepare_v2(db,sql,-1, &stmt,0);
                if (rc != SQLITE_OK) 
                {
                    fprintf(stderr, "Can't prepare select statment %s (%i): %s\n", sql, rc, sqlite3_errmsg(db));
                    sqlite3_close(db);
                    exit(1);
                }
                rc = sqlite3_bind_int(stmt, 1, val);
                if(rc != SQLITE_OK) {
                    fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
                    sqlite3_close(db);
                    exit(1);
                }
                rc = sqlite3_bind_blob(stmt, 2, connected_cmd.get_param1().c_str(),connected_cmd.get_param1().length(),NULL);
                if(rc != SQLITE_OK) {
                    fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
                    sqlite3_close(db);
                    exit(1);
                }
                
                rc = sqlite3_step(stmt);
                if(rc != SQLITE_DONE) 
                {
                    fprintf(stderr, "update statement didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
                }
                finalize_query(stmt, db);

            }else if(std::strcmp(connected_cmd.get_cmd_request().c_str(),"admin")==0)
            {
                char sql[] = "UPDATE user SET grade = 'Admin' WHERE username = ?";
                rc = sqlite3_prepare_v2(db,sql,-1, &stmt,0);
                if (rc != SQLITE_OK) 
                {
                    fprintf(stderr, "Can't prepare select statment %s (%i): %s\n", sql, rc, sqlite3_errmsg(db));
                    sqlite3_close(db);
                    exit(1);
                }
                rc = sqlite3_bind_blob(stmt, 1, connected_cmd.get_param1().c_str(),connected_cmd.get_param1().length(),NULL);
                if(rc != SQLITE_OK) {
                    fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
                    sqlite3_close(db);
                    exit(1);
                }
                
                rc = sqlite3_step(stmt);
                if(rc != SQLITE_DONE) 
                {
                    fprintf(stderr, "update statement didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
                }

                finalize_query(stmt, db);

            }else if(std::strcmp(connected_cmd.get_cmd_request().c_str(),"del")==0)
            {
                std::filesystem::remove_all(tmp.c_str());
            }else if (std::strcmp(connected_cmd.get_cmd_request().c_str(),"create")==0)
            {
                std::filesystem::create_directories(tmp);
                std::filesystem::permissions(tmp, std::filesystem::perms::all, std::filesystem::perm_options::add);

            }else if (std::strcmp(connected_cmd.get_cmd_request().c_str(),"dl")==0)
            {
                std::string path = "./files/"+connected_cmd.get_param1();
                Utils::check_path_exists(path);
                Utils::recursive_send(path,connection);
            }else if (std::strcmp(connected_cmd.get_cmd_request().c_str(),"upload")==0)
            {
                Message::unixFile file(std::filesystem::path(""),false,0);
                do
                {
                        Utils::unserialize_message<Message::unixFile>(file,connection);
                        if (file.get_size() == 0)
                        {
                            break;
                        }
                    
                        if (file.get_is_dir())
                        {
                            std::string path = "./files/"+connected_cmd.get_param2()+"/"+file.get_path().generic_string();
                            std::filesystem::create_directories(path);
                            try{
                                std::filesystem::permissions(path, std::filesystem::perms::all, std::filesystem::perm_options::add);
                            }catch(...)
                            {
                                std::cout<<"An error occuried."<<std::endl;
                                break;
                            }
                        }else
                        {
                            std::string fileName = "./files/"+connected_cmd.get_param2()+"/"+file.get_path().generic_string();
                            FILE * readFile =  fopen(fileName.data(),"wb");
                            try{
                            std::filesystem::permissions(fileName, std::filesystem::perms::all, std::filesystem::perm_options::add);
                            }catch(...)
                            {
                                std::cout<<"An error occuried."<<std::endl;
                                break;
                            }
                            int FileSize = file.get_size();
                            int buffSize = 1024;
                            if (FileSize < 1024)
                            {
                                buffSize=FileSize;
                            }
                            
                            char recvbuf[buffSize];
                            memset(recvbuf,0,buffSize);
                            int error = recv(connection,recvbuf,buffSize,0);
                            if (error == 0)
                            {
                                std::cout<<"Error in receving FileSize "<<std::endl;
                                break;
                            }
                            else
                            {
                                char buffer[buffSize];
                                int bytesReceived = 0;
                                
                                while(FileSize > 0)
                                {
                                    
                                    bytesReceived = 0;
                                    memset(buffer,0,buffSize);
                                    if(FileSize>1024)
                                    {
                                        bytesReceived = recv(connection, buffer, 1024, 0 );
                                        fwrite(buffer, 1024, 1, readFile);
                                    }
                                    else
                                    {
                                        bytesReceived =recv(connection, buffer, FileSize, 0 );
                                        buffer[FileSize]='\0';
                                        fwrite(buffer, FileSize, 1, readFile);
                                        send(connection,"END",strlen("END"),0);
                                    }
                                    FileSize -= 1024;
                                }
                                
                            }
                            fclose(readFile);
                        }
                    }while(file.get_size() != 0);   
             
            }else if (std::strcmp(connected_cmd.get_cmd_request().c_str(),"ls")==0)
            {
                std::string ls_output="";
                for (const auto & entry : std::filesystem::recursive_directory_iterator(origin_path))
                {
                    ls_output += entry.path().c_str()+origin_path.length();
                    ls_output +="\n";
                }
                // fdatasync(connection);
                write(connection, ls_output.c_str(), ls_output.length()-1);
                ls_output.clear();
            }else
            {
                break;
            }
            
                
        } while (1);
    }
    
    rc = sqlite3_close(db);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "close didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
    }

    std::cout<<"Disconnected"<<std::endl;
    close(connection);
}

void quit_command(int sockfd)
{
    std::string s;
    while (std::cin >> s)
    {
        if (strcmp(s.c_str(),"quit")== 0)
        {
            close(sockfd);
            exit(EXIT_FAILURE);
        }
    }
}

int main()
{
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

        std::thread quit_cmd(quit_command, sockfd);
        quit_cmd.detach();

        // Listen to port 9999 on any address
        sockaddr_in sockaddr;                     //https://stackoverflow.com/a/21099172  https://www.gta.ufrj.br/ensino/eel878/sockets/sockaddr_inman.html
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port = htons(9999); // htons is necessary to convert a number to
        sockaddr.sin_addr.s_addr = INADDR_ANY;
                                        // network byte order

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


            std::thread client_cmd(client_command,sockaddr,connection);
            client_cmd.detach();
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