#include <sys/socket.h> // For socket functions
#include <netinet/in.h> // For sockaddr_in
#include <cstdlib> // For exit() and EXIT_FAILURE
#include <iostream> // For cout
#include <unistd.h> // For read
#include <errno.h>
#include <cstring>
#include <thread>
#include <sys/stat.h>

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>

void threadClient(sockaddr_in sockaddr,int connection)
{
    /*
    // Send a message to the connection
    std::string response = "Good talking to you\n";
    write(connection, response.c_str(), response.size());
    */

    // Read from the connection
    // char buffer[100];
    // const char *buffer [2];

    // while (read(connection, &buffer, sizeof(buffer))>0)
    // {
    //     const char * pwd = buffer.back();
    //     buffer.pop_back();
    //     const char * usrname = buffer.back();
    //     buffer.pop_back();
    //     std::cout << "The message was: " << &usrname << " "<<&pwd;
            // std::cout<< "The message was : "<<buffer[0]<<" "<<buffer[1];
    // }
    
    // close(connection);
    

}

void command(int sockfd)
{
    std::cout <<" === Welcome to a file storage system ===\n"<<
            "  To delete a file (or repo) write '""del""'\n"<<
            "  To download a file (or repo) write '""dl""'\n"<<
            "  To upload a file (or repo) write '""upload""'\n"<<
            "  To create a repo write '""create""'\n"<<
            "  To quit write '""quit""'"<<std::endl;
    std::string s;
    while (std::cin >> s)
    {
        
        if (s == "quit")
        {
            close(sockfd);
            exit(EXIT_FAILURE);
        }else{

             //Store file
            //Dl files
            //delete files
            //files =  repo or files


            //un ls de tout les dossier ou le user est proprio ou a les droit ecriture ==> jsp quoi pour le droit de lecture

            std::string param;
            std::string path = "./files/";

            if(std::strcmp(s.c_str(),"del")==0)
            {
                std::cout<<"You're in the delete section"<<std::endl;

                std::filesystem::remove_all("./files/a");

            }else if (std::strcmp(s.c_str(),"dl")==0)
            {
                std::cout<<"You're in the download section"<<std::endl;


            }else if (std::strcmp(s.c_str(),"upload")==0)
            {
                std::cout<<"You're in the upload section"<<std::endl;

                std::filesystem::copy("./files/a", "./files/test", std::filesystem::copy_options::recursive);

            }else if (std::strcmp(s.c_str(),"create")==0)
            {
                std::cout<<"You're in the create section"<<std::endl;
                std::cout<<"Enter the directory name. e.g. path/myDirectory : ";
                
                std::cin >> param;

                std::string merge = path+param;

                const char* tmp[]={merge.c_str()};
                std::cout<<"path : "<<tmp<<std::endl;

                if(!mkdir(*tmp,S_IRWXU))
                {
                    std::cout<<"repo created"<<std::endl;
                }else
                {
                    std::cout<<"Error creation repo"<<std::endl;
                }
                

            }
            
            







        }
    }
}

int main()
{

    command(0);

    /*
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

    // std::thread com(command, sockfd);
    // com.detach();

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

        std::thread test(threadClient,sockaddr,connection);
        test.detach();
    }
    */
    
    
}