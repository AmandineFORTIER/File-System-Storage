
#include "client.h"

#include <sys/socket.h> // For socket functions
#include <netinet/in.h> // For sockaddr_in
#include <cstdlib> // For exit() and EXIT_FAILURE
#include <unistd.h> // For read
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <cstring>
#include <termios.h>



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

void read_from_connection(int sockfd)
{
    // Read from the connection
    char buffer[100];
    auto bytesRead = read(sockfd, buffer, 100);
    std::cout<<buffer<<std::endl;
}

int main()
{
    std::cout <<" === Welcome to a file storage system ===\n"<<
                "  To create an account write '""create""'\n"<<
                "  To connect yourself write '""connect""'\n"<<
                "  To quit write '""quit""'"<<std::endl;
    
    //traiter le quit ici le reste envoyer et le serveur gère
    std::string s;
    while (std::cin >> s)
    {
        if (std::strcmp(s.c_str(),"quit")==0)
        {
            exit(EXIT_SUCCESS);
        }else if (std::strcmp(s.c_str(),"create")==0 || std::strcmp(s.c_str(),"connect")==0)
        {
            break;
        }
    }

    int sockfd = connect_to_server();

    std::string username = ask_username();
    char pass[72];
    ask_password(pass);
    user usr(username,pass);


    //envoyer au server




    

    std::cout<<usr.get_username()<<" "<<usr.get_password()<<std::endl;
    

    read_from_connection(sockfd);


    char buff[100];
    while(read(1, buff, 100) > 0)
    {
        write(sockfd, buff, 100);
        memset(buff, 0, sizeof(buff));
    }

    close(sockfd);

}


