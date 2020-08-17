#ifndef UTILS_H
#define UTILS_H


#include <cstring>
#include <unistd.h> // For read
#include <sys/types.h>
#include <sys/socket.h>
#include "Message.hpp"

struct Utils
{
    public:
        static void check_path_exists(std::string& path);
        static std::string itoa(int a);
        template <typename T> static void unserialize_message(T& msg, int connection);
        template <typename T> static void serialize_message(T& msg, int sockfd);
        static void send_msg(int sockfd, std::string path, ssize_t file_size);
        static void recursive_send(std::string path, int sockfd);
};

void Utils::recursive_send(std::string path, int sockfd)
{
    std::filesystem::path p(path);
    std::string upload_path(p.filename().generic_string());
    bool isDir = std::filesystem::is_directory(p);
    if (isDir)
    {
        Message::unixFile msg(std::filesystem::path(upload_path),isDir,upload_path.length());
        Utils::serialize_message<Message::unixFile>(msg,sockfd);
        for (const auto & entry : std::filesystem::recursive_directory_iterator(path))
        {
            isDir = std::filesystem::is_directory(entry.path());
            if (!isDir)
            {
                Message::unixFile msg(std::filesystem::path(upload_path+"/"+entry.path().filename().generic_string()),isDir,entry.file_size());
                Utils::serialize_message<Message::unixFile>(msg,sockfd);
                Utils::send_msg(sockfd,entry.path().c_str(),entry.file_size());
            }else
            {
                upload_path = upload_path+"/"+entry.path().filename().generic_string();
                Message::unixFile msg(std::filesystem::path(upload_path),isDir,upload_path.length());
                Utils::serialize_message<Message::unixFile>(msg,sockfd);
            }
        }
    }else
    {
        Message::unixFile msg(std::filesystem::path(upload_path),isDir,std::filesystem::file_size(p));
        Utils::serialize_message<Message::unixFile>(msg,sockfd);
        Utils::send_msg(sockfd,path,std::filesystem::file_size(p));
    }
    Message::unixFile fin("",isDir,0); 
    Utils::serialize_message<Message::unixFile>(fin,sockfd);
}

void Utils::send_msg(int sockfd, std::string path, ssize_t file_size)
{
    FILE * readFile =  fopen(path.data(),"rb");
    if (readFile == NULL)
    {
        std::cout<<"Unable to open File";
        fclose(readFile);
        close(sockfd);
    }

    int buffSize = 1024;
    if (file_size<1024)
    {
        buffSize = file_size;
    }

    std::cout<<"\nNumber of Bytes :"<<file_size<<std::endl;

    std::string FileSize = Utils::itoa(buffSize).c_str();
    FileSize[buffSize] = '\0';
    send(sockfd,FileSize.c_str(),buffSize,0);
    double origin_size = file_size;

    
    char buffer[buffSize];
    int pourc;
    int bytesReceived = 0;
    int test = 0;
    int last_pourc = 0;
    while(file_size > 0)
    {
        bytesReceived = 0;
        memset(buffer,0,sizeof(buffer));
            if(file_size>1024)
            {
                fread(buffer, 1024, 1, readFile);
                bytesReceived = send(sockfd, buffer, 1024, 0 );
            }
            else
            {
                fread(buffer, file_size, 1, readFile);
                buffer[file_size]='\0';
                bytesReceived = send( sockfd, buffer, file_size, 0 );
            }
            test+=bytesReceived;
            file_size -= 1024;
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
}

void Utils::check_path_exists(std::string& path)
{
    std::filesystem::path p(path);
    while (!std::filesystem::exists(p))
    {
        std::cout<<"This file doesn't exists. Enter a correct file path."<<std::endl;
        std::cin >> path;
        p = std::filesystem::path(path);
    }
}

std::string Utils::itoa(int a)
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

template <typename T>
void Utils::unserialize_message(T& msg, int connection)
{
    char buffer[sizeof(msg)];
    memset(buffer,0,sizeof(buffer));
    std::string temp;
    std::stringstream ss;

    read(connection, buffer, sizeof(msg)); 
    temp.assign(buffer); 
    ss << temp;
    ss >> msg;
    ss.clear();
}


template <typename T>
void Utils::serialize_message(T& msg, int sockfd)
{
    std::stringstream ss;
    ss << msg;    //serialize
    write (sockfd, ss.str().c_str(), sizeof(msg)); 
    ss.clear();
}

#endif