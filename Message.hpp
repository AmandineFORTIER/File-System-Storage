#ifndef MESSAGE_H
#define MESSAGE_H


#include <iostream>
#include <filesystem>

struct Message
{
    struct userMsg
    {
        private:
            std::string cmd_request;
            std::string username;
            char (&password)[72];
        public:
            // user(char (&password)[72]);
            userMsg(std::string cmd_request, std::string username, char (&password)[72]);
            std::string get_username();
            char* get_password();
            std::string get_cmd_request();
            //void set_password(char password[72]);
            //std::string to_string();
            friend std::ostream& operator<< (std::ostream& out, userMsg& object) 
            {
                out << object.cmd_request<<" "<< object.username << " " << object.password;   //The space (" ") is necessari for separete elements
                return out;
            }

            friend std::istream& operator>> (std::istream& in, userMsg& object) 
            {
                in >> object.cmd_request;
                in >> object.username;
                in >> object.password;
                return in;
            }
    };

    struct cmdMsg
    {
        private:
            std::string cmd_request;
            std::string param1;
            std::string param2;
        public:
            cmdMsg(std::string cmd_request,std::string param1, std::string param2);
            cmdMsg(std::string cmd_request,std::string param1);
            cmdMsg(std::string cmd_request);
            std::string get_cmd_request();
            std::string get_param1();
            std::string get_param2();
            friend std::ostream& operator<< (std::ostream& out, cmdMsg& object) 
            {
                out << object.cmd_request<<" "<< object.param1 << " " << object.param2;   //The space (" ") is necessari for separete elements
                return out;
            }

            friend std::istream& operator>> (std::istream& in, cmdMsg& object) 
            {
                in >> object.cmd_request;
                in >> object.param1;
                in >> object.param2;
                return in;
            }
    };

    struct unixFile
    {
        private:
            std::filesystem::path path;
            bool is_dir;
            ssize_t size;
        public:
            unixFile(std::filesystem::path path, bool is_dir, ssize_t size);
            std::filesystem::path get_path();
            bool get_is_dir();
            ssize_t get_size();
            friend std::ostream& operator<< (std::ostream& out, unixFile& object) 
            {
                out << object.path<<" "<< object.is_dir<<" "<<object.size;   //The space (" ") is necessari for separete elements
                return out;
            }

            friend std::istream& operator>> (std::istream& in, unixFile& object) 
            {
                in >> object.path;
                in >> object.is_dir;
                in >> object.size;
                return in;
            }
    };
};

Message::unixFile::unixFile(std::filesystem::path path, bool is_dir, ssize_t size):path(path), is_dir(is_dir), size(size){}
std::filesystem::path Message::unixFile::get_path()
{
    return path;
}
bool Message::unixFile::get_is_dir()
{
    return is_dir;
}
ssize_t Message::unixFile::get_size()
{
    return size;
}

Message::cmdMsg::cmdMsg(std::string cmd_request):cmdMsg(cmd_request,"",""){}
Message::cmdMsg::cmdMsg(std::string cmd_request, std::string param1):cmdMsg(cmd_request,param1,""){}
Message::cmdMsg::cmdMsg(std::string cmd_request, std::string param1, std::string param2):cmd_request(cmd_request),param1(param1), param2(param2){}
std::string Message::cmdMsg::get_cmd_request()
{
    return this->cmd_request;
}
std::string Message::cmdMsg::get_param1()
{
    return this->param1;
}
std::string Message::cmdMsg::get_param2()
{
    return this->param2;
}

// user::user(char (&password)[72]):user("",password){}

Message::userMsg::userMsg(std::string cmd_request, std::string username, char (&password)[72]):cmd_request(cmd_request), username(username),password(password){}

std::string Message::userMsg::get_cmd_request()
{
    return this->cmd_request;
}


char * Message::userMsg::get_password()
{
    return this->password;
}


std::string Message::userMsg::get_username()
{
    return this->username;
}


// std::string user::to_string()
// {
//     std::string to_string = this->username;
//     to_string += " ";
//     to_string += this->password;
//     return to_string;
// }

#endif