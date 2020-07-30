#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>



struct user
{
    private:
        std::string username;
        char (&password)[72];
    public:
        user(std::string username, char (&password)[72]);
        std::string get_username();
        char* get_password();
        //void set_password(char password[72]);
        std::string to_string();
};

struct command
{
    private:
        std::string action;
        user usr;
    public:
        command(std::string action, user usr);
        std::string to_string();
};


user::user(std::string username, char (&password)[72]):username(username),password(password){};

char * user::get_password()
{
    return this->password;
}


std::string user::get_username()
{
    return this->username;
}


command::command(std::string action, user usr):action(action),usr(usr){};

std::string command::to_string()
{
    std::string to_string = this->action;
    to_string += " ";
    to_string += this->usr.to_string();
    return to_string;
}

std::string user::to_string()
{
    std::string to_string = this->username;
    to_string += " ";
    to_string += this->password;
    return to_string;
}



#endif //CLIENT_H
