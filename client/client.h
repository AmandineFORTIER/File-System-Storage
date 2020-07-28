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
};









#endif //CLIENT_H
