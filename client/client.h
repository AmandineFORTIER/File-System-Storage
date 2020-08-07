#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>
#include "../User.h"


struct command
{
    private:
        std::string action;
        user usr;
    public:
        command(std::string action, user usr);
        // std::string to_string();
};

command::command(std::string action, user usr):action(action),usr(usr){};

// std::string command::to_string()
// {
//     std::string to_string = this->action;
//     to_string += " ";
//     to_string += this->usr.to_string();
//     return to_string;
// }

#endif //CLIENT_H
