#include <iostream>

struct user
{
    private:
        std::string username;
        char (&password)[72];
    public:
        // user(char (&password)[72]);
        user(std::string username, char (&password)[72]);
        std::string get_username();
        char* get_password();
        //void set_password(char password[72]);
        //std::string to_string();
        friend std::ostream& operator<< (std::ostream& out, user& object) {
        out << object.username << " " << object.password;   //The space (" ") is necessari for separete elements
        return out;
        }

        friend std::istream& operator>> (std::istream& in, user& object) {
        in >> object.username;
        in >> object.password;
        return in;
        }
};

// user::user(char (&password)[72]):user("",password){}

user::user(std::string username, char (&password)[72]):username(username),password(password){}

char * user::get_password()
{
    return this->password;
}


std::string user::get_username()
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