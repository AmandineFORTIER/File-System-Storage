#include <iostream>


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

cmdMsg::cmdMsg(std::string cmd_request):cmdMsg(cmd_request,"",""){}
cmdMsg::cmdMsg(std::string cmd_request, std::string param1):cmdMsg(cmd_request,param1,""){}
cmdMsg::cmdMsg(std::string cmd_request, std::string param1, std::string param2):cmd_request(cmd_request),param1(param1), param2(param2){}
std::string cmdMsg::get_cmd_request()
{
    return this->cmd_request;
}
std::string cmdMsg::get_param1()
{
    return this->param1;
}
std::string cmdMsg::get_param2()
{
    return this->param2;
}

// user::user(char (&password)[72]):user("",password){}

userMsg::userMsg(std::string cmd_request, std::string username, char (&password)[72]):cmd_request(cmd_request), username(username),password(password){}

std::string userMsg::get_cmd_request()
{
    return this->cmd_request;
}


char * userMsg::get_password()
{
    return this->password;
}


std::string userMsg::get_username()
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
