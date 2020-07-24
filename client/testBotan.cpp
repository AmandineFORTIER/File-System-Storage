#include "botan-2/botan/bcrypt.h"
#include "botan-2/botan/botan.h"
#include <iostream> // For cout

int main()
{
    Botan::AutoSeeded_RNG rng;
    std::string strr="test";
    auto hash = Botan::generate_bcrypt(strr, rng, 10);
    std::cout<<hash<<std::endl;
    std::cout<<Botan::check_bcrypt("test",hash)<<std::endl;

}

