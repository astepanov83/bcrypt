#include "bcrypt/BCrypt.hpp"
#include <iostream>
#include <vector>
#include <utility>

int main(int, char**) {
    std::cout << "Testing libbcrypt." << std::endl;
    std::vector<std::pair<std::string, std::string>> testPasswordsAndHashesVector;
    
    testPasswordsAndHashesVector.push_back({"abc", "$2a$10$8iRRL3xhamstsVQayC04aeO1NRZ0Hm4ycv2S5qgMtDV3SxCy8/qPK"});
    testPasswordsAndHashesVector.push_back({"superStrongPass", "$2a$10$2CowvhDtaXQWzt6Ia4Dv.Or3Mv7gjTbOW2kZcXdB/p2Oj92mYI47e"});
    testPasswordsAndHashesVector.push_back({"cba", "$2a$10$vg8Z3MaVd/Yy2bzOcn/HYeWaY78K5c3jo8NVsri1i1UqyLOzNzIJm"});
    testPasswordsAndHashesVector.push_back({"dasd'dasd!@", "$2a$10$VlLE1pXWuFI6i0YDJPD.tuJ9Qb5fqFjja3r9xto650qtU10/i2Y/K"});
    testPasswordsAndHashesVector.push_back({"sdasd1WS)SD<KI*@", "$2a$10$HK25GYXyedcnb9XV8uv1EegRVKHaL/luF16/PbwrgnX96CAHH5uce"});
    testPasswordsAndHashesVector.push_back({"sdasd1WS)SD<KI*@", "$2a$10$HK25GYXyedcnb9XV8uv1EegRVKHaL/lu666/PbwrgnX16CAHH5555"}); //WRONG HASH FOR TEST

    std::cout << "password ----- generated hash ----- check gen hash " << std::endl << " ----- test hash ----- check test hash" << std::endl;
    std::vector<std::string> generatedHashes;

    int numberOfHashingPasses = 10; //same as jbcrypt, increase for complexity, must be in range 4 - 30
    for(auto testPassAndHash : testPasswordsAndHashesVector) {
        std::string hash = BCrypt::generateHash(testPassAndHash.first, numberOfHashingPasses);
        BCrypt::validatePassword(testPassAndHash.first, testPassAndHash.second);
        std::cout << testPassAndHash.first  << " ----- " << hash  << std::endl << " ----- "
        << BCrypt::validatePassword(testPassAndHash.first, hash) << " ----- " 
        << testPassAndHash.second << " ----- " << BCrypt::validatePassword(testPassAndHash.first, testPassAndHash.second)  << std::endl;
    }

    

}
