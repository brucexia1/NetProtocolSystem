#include <iostream>

using namespace std;

extern "C" {
void hash_test();
void cipher_test();
}


int main()
{
    hash_test();
    cipher_test();

    return 0;
}
