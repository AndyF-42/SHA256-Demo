#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

//currently just prints out result
void sha256(const char* str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, strlen(str));
    SHA256_Final(hash, &sha256);
    
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", (int)hash[i]);
    }
    printf("\n");
}

int main() {
    // sample cases
    sha256("12345_1");
    sha256("12345_2");
    sha256("12345_3");
    sha256("12345_4");
    return 0;
}

