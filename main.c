#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <openssl/sha.h>
#include <ctype.h>

// Given two hex characters in ASCII (0-9, a-f) 
// representing a two-digit hexadecimal number, 
// return the integer they represent.
uint8_t hex_to_byte(unsigned char h1, unsigned char h2){
    // store the decimal value of the first char h1
    int result1 =0;

    // Conditions for hexa h1
    if(h1 >= 'a' && h1 <= 'f'){
        result1 = h1 - 'a' + 10;
    }
    else if(h1 >= '0' && h1 <= '9'){
        result1 = h1 - '0';
    }
    
    // store the decimal value of the second char h2
    int result2 =0;

    // Conditions for hexa h2
    if(h2 >= 'a' && h2 <= 'f'){
        result2 = h2 - 'a' + 10;
    }
    else if(h2 >= '0' && h2 <= '9'){
        result2 = h2 - '0';
    }
    
    return (result1  << 4) + (result2);
}

// Converting from 64 hex characters into 32-byte array correspoding
// to the hex values.
void hexstr_to_hash(char hexstr[], unsigned char hash[32]) {
    int i;
    for (i= 0; i < 32; i++) {
        hash[i] = hex_to_byte(hexstr[2 * i], hexstr[2 * i + 1]);
    }
}

// Testing the hex_to_byte function
void test_hex_to_byte(){

assert(hex_to_byte('c', '8') == 200);
assert(hex_to_byte('0', '3') == 3);
assert(hex_to_byte('0', 'a') == 10);
assert(hex_to_byte('1', '0') == 16);
printf("test_hex_to_byte success!! \n");
}


// Testing the hexstr_to_hash
void test_hexstr_to_hash(){
    char hexstr[64] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
    unsigned char hash[32];
    hexstr_to_hash(hexstr, hash);
    // hash should now contain { 0xa2, 0xc3, 0xb0, 0x2c, ... }
    int i;
    for( i=0; i< sizeof(hash); i++){
        printf("%02x, ", hash[i]);
    }

    //for clear output
    printf("\n");

    // assert values for the beginning and end elements
    assert(hash[0] == 0xa2);
    assert(hash[31] == 0xfd);
    printf("test_hexstr_to_hash passed!\n");
}

// Function to hash a string and store the result in hash_output
void hash_password(const char *password, unsigned char hash_output[SHA256_DIGEST_LENGTH]) {
    SHA256((unsigned char *)password, strlen(password), hash_output);
}

// Function to compare two hashes
int compare_hashes(const unsigned char hash1[SHA256_DIGEST_LENGTH], const unsigned char hash2[SHA256_DIGEST_LENGTH]) {
    return memcmp(hash1, hash2, SHA256_DIGEST_LENGTH) == 0;
}

// **Milestone 2**
int8_t check_password(char password[], unsigned char given_hash[32]) {
    unsigned char hashed_password[32];
    SHA256((unsigned char *)password, strlen(password), hashed_password);
    return compare_hashes(hashed_password, given_hash) ? 1 : 0;
}



int8_t crack_password(char password[], unsigned char given_hash[32]){

    unsigned char current_hash[32];
    size_t len = strlen(password);

    // Trying the original password
    hash_password(password, current_hash);
    if(compare_hashes(current_hash, given_hash)){
        return 1; // matching
    }

    // If uppercased or lowercased
    int i;
    for(i =0; i<len; i++){
        if(isalpha(password[i])){
            char original_char = password[i];

            if(islower(password[i])){
                password[i] = toupper(password[i]);
            } 
            else if(isupper(password[i])){
                password[i] = tolower(password[i]);
            }
            // Hash and compare
            hash_password(password, current_hash);
            if (compare_hashes(current_hash, given_hash)) {
                return 1;  // A variation matches
            }

            // Restore original character
            password[i] = original_char;
        }
    }
    printf("<Press Ctrl-D for end of input>\n");
    printf("Did not find a matching password\n");

    return 0;
}
int main(int argc, char **argv){
/*
    // If for test 1, if not 0
    const int testing = 0; 

    // Runing the test
    if(testing){
        test_hex_to_byte();
        test_hexstr_to_hash();
    }

    if(argc != 2){
        printf("Wrong input");
        return 1;
    }

    // if user input correctly
    unsigned char hash[32];
    hexstr_to_hash(argv[1], hash);

    printf("User input as hash: \n");
    for(int i =0; i< sizeof(hash); i++){
        printf("%02x, ", hash[i]);
    }

    printf("\n");


    // Example hash for the password "password"
    char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    unsigned char given_hash[32];

    // Convert the hex string to byte array (assuming you have hexstr_to_hash implemented)
    hexstr_to_hash(hash_as_hexstr, given_hash);

    // Test with correct and incorrect passwords
    assert(check_password("password", given_hash) == 1);   // Should return 1
    assert(check_password("wrongpass", given_hash) == 0);  // Should return 0

    printf("All tests passed.\n"); // passed
*/
    unsigned char given_hash[32];
    hexstr_to_hash(argv[1], given_hash);

    char password[256];
    while(fgets(password, sizeof(password),stdin) != NULL){
        
        // Remove the newline character from the input password
        password[strcspn(password, "\n")] = 0;

        //Check if this password matches the given bash
        if(check_password(password,given_hash)){
            printf("Found password: SHA256(%s) = %s\n", password, argv[1]);
            return 0;
        } else if (crack_password(password, given_hash)) {
            printf("Found matching password variation: SHA256(%s) = %s\n", password, argv[1]);
            return 0;
        }
    }
    
    return 0;
}