#ifndef __SIMPLE_CRYPTO_H
#define __SIMPLE_CRYPTO_H

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
/**
This file contains the definitions oft the functions 
we will use to implement the algorithms for encryption
and decryption as well as any other definitions we will
find useful
*/


//function that encrypts data inserted by user using OTP algorithm
char* OTP_encrypt(char plaintext[] , char key[] );


//function that decrypts data that have been encrypted  using OTP algorithm
char* decrypt_OTP(char ciphertext[] , char key[]);


//function that encrypts data inserted by user using Caesar algorithm
char* Caesar_encrypt(char plaintext[] , int key );


//function that decrypts data that have been encrypted  using Caesar algorithm
char* decrypt_Caesar(char ciphertext[] , int  key);

//function that encrypts data inserted by user using Vigenere algorithm
char* Vigenere_encrypt(char plaintext[] , char key[] );


//function that decrypts data that have been encrypted  using Vigenere algorithm
char* decrypt_Vigenere(char ciphertext[] , char  key[]);








//array to store the random key we generate
char secret_key[255];

//array to store the ciphertext
char otp_encrypted[255];
char caesar_encrypted[255];
char vigenere_encrypted[255];

//array to store the decrypted string
char otp_decrypted[255];
char caesar_decrypted[255];
char vigenere_decrypted[255];

#endif
