#include "simple_crypto.h"
#include<stdio.h>
/**
In this file we implement the functions 
that we definde in simple_crypto.h for the 
three algorithms we want to implement
*/

 char* OTP_encrypt (char plaintext[] , char key[]  ){
	
	for (int i=0; i<strlen(plaintext); i++)
		otp_encrypted[i]=plaintext[i]^key[i];
	
	return otp_encrypted;
}

char*  decrypt_OTP (char ciphertext[] , char key[] ){
	
	for (int i=0; i<strlen(ciphertext); i++)
		otp_decrypted[i]=ciphertext[i]^key[i];


	key[0]='\0';//clear random keyCLEAR
}	

char * Caesar_encrypt(char plaintext[] , int key ){
	for(int i=0; i<strlen(plaintext);i++){
		if(isupper(plaintext[i]))
			caesar_encrypted[i]=((plaintext[i] - 65 + key) % 26) + 65; // for upper letters
		
		else if(islower(plaintext[i]))
			caesar_encrypted[i]=((plaintext[i] - 97 + key) % 26) + 97; // for lower letters
 
		else
			caesar_encrypted[i]=((plaintext[i] - 48 + key) % 10) + 48; // for numbers
	}
	return caesar_encrypted;
}

char * decrypt_Caesar(char ciphertext[] , int key ){
	for(int i=0; i<strlen(ciphertext);i++){
		if(isupper(ciphertext[i]))
			caesar_decrypted[i]=((ciphertext[i] - 65 - key) % 26) + 65;
		
		else if(islower(ciphertext[i]))
			caesar_decrypted[i]=((ciphertext[i] - 97 - key) % 26) + 97;
 
		else
			caesar_decrypted[i]=((ciphertext[i] - 48 - key) % 10) + 48;
	}

	return caesar_decrypted;
}



char* Vigenere_encrypt(char plaintext[] , char key[] ){
	for(int i=0; i<strlen(plaintext);++i)
		vigenere_encrypted[i]=(( plaintext[i] + key[i]) % 26) + 'A';

	return vigenere_encrypted;
		
}



char* decrypt_Vigenere(char ciphertext[] , char key[]){
	for(int i=0; i<strlen(ciphertext);++i)
		vigenere_decrypted[i]=(( ciphertext[i] - key[i] + 26) % 26) + 'A';

	return vigenere_decrypted;
		
}

