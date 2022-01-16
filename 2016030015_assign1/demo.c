#include "simple_crypto.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include<ctype.h>


/*
Demo file to run and see
how the algorithms we implemented 
execute
*/


//function to generate key for OTP algorithm 
void generate_key(int N);




int main(int argc, char** argv)
{
	char otp[255],caesar[255],vinegere[255],vkey[100];
	int key,i,j;
	char extendedKey[100];

	////OTP algorithm !!!!!!!!!!
	printf("Give us the string to be encrypted  using OTP algorithm : \n");
	scanf("%s",otp);
	generate_key(strlen(otp));


	////Caesar algorithm !!!!!!!!!!!!
	printf("Give us the string to be encrypted  using Caesar algorithm : \n");
	scanf("%s",caesar);
	printf("Give us the key for the Caesar algorithm: \n");
	scanf("%d",&key);

	//// Vinegere algorithm !!!!!!!!!!!!
	printf("Give us the string to be encrypted  using Vinegere algorithm : \n");
	scanf("%s",vinegere);
	printf("Give us the key for the Vinegere algorithm : \n");
	scanf("%s",vkey);
	for(i=0,j=0;i<strlen(vinegere);++i,++j){
		if(j == strlen(vkey))
			j=0;
		extendedKey[i]=vkey[j];
	}


	////Perform encryptions and decryptions 

	//OTP
	OTP_encrypt(otp,secret_key);
	decrypt_OTP(otp_encrypted,secret_key);
	printf("[OTP] input : %s \n",otp);
	printf("[OTP] encrypted: %s \n",otp_encrypted);
	printf("[OTP] decrypted : %s \n",otp_decrypted);

	//Caesar
	Caesar_encrypt(caesar,key);
	decrypt_Caesar(caesar_encrypted,key);
	printf("[Caesars] input : %s \n",caesar);
	printf("[Caesars] key: %d \n",key);
	printf("[Caesars] encrypted: %s \n",caesar_encrypted);
	printf("[Caesars] decrypted : %s \n",caesar_decrypted);

	//Vinegere
	Vigenere_encrypt(vinegere , extendedKey );
	decrypt_Vigenere(vigenere_encrypted,extendedKey);
	printf("[Vinegere] input : %s \n",vinegere);
	printf("[Vinegere] key: %s \n",vkey);
	printf("[Vinegere] encrypted: %s \n",vigenere_encrypted);
	printf("[Vinegere] decrypted : %s \n",vigenere_decrypted);
	

	
}


void generate_key(int N ){
	
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	if (fp==NULL){
		;
	}
	int p=fread(secret_key,sizeof(char),N,fp);
	fclose(fp);
}

