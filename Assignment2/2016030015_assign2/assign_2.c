#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);
EVP_CIPHER*  choose_ciphertype(int );
unsigned long  file_length(char *);
unsigned char * load_data(char *,unsigned long *);
void store_data(char *,  unsigned char *, unsigned long  );
unsigned char * string_init(unsigned long );




/* TODO Declare your function prototypes here... */



/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
* Choose aes algorithm
*/
 EVP_CIPHER* choose_ciphertype(int bit_mode){
 	EVP_CIPHER* cipher_type;
 	if(bit_mode == 128)
 		cipher_type = (EVP_CIPHER*)EVP_aes_128_ecb();
 	else
 		cipher_type = (EVP_CIPHER*)EVP_aes_256_ecb();
 	return cipher_type;

}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{
	EVP_CIPHER* cipher_type = choose_ciphertype(bit_mode);
	const EVP_MD* message_digest = EVP_sha1();
	const unsigned char* salt = NULL;
	const unsigned char* data = password;
	int password_len = strlen((const char *)password);
	int iterations = 5;

	if(!(EVP_BytesToKey(cipher_type,message_digest,salt,data,password_len,iterations,key,iv)))
		printf("Problem generating key....");

	

}


/*
 * Encrypts the data
 */
void
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext,int bit_mode)
{

	EVP_CIPHER_CTX* cipher_context = EVP_CIPHER_CTX_new();
	int len;

	if(!(EVP_EncryptInit_ex(cipher_context,choose_ciphertype(bit_mode),NULL,key,iv)))
		printf("Error setting up cipher context\n");

	if(!(EVP_EncryptUpdate(cipher_context,ciphertext,&len,plaintext,plaintext_len)))
		printf("Error encrypting .... \n");

	if(!(EVP_EncryptFinal_ex(cipher_context, ciphertext + len, &len)))
		printf("Error finalising encryption .... \n");

	EVP_CIPHER_CTX_free(cipher_context);


}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext,int bit_mode)
{
	EVP_CIPHER_CTX* cipher_context = EVP_CIPHER_CTX_new();
	int len;
	int plaintext_len;

	plaintext_len = 0;

	if(!(EVP_DecryptInit_ex(cipher_context,choose_ciphertype(bit_mode),NULL,key,iv)))
		printf("Error setting up cipher context\n");
	if(!(EVP_DecryptUpdate(cipher_context,plaintext,&len,ciphertext,ciphertext_len)))
		printf("Error decrypting .... \n");
	plaintext_len = len;

	//if((EVP_DecryptFinal_ex(cipher_context, ciphertext + len, &len)))
	//	printf("Error finalising decryption .... \n");
	
	int i=0;
	i=EVP_DecryptFinal_ex(cipher_context, ciphertext + len, &len);
	
	printf("Return value :%d\n",i );
	plaintext_len += len;
	EVP_CIPHER_CTX_free(cipher_context); 

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{

	CMAC_CTX *context = CMAC_CTX_new();
	size_t poutlen,keylen;
	if(bit_mode == 128)
		keylen = 16;
	else
		keylen = 32;



	if(!(CMAC_Init(context, key, keylen, choose_ciphertype(bit_mode), NULL)))
		printf("Error initializing CMAC ...\n");

	if(!(CMAC_Update(context, data, data_len)))
		printf("Error generating CMAC .....\n");

	if(!(CMAC_Final(context, cmac , &poutlen)))
		printf("Error finalising CMAC ....\n");

	CMAC_CTX_free(context);
	}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0;

	verify = strcmp(cmac1,cmac2);

	return verify;
}

/*
 * Get length of a file
 */
unsigned long file_length(char * input_file){
	FILE *fp;
	fp = fopen(input_file,"r");
	
	fseek(fp,0,SEEK_END);
	unsigned long fileLength = ftell(fp);
	rewind(fp);
	fclose(fp);
	
	return fileLength;
}

unsigned char *load_data(char* input_file,unsigned long *data_length){
	unsigned char *inputString;
	//unsigned long len;
	FILE *fp;
	fp = fopen(input_file,"r");
	*data_length = file_length(input_file);
	printf("Size of file is %ld\n", *data_length );
	inputString = malloc(*data_length);
	fread(inputString,1,*data_length,fp);
	fclose(fp);
	return inputString;

}

void store_data(char * output_file,unsigned char* output,unsigned long store_length){
	FILE *fp;
	fp = fopen(output_file,"w");
	fwrite(output,1,store_length,fp);
}

unsigned char * string_init(unsigned long store_length){
	unsigned char* output;
	output = malloc(store_length);
	return output;
}

/* TODO Develop your functions here... */



/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;/* the user defined password */
	unsigned char *output=NULL;	
	unsigned char *input=NULL;
	unsigned long data_length=0;
	unsigned long store_length = 0;
	unsigned char key[256], iv[256],cmac[16]; /* store key and iv from kdf */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */




	/* Initialize the library */
	//data_len = file_length(input_file);
	input = load_data(input_file,&data_length);


	/* Keygen from password */
	keygen(password, key, iv, bit_mode);

	/* Operate on the data according to the mode */
	switch(op_mode) {

		/* encrypt */
		case 0:
			store_length= data_length + BLOCK_SIZE - (data_length % BLOCK_SIZE);
			output = malloc(store_length);
			encrypt(input,data_length,key,iv,output,bit_mode);
			store_data(output_file,output,store_length);
			break;

		/* decrypt */
		case 1:
			output = malloc(data_length);
			store_length = decrypt(input , data_length, key , iv ,output, bit_mode);
			store_data(output_file,output,store_length);
			//print_hex(output,store_length);
			break;

		/* sign */
		case 2:
			store_length = data_length - (data_length %  16) + 2*16;
			output = malloc(store_length);
			encrypt(input,data_length,key,iv,output,bit_mode);
			gen_cmac(input, data_length, key, output + (store_length - 16), bit_mode);
			store_data(output_file,output,store_length);
			break;

		/* verify */
		case 3:
			output = malloc(data_length);
			store_length = decrypt(input , data_length - 16, key , iv ,output, bit_mode);
			gen_cmac(output, store_length, key, cmac , bit_mode);
			if (!verify_cmac(cmac, input + (data_length - 16)))
				return 1;

			store_data(output_file,output,store_length);
			break;

		default:
			break;
		
		
	}
	free(input);
	free(output);
	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
