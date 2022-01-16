#include "rsa.h"
#include "utils.h"


/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *prime_sz){
    size_t *all;
    size_t *primes;
    int i,j;
   

    for (i = 2;i < limit; i++)
        all[i] = 1; 

    for (i = 2;i < limit; i++)
        if (all [i])
           for (j = i;i * j < limit; j++)
                all[i * j] = 0;

    int prime_size=0,index=-1;
    for (int i =  0 ; i < limit; i++ ){
        if(all[i] != 0)
            prime_size ++;
    }
    *prime_sz = prime_size;
    primes = malloc(prime_size*sizeof(size_t));

    for(int i = 0; i < limit; i++){
        if(all[i] !=0){
            index++;
            primes[index] = all[i];
        }
    } 


    return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{

    if(b == 0)
        return a;
    return gcd(b,a % b);

}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
    size_t e;

    for (int i = 2; i < fi_n ; i++){
        e = i;
        if((gcd(e,fi_n) == 1))
            break;
    }

    return e;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{
    size_t inv;
    //a = a % b;
    for(int i = 0; i < b; i++){
        if((a * i) % b == 1){
            inv = i;
        }
    }
    
    return inv;
}

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

/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{   
    size_t *primes;
    size_t p;
    size_t q;
    size_t n;
    size_t fi_n;
    size_t e;
    size_t d;
    int size;

    primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &size);
    p = primes[rand()%size];
    q = primes[rand()%size];
    if(p == q){
        do{
             q = primes[rand()%size];
        }while(p == q);
    }

    n = p * q;
    fi_n = (p - 1) * (q - 1);
    e = choose_e(fi_n);
    d = mod_inverse(e,fi_n);
    FILE* fp1,*fp2;
    fp1 = fopen("hpy414_public.key","w+");
    fprintf(fp1,"%ld-%ld",n ,d);
    rewind(fp1);
    fclose(fp1);

    fp2 = fopen("hpy414_private.key","w+");
    fprintf(fp2,"%ld-%ld",n ,e);
    rewind(fp2);
    fclose(fp2);

}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{
    FILE* fp1,*fp2,*fp3;
    
    
    char keyinfo[300];
    char inputInfo[300];
    char ciphertext[300];
    char ciphertextinbytes[300*16]; //for encrypted
    fp1= fopen(key_file,"r");
    fscanf(fp1,"%s",keyinfo);
    char* split=strtok(keyinfo,"-");
    size_t n= atoi(split);
    split= strtok(NULL,"-");
    size_t d=atoi(split);

    fp2= fopen(input_file,"r");
    fgets(inputInfo,300,fp2);
    size_t helpChar;
    size_t a=1;
    //size_t a_inv;
    //encryption
    for(int i=0; i<=strlen(inputInfo); i++){
        for(int j=0; j<d;j++){
           a = ((a*inputInfo[i])%n);
        }
        ciphertext[i] = a;

    }
    fp3=fopen(output_file,"wb");
    fwrite(ciphertext,1,strlen(ciphertext),fp3);


    fclose(fp1);
    fclose(fp2);
    fclose(fp3);


}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

    FILE* fp1,*fp2,*fp3;
    size_t n,d;
   

    char ciphertext[255];
    

}
