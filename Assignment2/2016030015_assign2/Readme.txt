File to explain the implementation of our program 

//////////ENCRYPTION//////////
USE functions EVP_EncryptInit_ex , EVP_EncryptUpdate , EVP_EncryptFinal_ex in order to encrpyt the input file 

//////DECRPYTION /////////////

USE functions EVP_DecryptInit_ex , EVP_DecryptUpdate , EVP_DecryptFinal_ex in order to decrpyt the input file 

//////////////keygen ////////////
inorder to generate the key we used the function EVP_BytesToKey using aes_ecb function fot the cipher type and algorithm and the EVP_sha1 hash function as a message digest 
//////////////verification ////////
use of function strcmp to verify the two cmacs 

///////cmac generation ////////
use of functions CMAC_Init CMAC_Update CMAC_Final in order to generate the cmac 

In addition we created functions to read and write from and to an input file 
respectively 

TASK F.4
Both files dont verify
