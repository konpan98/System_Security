File to explain the implementation of our program 

Folder contairs files simple_crypto.h simple_crypto.c demo.c Makefile and this ReadMe file.

//////////OTP ALGORITHM/////////////
we used the /dev/random presudorandom generator,using fread, to get a random key in order to get the key to cipher the plaintext. After the decryption we erased the key for security reasons.
We used the operan ^ in order to XOR the plaintext and the key to do the encryption as well as the decryption since XOR is a symmetric operation


///////////CAESARS ALGORITHM ///////////
using the key inserted by the user and the modulus operator we managed to encrypt and decrypt the data and make the neccasary shifts as the caesars algorithm dictates. We used ASCII code in order to see the boundaries and do the shifts in a way that we dont have any non printable characters.

///////////////////Vinegere algorithm /////////
we implemented in main a simple for loop to extend the key given by the user in the same length as the plaintext. For the encryption and decryption we used again the modulus operator as shown below:
Encryption: E=(P + K ) % 26 , where P:plaintext K:extended key and 26 is the number of the letters of the English alphabet
Decryptio: D= (E - K + 26) % 26 where E:ciphertext K:extended key


simple_crypto.h
here we have the declarations of the encryption and decryption functions for each algorithm as well as char arrays where we save the encyption and decryption string for each algorithm

demo.c
the program will ask you first the plaintext and the key depending the algorithm and then it will execute the encryption and decryption tasks printing in the terminal the messages as requested in the lab assigment

NOTE 
in the otp algorithm the encrypted strings sometimes is not shown fully as it has some non printable characters after the XOR opetation is done. I dont if it is a problem with my setting but i wanted to mention it if it occurs.


gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0

