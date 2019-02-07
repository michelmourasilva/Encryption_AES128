# AES 128 / CPC / PAD5

Method that replaces the values in another value that will depend on the chosen configuration

Application that masks or replaces fields that are considered sensitive from a .txt or .csv file

**Encryption:**

- AES 128 - AES is very fast and secure, and it is the de facto standard for symmetric encryption.
- CBC(Cipher-Block Chaining) Each of the ciphertext blocks depends on the current and all previous plaintext blocks
- PKCS#5 - Password-Based Encryption Standard, RSA Laboratories	

**Parâmeters:**

- [original text]:* text to be converted according to the chosen algorithm and action
- [key 16 characters]:* The secret key to use in the symmetric cipher. It must be 16 (AES-128)
- [action]:* 1 encrypt , 2 decrypt 

**Run application**

Application should be called via the command line. 	

**e.g:**

java Main [original text] [key 16 characters] [action]

java Main text 1234567890123456 1

