# AES 128 / CPC / PAD5

Function that replaces the values ​​of a field of a select in another value that will depend on the chosen configuration

**Encryption:**

- AES 128 - AES is very fast and secure, and it is the de facto standard for symmetric encryption.
- CBC(Cipher-Block Chaining) Each of the ciphertext blocks depends on the current and all previous plaintext blocks
- PKCS#5 - Password-Based Encryption Standard, RSA Laboratories

**parâmeters:**
- p_original_text: text to be converted according to the chosen algorithm and action
- p_key: The secret key to use in the symmetric cipher. It must be 16 (AES-128)
- p_algorithm: AES128 - will encrypt or decrypt the column string reported using the 128-bit AES algorithm 
  - SUBS_STRING  - It will replace all the characters of the string with the value X. The spaces will be kept
  - SUBST_DATA - Will replace a date for a default date 01/01/1900
  - SUBST_NUMERIC - It will replace all the characters in the string with a value of 0. The spaces will be kept

 *p_action:* 1 for encrypt 0 for decrypt. Decryption will only be performed for columns that have been encrypted with the 128-bit aes algorithm	

e.g:

-- (Encoding of a string using AES128 algorithm)

select AES128_STRING('133467895421','1234567890123456', 'AES128',1) from dual; 

-- (Decoding of a string using AES128 algorithm)

select AES128_STRING('EB833824D0AA717F59D8899BE09582CF','1234567890123456', 'AES128', 2) from dual; 

-- (Mask a string by replacing all its characters with x)

select AES128_STRING('NAME LAST LANE','null', 'SUBS_STRING', 1) from dual; 

-- (Mask a string by replacing all its characters with 0)

select AES128_STRING('15789 7897','null', 'SUBS_NUMERIC', 1) from dual; 

-- (Mask a string by replacing all its characters with 01/01/1900)

select AES128_STRING('25/12/1980','null', 'SUBS_DATA', 1) from dual; 
