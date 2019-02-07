# AES 128 / CPC / PAD5

Conversion of data considered sensitive in text files using encryption AES 128 / CPC / PAS 5 

Application that masks or replaces fields that are considered sensitive from a .txt or .csv file

**Encryption:**
- AES 128 :AES is very fast and secure, and it is the de facto standard for symmetric encryption.	
- CBC(Cipher-Block Chaining): Each of the ciphertext blocks depends on the current and all previous plaintext blocks	
- PKCS#5: Password-Based Encryption Standard, RSA Laboratories

Json file that contain the list of columns that will masked or replaced

**Template of Json config File**
        
*{"field": {"sensitive column": {"algorithm": "algorithm mask AES128, SUBS_STRING, SUBS_DATA or SUBS_NUMERIC","method": mask method - 1 for encrypt 0 for decrypt}}}*

**parameters:**
		
*sensitive column:* Name of the column inside the file that will have its data replaced
		
*algorithm:* AES128 - will encrypt or decrypt the column string reported using the 128-bit AES algorithm
		
- SUBS_STRING  - It will replace all the characters of the string with the value X. The spaces will be kept
- SUBST_DATA - Will replace a date for a default date 01/01/1900
- SUBST_NUMERIC - It will replace all the characters in the string with a value of 0. The spaces will be kept

*method:* 1 for encrypt 0 for decrypt. Decryption will only be performed for columns that have been encrypted with the 128-bit aes algorithm

**e.g.:**
*{"field": {"document_number": {"algorithm": "AES128","method": 1},"name": {"algorithm": "SUBS_STRING","method": 1},"date_birth": {"algorithm": "SUBS_DATA","method": 1},"phone_number": {"algorithm": "SUBS_NUMERIC","method": 1}}}*
	
Application should be called via the command line. 

**Run application**

*python mask.py {file} {json_config} {key} {column_splitter}*

**Parâmeters:**
- File:  File that will be processed. It should be a .csv or .txt file.
- json_config: .Json configuration file
- Key: The secret key to use in the symmetric cipher. It must be 16 (AES-128)
- column_splitter: Character of separating columns from a file
	
*e.g: python mask.py test/file.txt config_file.json 1234567890123456 ;*

Note: It is necessary to install the packages contained in the requirements.txt file.

