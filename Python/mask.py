import sys
import json
import pandas as pd
from datetime import datetime
import codecs
import base64
import re
import binascii
from Crypto.Cipher import AES


def get_best_chunk_size(filename, memory_allowed=8, tested_rows=1000, factor_adjustment=0.095):
    """
    :param filename: The name of the file being chunked
    :param memory_allowed:The maximum amount of memory, in gigabytes, that you want allowed by the Python process on the
    current system or operating system.
    :param tested_rows: Number of rows to be read to determine the ideal block size. In thousand is set by default
    :param factor_adjustment: Factor adjustment to explain process overload during assembly.
        Increase the factor to increase the memory used. By default, the factor is 0.095.
        adjusted R Language function withdrawal from site https://rdrr.io/cran/allan/man/getbestchunksize.html
    :return: Returns the optimal block size as the number of rows to read each iteration
    """
    data_frame_source = pd.read_csv(filename, sep=';', encoding='ISO-8859-1', nrows=tested_rows)
    memory = data_frame_source.memory_usage(index=True, deep=True).sum()
    optional_chunk_size = (memory_allowed * 1000000000 / memory) * tested_rows * factor_adjustment
    return optional_chunk_size


def pad(plain_text):
    number_of_bytes_to_pad = AES.block_size - len(plain_text) % AES.block_size
    ascii_string = chr(number_of_bytes_to_pad)
    padding_str = number_of_bytes_to_pad * ascii_string
    padded_plain_text = plain_text + padding_str
    return padded_plain_text


def fnc_convert_json(file_json):
    with open(file_json, encoding='utf-8') as data_file:
        data = json.loads(data_file.read())
    return data


class cls_Mask(object):
    """
    Application that masks or replaces fields that are considered sensitive from a .txt or .csv file
    Encryption:
        AES 128 - AES is very fast and secure, and it is the de facto standard for symmetric encryption.
        CBC(Cipher-Block Chaining) Each of the ciphertext blocks depends on the current and all previous plaintext blocks
        PKCS#5 - Password-Based Encryption Standard, RSA Laboratories
    Check in my github repository(michelmourasilva) for the same result in Java and PL/SQL
    Application should be called via the command line.
    python mask.py <file> <json_config> <key> <column_splitter>
    """
    def __init__(self, file_path, config_file_path, key='1234567890123456', column_splitter=';'):
        """
        Constructor method
        :param file_path: file that will be processed
        :param config_file_path: Json file that contain the list of columns that will masked or replaced
        Template of Json config File
        {
          "field": {
            "<sensitive column>": {
              "algorithm": "<algorithm mask >",
              "method": <mask method>  
            }
          }
        }
        e.g.:
        {
          "field": {
            "document_number": {
              "algorithm": "AES128",
              "method": 1	  
            },
            "name": {
              "algorithm": "SUBS_STRING",
              "method": 1
            },
            "date_birth": {
              "algorithm": "SUBS_DATA",
              "method": 1
            },
            "mother_name": {
              "algorithm": "SUBS_STRING",
              "method": 1
            }
          }
        }
            Origin file:
                document_number;name;date_birth;mother_name
                5d597-dd7;my name;23/12/1980;my mom
            Result:
                document_number;name;date_birth;mother_name
                5F8J8UI2UJ5FG5D8S78EW5T5Y554JH8;XX XXXX;01/01/1900;XX XXX
        :param key: The secret key to use in the symmetric cipher. It must be 16 (AES-128)
        :param column_splitter: Character of separating columns from a file
        """
        self.file_path = file_path
        self.config_file_path = config_file_path
        self.key = key
        self.column_splitter = column_splitter
        self.block_size = AES.block_size
        self.iv = '0000000000000000'.encode()

    def fnc_mask(self):
        dictionary_json = fnc_convert_json(self.config_file_path)

        def decrypt(value_series):
            """
            Decrypt method. called dynamically using pandas series
            :param value_series: value that is retrieved when reading each line with pandas
            :return: decrypted value
            """
            #encrypt_string_base64 = codecs.encode(codecs.decode(value_series, 'hex'), 'base64').decode('UTF-8').replace('\n', '').replace('\r', '')  # encrypt value is converted from hex format to base64 format
            cipher_dec = AES.new(self.key.encode(), AES.MODE_CBC, self.iv)
            encrypt_base64_binary_array = binascii.unhexlify(value_series) # Convert base64 string to bynary array
            decrypted_text = cipher_dec.decrypt(encrypt_base64_binary_array)

            return re.sub('[^A-Za-z0-9]+', '', decrypted_text.decode("utf-8", 'ignore'))

        def crypt(value_series):
            """
            Crypt method. called dynamically using pandas series
            :param value_series: value that is retrieved when reading each line with pandas
            :return: crypt value
            """
            plain = pad(value_series).encode()
            cipher = AES.new(self.key.encode(), AES.MODE_CBC, self.iv)
            encrypted_text = cipher.encrypt(plain)
            encrypted_base64 = base64.b64encode(encrypted_text).decode() #
            return codecs.encode(base64.b64decode(encrypted_base64), 'hex').decode("utf-8").upper()

        def string_convert(value_series):
            """
            Replaces any character of a string with the string X. Special characters are not overridden.
            :param value_series: value that is retrieved when reading each line with pandas
            :return: characters replaced by x. Replacement is not applied in special characters
            """
            return_string = re.sub("\w", 'X', value_series)
            return return_string

        def data_convert(value_series):
            """
            Replaces any character of a string with the string '01/01/1900'.
            :param value_series: value that is retrieved when reading each line with pandas
            :return: characters replaced by '01/01/1900'
            """
            return_string = "01/01/1900"
            return return_string

        def numeric_convert(value_series):
            """
             Replaces any character of a string with the string 0. Special characters are not overridden.
             :param value_series: value that is retrieved when reading each line with pandas
             :return: characters values replaced by 0. Replacement is not applied in special characters
             """
            return_numeric = re.sub("\w", '0', value_series)
            return return_numeric

        converters = {}
        precessed_lines = 0
        start_time = datetime.now()

        # Reads the Json configuration file and mounts a list of the fields to be replaced
        # and their respective encryption or decryption methods
        for x in dictionary_json:
            for y in dictionary_json[x]:
                if dictionary_json[x][y].get('algorithm', '') == 'AES128' \
                        and dictionary_json[x][y].get('method', '') == 0:
                    converters.__setitem__(y, decrypt)
                elif dictionary_json[x][y].get('algorithm', '') == 'AES128' \
                        and dictionary_json[x][y].get('method', '') == 1:
                    converters.__setitem__(y, crypt)
                elif dictionary_json[x][y].get('algorithm', '') == 'SUBS_STRING':
                    converters.__setitem__(y, string_convert)
                elif dictionary_json[x][y].get('algorithm', '') == 'SUBS_DATA':
                    converters.__setitem__(y, data_convert)
                elif dictionary_json[x][y].get('algorithm', '') == 'SUBS_NUMERIC':
                    converters.__setitem__(y, numeric_convert)

        # Reads the file using pandas and converts all the fields defined in the
        # configuration file with their respective methods
        data_frame_origin = pd.read_csv(self.file_path, sep=self.column_splitter, encoding='ISO-8859-1',
                                        converters=converters, chunksize=int(get_best_chunk_size(self.file_path)),
                                        low_memory=False)
        write_header = True
        for chunk in data_frame_origin:

            precessed_lines = len(chunk) + precessed_lines
            print('>>>>>>>>>>>>>>>>>>>>>>>>', precessed_lines)

            # Write a new text file with the replaced values
            chunk.to_csv(self.file_path.replace('.txt', '_processed.txt').replace('.csv', '_processed.txt')
                         , sep=';', index=False, encoding='ISO-8859-1', mode='a', header=write_header)
            write_header = False
        end_time = datetime.now()
        print('Duration: {}'.format(end_time - start_time))

        log_text = 'File {0} processed from  {1} to {2} - Process time: {3} ' \
                   '\nLines reads and processed: {4}'.format(self.file_path, start_time, end_time, end_time - start_time
                                                             , precessed_lines)

        with open(self.file_path.replace('.txt', '.log').replace('.csv', '.log'), 'w') as the_file:
            the_file.write(log_text)

        print('Process finished.')

if __name__ == "__main__":
    file_path, config_file_path, key, column_splitter = sys.argv[1:5]
    print(sys.argv[1:5])
    mask = cls_Mask(file_path, config_file_path, key, column_splitter)
    mask.fnc_mask()
