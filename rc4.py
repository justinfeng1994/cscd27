#!/usr/local/bin/python3
import binascii
import wave
import base64
import wave

#########################
####### RC4 #############
#########################

def ksa(key_b):
    ''' KSA - Key-scheduling algorithm (KSA)
    '''
    # using algroithm from wikipedia kas
    s = []
    j = 0
    for i in range(256):
        s.append(i)
    for i in range(256):
        j = (j + s[i] + key_b[i % len(key_b)]) % 256
        s[i], s[j] = s[j], s[i]
    return s
    

def prga(s, plaintext_b):
    ''' PRGA - Pseudo-random generation algorithm
    '''
    # using algroithm from wikipedia
    # add anthor param plaintext_b to set the loop limit
    i = 0
    j = 0
    m = bytes()
    for ele in plaintext_b:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = ele^s[(s[i] + s[j]) % 256]
        # print(k)
        m += bytes([k])
    return m


def rc4(key_b,plaintext_b):
    ''' returns the RC4 ciphertext corresponding to the keys and plaintext given as bytes
    (bytes, bytes) -> bytes
    >>> rc4(b'Key',b'Plaintext')
    b'\xbb\xf3\x16\xe8\xd9@\xaf\n\xd3'
    '''
    s = ksa(key_b)
    return prga(s, plaintext_b)


#########################
####### utils ###########
#########################


def utf82bytes(s):
    ''' returns the bytes encoding of utf-8 string s given as argument
    (string) -> bytes
    >>> utf82ba('Key')
    b'Key'
    '''
    return s.encode("utf-8")


def bytes2utf8(b):
    ''' returns the utf-8 string of the bytes ba given as parameter
    (bytes) -> string
    >>> ba2utf8(b'Key')
    'Key'
    '''
    return b.decode("utf-8")

def armor2bytes(a):
    ''' returns the bytes of the ASCII armor string a given as parameter
    (string)-> bytes
    >>> armor2ba('S2V5')
    b'Key'
    '''
    return base64.b64decode(a)


def bytes2armor(b):
    ''' returns the ASCII armor string of the bytes ba given as parameter
    (bytes)-> string
     >>> ba2armor(b'Key')
    'S2V5'
    '''
    return bytes2utf8(base64.b64encode(b))

#########################
### textfile support ####
#########################

def rc4_textfile_encrypt(key, input_filename, output_filename):
    ''' encrypts the input plaintext file into the ASCI-armored output file using the key
    (string, string, string) -> None
    '''
    # open plaintext file with read mode
    myfile = open(input_filename, 'r')
    # change key into bytes form
    key_b = utf82bytes(key)
    # change plaintext into bytes form
    plaintext_b = utf82bytes(myfile.read())
    # open outputfile with write mode
    newfile = open(output_filename, 'w')
    # write after rc4
    newfile.write(bytes2armor(rc4(key_b, plaintext_b)))
    # close files
    myfile.close()
    newfile.close()

def rc4_textfile_decrypt(key, input_filename, output_filename):
    ''' decrypts the ASCII-armored input file to the plaintext output file using the key
    (string, string, string) -> None
    '''
    # open encrypted file with read mode
    # change key into bytes form
    myfile = open(input_filename, 'r')
    key_b = utf82bytes(key)
    # change encrypted file into bytes form
    plaintext_b = armor2bytes(myfile.read())
    # open outputfile with write mode
    newfile = open(output_filename, 'w')
    # use rc4 to decrypt
    # we get form bytes after rc4, change to utf8 type and write
    newfile.write(bytes2utf8(rc4(key_b, plaintext_b)))
    # close files
    myfile.close()
    newfile.close()

#########################
### binary support ######
#########################

def rc4_binary(key, input_filename, output_filename):
    ''' encrypts/decrypts the binary input file to the binary output file file using the key
    (string, string, string) -> None
    '''
    # create empty bytearray to store results
    myArr = bytearray()
    key_b = utf82bytes(key)
    # open file with mode read binary
    myfile = open(input_filename, 'rb')
    plaintext_b = myfile.read()
    # open output file with mode write binary
    newfile = open(output_filename, 'wb')
    # store the rc4 results into bytearray
    myArr.extend(rc4(key_b, plaintext_b))
    # write with bytearray and close files
    newfile.write(myArr)
    myfile.close()
    newfile.close()
    
#########################
### wave support ########
#########################

def rc4_wave(key, input_filename, output_filename):
    ''' encrypts/decrypts the wave input file to the wave output file file using the key
    (string, string, string) -> None
    '''
    # change key into byte form
    key_b = utf82bytes(key)
    # use wave.openfp() to open inputfile and outputfile
    myfile = wave.openfp(input_filename,'rb')
    newfile = wave.openfp(output_filename, 'wb')
    # use getparams() to get the header part
    header = myfile.getparams()
    # use getnframes() to get the number of frames
    n = myfile.getnframes()
    # use readframes() to find the plaintext
    plaintext_b = myfile.readframes(n)
    # setparams with header so the outputfile is playable
    newfile.setparams(header)
    # use rc4 to en/decrypt data and write into outputfile
    data = rc4(key_b, plaintext_b)
    newfile.writeframes(data)
    # close files
    myfile.close()
    newfile.close()
    

#########################
### tests  ##############
#########################

if __name__ == '__main__':
    ''' Tests
    '''
    # Works with Python 3
    # Declare a value of type Bytes
    plaintext_b = b'Plaintext'
    # iterate throught a bytes value
    for byte in plaintext_b:
        print(byte)
    # modify a byte does not work because Bytes are immutable
    # the following line raises an exception
    # plaintext_b[0],plaintext_b[-1] = plaintext_b[-1],plaintext_b[0]
    # so we need to convert it into a mutable bytearray
    plaintext_ba = bytearray(plaintext_b)
    plaintext_ba[0],plaintext_ba[-1] = plaintext_ba[-1],plaintext_ba[0]
    # and convert it back to byte
    plaintext_b = bytes(plaintext_ba)
    print(plaintext_b)
    # making a xor byte per byte
    key_b = b'Secretext'
    cipher_b = bytearray(b'')
    for i in range(len(plaintext_b)):
        print(i)
        cipher_b.append(plaintext_b[i] ^ key_b[i])
    print(bytes(cipher_b))





