
import base64
import hashlib
import time
import random
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
import rsa
# key is generated
key = Fernet.generate_key()
  
# value of key is assigned to a variable
fernet = Fernet(key)
k=open('mysecrkey.key','wb')
k.write(key)
k.close()
#create pub & pvt keys
(pubkey, privkey) = rsa.newkeys(2048)
print("Public key: ",pubkey)
print("Private key: ",privkey)
pukey=open('publickey.key','wb')
pukey.write(pubkey.save_pkcs1('PEM'))
pukey.close()
prkey=open('publickey.key','wb')
prkey.write(privkey.save_pkcs1('PEM'))
prkey.close()
with open('mysecrkey.key','rb')as file:
  key=file.read()
data=''
with open('bbb.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)

 
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
 
password = input("Enter encryption password: ")
 
 
def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))
    
 
 
def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))
    
 
# First let us encrypt secret message
start_time1= time.time()
with open('1k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
encrypted_bytes = my_fernet.encrypt(data)
#print(encrypted_bytes)
entime1= time.time()
with open('mysecrInfo1.txt','wb')as file:
  file.write(encrypted_bytes)
#encrypted = encrypt("This is a secret message", password)
#print(encrypted)
#print(entime)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime1 - start_time1))
 
# Let us decrypt using our original password
start_time11= time.time()
encrdata=''
with open('mysecrInfo1.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
#decrypted = decrypt(encrypted, password)
#print(bytes.decode(decrypted))
dectime11= time.time()
#print(dectime)
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime11 - start_time11))
###################################################################################################################
start_time2= time.time()
with open('2k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
encrypted_bytes = my_fernet.encrypt(data)
#print(encrypted_bytes)
entime2= time.time()
with open('mysecrInfo2.txt','wb')as file:
  file.write(encrypted_bytes)
#encrypted = encrypt("This is a secret message", password)
#print(encrypted)
#print(entime)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime2 - start_time2))
 
# Let us decrypt using our original password
start_time22= time.time()
encrdata=''
with open('mysecrInfo.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
#decrypted = decrypt(encrypted, password)
#print(bytes.decode(decrypted))
dectime22= time.time()
#print(dectime)
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime22 - start_time22))
####################################################################################################################
start_time3= time.time()
with open('10k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
encrypted_bytes = my_fernet.encrypt(data)
#print(encrypted_bytes)
entime3= time.time()
with open('mysecrInfo3.txt','wb')as file:
  file.write(encrypted_bytes)
#encrypted = encrypt("This is a secret message", password)
#print(encrypted)
#print(entime)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime3 - start_time3))
 
# Let us decrypt using our original password
start_time33= time.time()
encrdata=''
with open('mysecrInfo3.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
#decrypted = decrypt(encrypted, password)
#print(bytes.decode(decrypted))
dectime33= time.time()
#print(dectime)
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime33 - start_time33))
#################################################################################################################
#######################################################################################################################
start_time4= time.time()
with open('28k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
encrypted_bytes = my_fernet.encrypt(data)
#print(encrypted_bytes)
entime4= time.time()
with open('mysecrInfo4.txt','wb')as file:
  file.write(encrypted_bytes)
#encrypted = encrypt("This is a secret message", password)
#print(encrypted)
#print(entime)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime4 - start_time4))
 
# Let us decrypt using our original password
start_time44= time.time()
encrdata=''
with open('mysecrInfo4.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
#decrypted = decrypt(encrypted, password)
#print(bytes.decode(decrypted))
dectime44= time.time()
#print(dectime)
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime44 - start_time44))
############################################################################################################
start_time5= time.time()
with open('40k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
encrypted_bytes = my_fernet.encrypt(data)
#print(encrypted_bytes)
entime5= time.time()
with open('mysecrInfo.txt','wb')as file:
  file.write(encrypted_bytes)
#encrypted = encrypt("This is a secret message", password)
#print(encrypted)
#print(entime)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime5 - start_time5))
 
# Let us decrypt using our original password
start_time55= time.time()
encrdata=''
with open('mysecrInfo.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
#decrypted = decrypt(encrypted, password)
#print(bytes.decode(decrypted))
dectime55= time.time()
#print(dectime)
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime55 - start_time55))
#######################################################################################################
