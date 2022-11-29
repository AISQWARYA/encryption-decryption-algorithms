import rsa
from cryptography.fernet import Fernet
import matplotlib.pyplot as plt
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import time
from Crypto import Cipher
from Crypto.Cipher import Blowfish
import numpy as np
import matplotlib.pyplot as plt
plt.style.use('ggplot')
import math
import timset

from Crypto.PublicKey import RSA
password = input("Enter encryptiondecryption log: ") 
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
with open('1k.txt','rb')as file:
  data=file.read()
cipher = Fernet(key)
start_time= time.time()
a1=timset.rsae1
encrypted_bytes = cipher.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo1.txt','wb')as file:
  file.write(encrypted_bytes)
#print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime - start_time))
entime11=entime - start_time
# Decrypt
encrdata=''
with open('mysecrInfo1.txt','rb')as file:
  encrdata=file.read()
start_time= time.time()

#decrypted_bytes = cipher.decrypt(encrdata)
decrypted_bytes =cipher.decrypt(encrypted_bytes)
dectime= time.time()
a1=timset.rsad1
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime11=dectime - start_time
######################################################################################################################
data=''
with open('2k.txt','rb')as file:
  data=file.read()

start_time= time.time()

encrypted_bytes = cipher.encrypt(data)
entime= time.time()

with open('mysecrInfo2.txt','wb')as file:
  file.write(encrypted_bytes)
#print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime - start_time))
entime21=entime - start_time
# Decrypt
encrdata=''
with open('mysecrInfo2.txt','rb')as file:
  encrdata=file.read()

start_time= time.time()
a1=timset.rsad2
decrypted_bytes = cipher.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime21=dectime - start_time
data=''
##########################################################################################################
with open('10k.txt','rb')as file:
  data=file.read()

start_time= time.time()

encrypted_bytes = cipher.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo3.txt','wb')as file:
  file.write(encrypted_bytes)
#print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime - start_time))
entime31=entime - start_time
# Decrypt
encrdata=''
with open('mysecrInfo3.txt','rb')as file:
  encrdata=file.read()

start_time= time.time()


decrypted_bytes = cipher.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime31=dectime - start_time
###############################################################################
data=''
with open('28k.txt','rb')as file:
  data=file.read()
start_time= time.time()

encrypted_bytes = cipher.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo4.txt','wb')as file:
  file.write(encrypted_bytes)
#print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime - start_time))
entime41=entime - start_time
# Decrypt
encrdata=''
with open('mysecrInfo4.txt','rb')as file:
  encrdata=file.read()

start_time= time.time()
#decrypted_bytes =cipher.decrypt(encrdata)
decrypted_bytes = cipher.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime41=dectime - start_time
data=''
with open('40k.txt','rb')as file:
  data=file.read()

start_time= time.time()
encrypted_bytes = cipher.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo5.txt','wb')as file:
  file.write(encrypted_bytes)
#print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime - start_time))
entime51=entime - start_time
# Decrypt
encrdata=''
with open('mysecrInfo5.txt','rb')as file:
  encrdata=file.read()
#cipher = Fernet(key)
start_time= time.time()
#decrypted_bytes = cipher.decrypt(encrdata)
decrypted_bytes = cipher.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime51=dectime - start_time

########################################################################################################################################################################################################################

#key = RSA.generate(1024)
(pub_key, priv_key) = rsa.newkeys(2048)
aes_key = rsa.randnum.read_random_bits(256) 
encrypted_aes_key = rsa.encrypt(aes_key, pub_key)
print(encrypted_aes_key)
print('Keysize is',len(encrypted_aes_key))

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
passsword=encrypted_aes_key
input_file1 = '1k.txt'
input_file2 = '2k.txt'
input_file5 = '10k.txt'
input_file3 = '28k.txt'
input_file4 = '48k.txt'
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

encrypted = encrypt( input_file1, password)
print(encrypted)
entime1= time.time()
#print(entime)

entime1k=entime1 - start_time1
print('Encryption time: {}',entime1k)
# Let us decrypt using our original password
start_time11= time.time()
decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
dectime11= time.time()

detime1k=dectime11 - start_time11
print('Decryption time: {}',detime1k)
######################################################

 
# First let us encrypt secret message
start_time5= time.time()

encrypted = encrypt( input_file5, password)
print(encrypted)
entime5= time.time()
#print(entime)

entime2k=entime5 - start_time5
print('Encryption time: {}',entime2k)
# Let us decrypt using our original password
start_time55= time.time()
decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
dectime55= time.time()

detime2k=dectime55 - start_time55
print('Decryption time: {}',detime2k)

#print(dectime)
#######################################################################################

 
# First let us encrypt secret message
start_time2= time.time()

encrypted = encrypt( input_file2, password)
print(encrypted)
entime2= time.time()
#print(entime)

entime10k=entime2 - start_time2
print('Encryption time: {}',entime10k)
# Let us decrypt using our original password
start_time22= time.time()
decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
dectime22= time.time()

detime10k=entime2 - start_time2
print('Decryption time: {}',detime10k)
####################################################################

    
 
# First let us encrypt secret message
start_time3= time.time()

encrypted = encrypt( input_file3, password)
print(encrypted)
entime3= time.time()
#print(entime)

entime28k=entime3 - start_time3 
print('Encryption time:',entime28k)
# Let us decrypt using our original password
start_time33= time.time()

decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
dectime33= time.time()

detime28k= dectime33 - start_time33
print('Decryption time:',detime28k)
############################################################################
#
    
 
# First let us encrypt secret message
start_time4= time.time()

encrypted = encrypt(input_file4, password)
print(encrypted)
entime4= time.time()
#print(entime)
entime40k=entime4 - start_time4
print('Encryption time:',entime40k)
# Let us decrypt using our original password
start_time44= time.time()

decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
dectime44= time.time()
detime40k=dectime44 - start_time44
print('Decryption time',detime40k)
####################################################################################################################


# key is generated
key = Fernet.generate_key()
# value of key is assigned to a variable
fernet = Fernet(key)
k=open('mysecrkey.key','wb')
k.write(key)
k.close()
#create pub & pvt keys
(pubkey, privkey) = rsa.newkeys(256)
print("Public key: ",pubkey)
#print("Private key: ",privkey)
pukey=open('publickey.key','wb')
pukey.write(pubkey.save_pkcs1('PEM'))
pukey.close()
##prkey.write(privkey.save_pkcs1('PEM'))
#prkey.close()
Blowfish = Fernet(key)
with open('mysecrkey.key','rb')as file:
  key=file.read()
data=''
with open('1k.txt','rb')as file:
  data=file.read()
start_time= time.time()
encrypted_bytes = Blowfish.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo1.txt','wb')as file:
  file.write(encrypted_bytes)
#print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime - start_time))
entime1=entime - start_time
# Decrypt
encrdata=''
with open('mysecrInfo1.txt','rb')as file:
  encrdata=file.read()

start_time= time.time()
decrypted_bytes = Blowfish.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime1=dectime - start_time
data=''
with open('2k.txt','rb')as file:
  data=file.read()
cipher = Fernet(key)
encrypted_bytes = Blowfish.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo2.txt','wb')as file:
  file.write(encrypted_bytes)
#print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime - start_time))
entime2=entime - start_time
# Decrypt
encrdata=''
with open('mysecrInfo2.txt','rb')as file:
  encrdata=file.read()
cipher = Fernet(key)
start_time= time.time()

decrypted_bytes =  Blowfish.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime2=dectime - start_time
data=''
with open('10k.txt','rb')as file:
  data=file.read()

start_time= time.time()
encrypted_bytes =  Blowfish.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo3.txt','wb')as file:
  file.write(encrypted_bytes)
#print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime - start_time))
entime3=entime - start_time
# Decrypt
encrdata=''
with open('mysecrInfo3.txt','rb')as file:
  encrdata=file.read()

start_time= time.time()
decrypted_bytes = Blowfish.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime3=dectime - start_time
data=''
with open('28k.txt','rb')as file:
  data=file.read()

start_time= time.time()
encrypted_bytes =  Blowfish.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo4.txt','wb')as file:
  file.write(encrypted_bytes)
#print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime - start_time))
entime4=entime - start_time
# Decrypt
encrdata=''
with open('mysecrInfo4.txt','rb')as file:
  encrdata=file.read()

start_time= time.time()
decrypted_bytes = Blowfish.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime4=dectime - start_time
data=''
with open('40k.txt','rb')as file:
  data=file.read()

start_time= time.time()
encrypted_bytes =  Blowfish.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo5.txt','wb')as file:
  file.write(encrypted_bytes)
#print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime - start_time))
entime5=entime - start_time
# Decrypt
encrdata=''
with open('mysecrInfo5.txt','rb')as file:
  encrdata=file.read()

start_time= time.time()

decrypted_bytes =  Blowfish.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime5=dectime - start_time

x1 = [1,2,10,28,40]
y1 = [entime11,entime21,entime31,entime41,entime51]
# plotting the line 1 points 
plt.plot(x1, y1, label = "ENCRYPTION rsa")
x2 = [1,2,10,28,40]
# corresponding y axis values
y2 = [entime1k,entime2k,entime10k,entime28k,entime40k]

plt.plot(x2, y2, label = "ENCRYPTION rsa aes") 

x3 = [1,2,10,28,40]
y3 = [entime1,entime2,entime3,entime4,entime5]
# plotting the line 1 points 
plt.plot(x3, y3, label = "ENCRYPTION rsa blowfish")
# line 2 points
plt.ylim(0.00001,.09)
plt.xlim(0,50)  
# naming the x axis
plt.xlabel('Data in kb')
# naming the y axis
plt.ylabel('Time in seconds')
# giving a title to my graph
plt.title('encryption time ')
  
# show a legend on the plot
plt.legend()
  
# function to show the plot
plt.show()
###############

x1 = [1,2,10,28,40]
y1 = [detime11,detime21,detime31,detime41,detime51]
# plotting the line 2 points 
plt.plot(x1, y1, label = "DECRYPTION rsa")

  
# show a legend on the plot

x2 = [1,2,10,28,40]
# corresponding y axis values
y2 = [detime1k,detime2k,detime10k,detime28k,detime40k]
#########################################################
plt.plot(x2, y2, label = "DECRYPTION rsaaes")

# line 2 points
x21= [1,2,10,28,40]
y21 = [detime1,detime2,detime3,detime4,detime5]
# plotting the line 2 points 
plt.plot(x21, y21, label = "DECRYPTION rsablowfish")
plt.ylim(0.00001,.09)
plt.xlim(0,50)  
# naming the x axis
plt.xlabel('Data in kb')
# naming the y axis
plt.ylabel('Time in seconds')
# giving a title to my graph
plt.title('decryption ')
  
# show a legend on the plot
plt.legend()
  
# function to show the plot
plt.show()