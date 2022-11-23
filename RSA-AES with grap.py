import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import time
import numpy as np
import matplotlib.pyplot as plt
plt.style.use('ggplot')
import math
from scipy.special import erfc
from scipy import stats
from Crypto.PublicKey import RSA
#key = RSA.generate(1024)
private_key = RSA.generate(1024)
print(private_key.exportKey('PEM'))

pub_key = private_key.publickey()
print(pub_key.exportKey('PEM'))
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
 
password = input("Enter encryption password: ")
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
print('Encryption time: {}'.format(entime1 - start_time1))
entime1k=entime1 - start_time1
# Let us decrypt using our original password
start_time11= time.time()
decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
dectime11= time.time()
print('Decryption time: {}'.format(dectime11 - start_time11))
detime1k=dectime11 - start_time11
######################################################
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
start_time5= time.time()
encrypted = encrypt( input_file5, password)
print(encrypted)
entime5= time.time()
#print(entime)
print('Encryption time: {}'.format(entime5 - start_time5))
entime2k=entime5 - start_time5
# Let us decrypt using our original password
start_time55= time.time()
decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
dectime55= time.time()
print('Decryption time: {}'.format(dectime55 - start_time55))
detime2k=dectime55 - start_time55
#print(dectime)
#######################################################################################
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
start_time2= time.time()
encrypted = encrypt( input_file2, password)
print(encrypted)
entime2= time.time()
#print(entime)
print('Encryption time: {}'.format(entime2 - start_time2))
entime10k=entime2 - start_time2
# Let us decrypt using our original password
start_time22= time.time()
decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
dectime22= time.time()
print('Decryption time: {}'.format(dectime22 - start_time2))
detime10k=entime2 - start_time2
####################################################################
#print(dectime)
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
start_time3= time.time()
encrypted = encrypt( input_file3, password)
print(encrypted)
entime3= time.time()
#print(entime)
print('Encryption time: {}'.format(entime3 - start_time3))
entime3 - start_time3 
# Let us decrypt using our original password
entime28k=start_time33= time.time()
decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
dectime33= time.time()
print('Decryption time: {}'.format(dectime33 - start_time33))
detime28k= dectime33 - start_time33
############################################################################
#print(dectime)
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
start_time4= time.time()
encrypted = encrypt(input_file4, password)
print(encrypted)
entime4= time.time()
#print(entime)
print('Encryption time: {}'.format(entime4 - start_time4))
entime40k=entime4 - start_time4
# Let us decrypt using our original password
start_time44= time.time()
decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
dectime44= time.time()
print('Decryption time: {}'.format(dectime44 - start_time44))
detime40k=dectime44 - start_time44
####################################################################################################################
x1 = [1,2,10,28,40]
# corresponding y axis values
y1 = [entime1k,entime2k,entime10k,entime28k,entime40k]

plt.plot(x1, y1, label = "ENCRYPTION")
##################################################################################################

x2 = [1,2,10,28,40]
# corresponding y axis values
y2 = [detime1k,detime2k,detime10k,detime28k,detime40k]
###########################################################################################################################
# plotting the points
plt.plot(x2, y2, label = "DECRYPTION")
plt.ylim(0.0001,.009)
plt.xlim(0,50)  
# naming the x axis
plt.xlabel('Data in kb')
# naming the y axis
plt.ylabel('Time in seconds')
# giving a title to my graph
plt.title('RSA with AES ')
  
# show a legend on the plot
plt.legend()
  
# function to show the plot
plt.show()
