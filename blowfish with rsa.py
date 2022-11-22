from cryptography.fernet import Fernet
import rsa
from Crypto.Cipher import Blowfish
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
cipher = Blowfish.new("key must be 4 to 56 bytes")
# input data must multiple of 8
data=''
with open('1k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time= time.time()
encrypted_bytes = cipher.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo.txt','wb')as file:
  file.write(encrypted_bytes)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time1: {}'.format(entime - start_time))

# Decrypt
encrdata=''
with open('mysecrInfo.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
start_time= time.time()
decrypted_bytes = cipher.decrypt(encrdata)
decrypted_bytes = cipher.decrypt(encrypted_bytes)
dectime= time.time()
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time1: {}'.format(dectime - start_time))
data=''
with open('2k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time= time.time()
encrypted_bytes = cipher.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo.txt','wb')as file:
  file.write(encrypted_bytes)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time2: {}'.format(entime - start_time))

# Decrypt
encrdata=''
with open('mysecrInfo.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
start_time= time.time()
decrypted_bytes = cipher.decrypt(encrdata)
decrypted_bytes = cipher.decrypt(encrypted_bytes)
dectime= time.time()
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time2: {}'.format(dectime - start_time))
data=''
with open('10k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time= time.time()
encrypted_bytes = my_fernet.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo.txt','wb')as file:
  file.write(encrypted_bytes)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time3: {}'.format(entime - start_time))

# Decrypt
encrdata=''
with open('mysecrInfo.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
start_time= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime= time.time()
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time3: {}'.format(dectime - start_time))
data=''
with open('28k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time= time.time()
encrypted_bytes = my_fernet.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo.txt','wb')as file:
  file.write(encrypted_bytes)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time4: {}'.format(entime - start_time))

# Decrypt
encrdata=''
with open('mysecrInfo.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
start_time= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime= time.time()
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time4: {}'.format(dectime - start_time))
data=''
with open('40k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time= time.time()
encrypted_bytes = my_fernet.encrypt(data)
entime= time.time()
#print(encrypted_bytes)
with open('mysecrInfo.txt','wb')as file:
  file.write(encrypted_bytes)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time5: {}'.format(entime - start_time))

# Decrypt
encrdata=''
with open('mysecrInfo.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
start_time= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime= time.time()
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time2: {}'.format(dectime - start_time))

