from cryptography.fernet import Fernet
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
with open('1k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time1= time.time()
encrypted_bytes = my_fernet.encrypt(data)
entime1= time.time()
#print(encrypted_bytes)
with open('mysecrInfo1.txt','wb')as file:
  file.write(encrypted_bytes)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime1 - start_time1))

# Decrypt
encrdata=''
with open('mysecrInfo1.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
start_time11= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime11= time.time()
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime11 - start_time11))
data=''
with open('2k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time2= time.time()
encrypted_bytes = my_fernet.encrypt(data)
entime2= time.time()
#print(encrypted_bytes)
with open('mysecrInfo2.txt','wb')as file:
  file.write(encrypted_bytes)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime2 - start_time2))

# Decrypt
encrdata=''
with open('mysecrInfo2.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
start_time22= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime22= time.time()
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime22 - start_time22))
data=''
with open('10k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time3= time.time()
encrypted_bytes = my_fernet.encrypt(data)
entime3= time.time()
#print(encrypted_bytes)
with open('mysecrInfo3.txt','wb')as file:
  file.write(encrypted_bytes)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime3 - start_time3))

# Decrypt
encrdata=''
with open('mysecrInfo3.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
start_time33= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime33= time.time()
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime33 - start_time33))
data=''
with open('28k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time4= time.time()
encrypted_bytes = my_fernet.encrypt(data)
entime4= time.time()
#print(encrypted_bytes)
with open('mysecrInfo4.txt','wb')as file:
  file.write(encrypted_bytes)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime4 - start_time4))

# Decrypt
encrdata=''
with open('mysecrInfo4.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
start_time44= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime44= time.time()
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime44 - start_time44))
data=''
with open('40k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time5= time.time()
encrypted_bytes = my_fernet.encrypt(data)
entime5= time.time()
#print(encrypted_bytes)
with open('mysecrInfo5.txt','wb')as file:
  file.write(encrypted_bytes)
print('Encrypted data:',encrypted_bytes.decode())
print('Encryption time: {}'.format(entime5 - start_time5))

# Decrypt
encrdata=''
with open('mysecrInfo5.txt','rb')as file:
  encrdata=file.read()
my_fernet = Fernet(key)
start_time55= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime55= time.time()
print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime55 - start_time55))
