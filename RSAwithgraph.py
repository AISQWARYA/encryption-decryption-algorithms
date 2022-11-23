# rsa with graph
import rsa
from cryptography.fernet import Fernet
import matplotlib.pyplot as plt
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
start_time= time.time()
encrypted_bytes = my_fernet.encrypt(data)
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
my_fernet = Fernet(key)
start_time= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime1=dectime - start_time
data=''
with open('2k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time= time.time()
encrypted_bytes = my_fernet.encrypt(data)
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
my_fernet = Fernet(key)
start_time= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime2=dectime - start_time
data=''
with open('10k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time= time.time()
encrypted_bytes = my_fernet.encrypt(data)
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
my_fernet = Fernet(key)
start_time= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime3=dectime - start_time
data=''
with open('28k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time= time.time()
encrypted_bytes = my_fernet.encrypt(data)
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
my_fernet = Fernet(key)
start_time= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime4=dectime - start_time
data=''
with open('40k.txt','rb')as file:
  data=file.read()
my_fernet = Fernet(key)
start_time= time.time()
encrypted_bytes = my_fernet.encrypt(data)
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
my_fernet = Fernet(key)
start_time= time.time()
decrypted_bytes = my_fernet.decrypt(encrdata)
decrypted_bytes = my_fernet.decrypt(encrypted_bytes)
dectime= time.time()
#print('Decrypted data:',decrypted_bytes.decode())
print('Decryption time: {}'.format(dectime - start_time))
detime5=dectime - start_time

x1 = [1,2,10,28,40]
y1 = [entime1,entime2,entime3,entime4,entime5]
# plotting the line 1 points 
plt.plot(x1, y1, label = "ENCRYPTION")
  
# line 2 points
x2 = [1,2,10,28,40]
y2 = [detime1,detime2,detime3,detime4,detime5]
# plotting the line 2 points 
plt.plot(x2, y2, label = "DECRYPTION")
plt.ylim(0.0001,.009)
plt.xlim(0,50)  
# naming the x axis
plt.xlabel('Data in kb')
# naming the y axis
plt.ylabel('Time in seconds')
# giving a title to my graph
plt.title('RSA ')
  
# show a legend on the plot
plt.legend()
  
# function to show the plot
plt.show()

