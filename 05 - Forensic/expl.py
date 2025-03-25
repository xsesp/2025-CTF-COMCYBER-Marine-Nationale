from base64 import b64decode as b64dec

key=['A', 'A', '$', 'F', '2', '-', 'D', '8', 'C', '1',
				'E', '7', 'B', '9', 'F', '3', 'A', '3', '5', '@',
				'C', '8', '@', '!', 'B', 'B', '2', 'E', '1', 'F',
				'0', 'A', '7', 'C', '3', 'D']

key="".join(key)

stkey=key

iv=['D', '1', '@', 'E', '2', '#', 'F', '3', '%', 'A',
				'4', 'B', '5', '&', 'C', '6', 'D', '1', '@', 'E',
				'2', '#', 'F', '3', '%', 'A', '4', 'B', '5', '&',
				'C', '6', 'D', '1', '@', 'E', '2', '#', 'F', '3',
				'%', 'A', '4', 'B', '5', '&', 'C', '6']

iv="".join(iv)

key=key[:16].encode()
iv=iv[:16].encode()


L=b"OF/sfn87WwjfIX14p17jp8mu5uavNFecb4D97pgVfZc="
L=b64dec(L)
O=b"3Npd3p5V7JSh6JZ5gqRmZg=="
O=b64dec(O)
N=b"IeLkqcSXkaE8QamE7i4DEY3N7NmqJvAl1fzI7gIQkbo="
N=b64dec(N)
G=b"Wil860ds3vJiRDi+iTntnfknYML8iTowJsQe0uwmTms="
G=b64dec(G)

from Crypto.Cipher import AES
import hashlib


def dec(x):
  cipher = AES.new(key, AES.MODE_CBC,iv=iv)
  return cipher.decrypt(x)


def dec2(x,K):
  cipher = AES.new(K, AES.MODE_CBC,iv=iv)
  return cipher.decrypt(x)

print(dec(L))
print(dec(O))
print(dec(N))
print(dec(G))

dinkeys=[
      "01f4d362ecdd89d26f5f0c5e6b2afe93",
      "35319a21dbe2ced1a7da56c2d717bb0d",
      "d7a6f9650e30eb65f8f6506c6d170b9a"
    ]

path="\\\\dc01\\shares\\private"
print(path)
timestamp="2025-02-11T16:28:16Z"

F=open("./private/crew_list.html.enc","rb").read()

for dinkey in dinkeys:
  T=dinkey+stkey+path+timestamp
  T=hashlib.sha256(T.encode()).digest()
  F2=open(f"./{dinkey}","wb")
  F2.write(dec2(F,T))
  F2.close()

  
  
  
  
