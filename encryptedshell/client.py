from Crypto.Cipher import AES
from Crypto import Random
from hashlib import sha256
from pwn import *

BLOCK_SIZE = 16
R = Random.new()
p = 174807157365465092731323561678522236549173502913317875393564963123330281052524687450754910240009920154525635325209526987433833785499384204819179549544106498491589834195860008906875039418684191252537604123129659746721614402346449135195832955793815709136053198207712511838753919608894095907732099313139446299843
g = 41899070570517490692126143234857256603477072005476801644745865627893958675820606802876173648371028044404957307185876963051595214534530501331532626624926034521316281025445575243636197258111995884364277423716373007329751928366973332463469104730271236078593527144954324116802080620822212777139186990364810367977

def pad(m):
    o = BLOCK_SIZE - len(m) % BLOCK_SIZE
    return m + o * chr(o)

def unpad(p):
    return p[0:-ord(p[-1])]

def send_encrypted(KEY, m):
    IV = R.read(BLOCK_SIZE)
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    c = aes.encrypt(pad(m))
    return (IV + c).encode('hex')

def read_encrypted(KEY, data):
    data = data.decode('hex')
    IV, data = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    m = unpad(aes.decrypt(data))
    return m

r = remote('shell2017.picoctf.com', 30754)
r.recvuntil('A = ')
b = 1
A = int(r.recvline())
B = pow(g, b, p)
K = pow(A, b, p)
r.recvuntil('Please supply B: ')
r.send('{}\n'.format(B))
print(str(K))
KEY = sha256(str(K)).digest()
r.send(send_encrypted(KEY, 'ThisIsMySecurePasswordPleaseGiveMeAShell\n') + '\n')
while True:
    cmd = raw_input("$ ")
    r.send(send_encrypted(KEY, cmd) + '\n')
    res = r.recvline().strip()
    print(read_encrypted(KEY, res))

