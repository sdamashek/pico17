from hashlib import md5 #Must be run in python 2.7.x
from pwn import *
import re

#code used to calculate successive hashes in a hashchain. 
seed = "18a9042b3fc5b02fe3d57fea87d6992f"
meme = '8c1601179475a08e25d87ea540019fa4'
mapping = {}

for _ in range(100):
    r = remote('shell2017.picoctf.com', 2412)
    r.recvuntil('r/f?')
    r.recvlines(2)
    r.send('r\n')
    ln = r.recvline()
    m = re.findall(r'Your ID is now (\d+) and your assigned hashchain seed is (.+)', ln)
    mapping[m[0][0]] = m[0][1]

    r.close()
print(mapping)

while True:
    r = remote('shell2017.picoctf.com', 2412)
    r.recvuntil('r/f?')
    r.recvlines(2)
    r.send('f\n')
    lns = r.recvlines(4)
    uid = lns[0].rsplit('user ',1)[1]
    if uid not in mapping:
        print("{} not in mapping".format(uid))
        r.close()
        continue

    print("Matching {}".format(lns[2]))
    hashc = mapping[uid]
    prev = hashc
    for _ in range(500000):
      hashc = md5(hashc.encode('utf8')).hexdigest()
      if hashc == lns[2]:
          r.send(prev + '\n')
          print(prev)
          print(r.recvall())
          break
      prev = hashc 
