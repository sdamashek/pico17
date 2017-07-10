from pwn import *
desired = 'tu1|\h+&g\OP7@% :BH7M6m3g='
rev = desired
out = ''
prev = 0
for i in rev:
    dc = ord(i)
    off = dc-32
    inp = (off + 96 - prev) % 96
    pri = inp
    out += chr(inp+32)
    print(dc,off,inp,prev,out)
    prev = pri
print(out[::-1])
